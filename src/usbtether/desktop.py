"""The desktop panel (``usbtether app``): a small window that waits for the drive.

It shows whether the enrolled drive is plugged in, keeps the bound folders encrypted (new plain
files are encrypted within seconds while *Auto* is on), and has switches for the double-click
association and for starting at sign-in. Opening a ``.utenc`` file does not need this window:
that is ``usbtether open``, started by Explorer. Only the standard library (tkinter) is used.
"""

from __future__ import annotations

import contextlib
import os
import queue
import sys
import threading
import time
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
from typing import TYPE_CHECKING, Any

from .errors import UsbTetherError
from .opener import (
    FolderGuard,
    association_command,
    default_command,
    register_association,
    run_at_login,
    set_run_at_login,
    unregister_association,
)
from .vault import SUFFIX, decrypt_file, encrypt_file

if TYPE_CHECKING:
    from .agent import Agent
    from .verifier import Verifier

TITLE = "usbtether"
BG, PANEL, LINE = "#0b1220", "#121c2e", "#263852"
TEXT, MUTED = "#e8f0ff", "#93a6c3"
CYAN, GREEN, AMBER, RED = "#67e8f9", "#6ee7b7", "#fcd34d", "#fda4af"
FONT = ("Segoe UI", 10)

# Set by the running app so a passphrase asked for on the worker thread is shown by the UI.
_ui_asker: Callable[[], bytes] | None = None


def ask_passphrase() -> bytes:
    """Ask for the drive's passphrase in a small dialog (used when there is no console)."""
    if _ui_asker is not None and threading.current_thread() is not threading.main_thread():
        return _ui_asker()
    root = tk.Tk()
    root.withdraw()
    try:
        value = simpledialog.askstring(TITLE, "Passphrase for the USB key:", show="*", parent=root)
    finally:
        root.destroy()
    if not value:
        raise UsbTetherError("no passphrase given")
    return value.encode("utf-8")


def _single_instance() -> bool:
    """True if this is the only panel running. Otherwise bring the other one forward."""
    if sys.platform != "win32":
        return True
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW(None, False, "Local\\usbtether-desktop-panel")
    if kernel32.GetLastError() != 183:  # ERROR_ALREADY_EXISTS
        return True
    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW(None, TITLE)
    if hwnd:
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.SetForegroundWindow(hwnd)
    return False


def _counts(folder: Path) -> tuple[int, int]:
    enc = plain = 0
    for p in folder.rglob("*"):
        if p.is_file() and not p.name.endswith(".tmp"):
            if p.name.endswith(SUFFIX):
                enc += 1
            else:
                plain += 1
    return enc, plain


class Panel:
    def __init__(self, agent: Agent, verifier: Verifier, home: Path) -> None:
        self.events: queue.Queue[str] = queue.Queue()
        self.guard = FolderGuard(agent, verifier, home, on_event=self.events.put)
        self.jobs: queue.Queue[Callable[[], None]] = queue.Queue()
        self.snapshot: list[tuple[Path, bool, int, int]] = []
        self.stop = threading.Event()
        self.declined = False
        self.root = tk.Tk()
        self._build()

    # -- worker thread: everything that touches the drive or the disk -----------------------

    def _worker(self) -> None:
        next_poll = 0.0
        while not self.stop.is_set():
            try:
                job = self.jobs.get(timeout=0.25)
            except queue.Empty:
                job = None
            if job is not None:
                try:
                    job()
                except UsbTetherError as exc:
                    self.events.put(str(exc))
                except OSError as exc:
                    self.events.put(f"File error: {exc}")
                next_poll = 0.0
            if time.monotonic() >= next_poll:
                if not self.declined:
                    self.guard.step()
                self.snapshot = [
                    (f, f.is_dir(), *(_counts(f) if f.is_dir() else (0, 0)))
                    for f in self.guard.bound.folders()
                ]
                # cheap while unlocked (a folder check); a 2 s probe while waiting
                next_poll = time.monotonic() + (1.0 if self.guard.key else 2.0)

    def _ask_on_ui(self) -> bytes:
        """Called on the worker thread when the key needs a passphrase."""
        if self.declined:
            raise UsbTetherError("passphrase needed: press Unlock")
        result: dict[str, Any] = {}
        done = threading.Event()

        def ask() -> None:
            result["v"] = simpledialog.askstring(
                TITLE, "Passphrase for the USB key:", show="*", parent=self.root
            )
            done.set()

        self.root.after(0, ask)
        done.wait()
        if not result.get("v"):
            self.declined = True
            raise UsbTetherError("passphrase needed: press Unlock")
        return str(result["v"]).encode("utf-8")

    # -- UI -----------------------------------------------------------------------------

    def _btn(self, parent: tk.Misc, text: str, cmd: Callable[[], None], **kw: Any) -> tk.Button:
        b = tk.Button(
            parent,
            text=text,
            command=cmd,
            bg=kw.pop("bg", "#16243a"),
            fg=kw.pop("fg", TEXT),
            activebackground="#1d3350",
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            padx=10,
            pady=5,
            font=FONT,
            cursor="hand2",
            **kw,
        )
        return b

    def _check(
        self, parent: tk.Misc, text: str, var: tk.BooleanVar, cmd: Callable[[], None]
    ) -> None:
        tk.Checkbutton(
            parent,
            text=text,
            variable=var,
            command=cmd,
            bg=PANEL,
            fg=TEXT,
            selectcolor=BG,
            activebackground=PANEL,
            activeforeground=TEXT,
            font=FONT,
            anchor="w",
            bd=0,
            highlightthickness=0,
        ).pack(fill="x", pady=1)

    def _card(self, title: str) -> tk.Frame:
        outer = tk.Frame(self.root, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        outer.pack(fill="x", padx=14, pady=(0, 10))
        tk.Label(outer, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(
            anchor="w", padx=12, pady=(8, 2)
        )
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="x", padx=12, pady=(0, 10))
        return inner

    def _build(self) -> None:
        r = self.root
        r.title(TITLE)
        icon = Path(__file__).with_name("usbtether.ico")
        if icon.exists() and sys.platform == "win32":
            with contextlib.suppress(tk.TclError):
                r.iconbitmap(default=str(icon))  # type: ignore[no-untyped-call]
        r.configure(bg=BG)
        r.geometry("470x640")
        r.minsize(420, 560)
        r.protocol("WM_DELETE_WINDOW", self._close)

        # status
        top = tk.Frame(r, bg=BG)
        top.pack(fill="x", padx=14, pady=14)
        self.dot = tk.Canvas(top, width=46, height=46, bg=BG, highlightthickness=0)
        self.dot.pack(side="left")
        self.dot_id = self.dot.create_oval(6, 6, 40, 40, fill=AMBER, outline="")
        box = tk.Frame(top, bg=BG)
        box.pack(side="left", fill="x", expand=True, padx=12)
        self.title = tk.Label(
            box,
            text="Waiting for the USB drive",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 15, "bold"),
            anchor="w",
        )
        self.title.pack(fill="x")
        self.sub = tk.Label(
            box,
            text="Plug in your enrolled drive.",
            bg=BG,
            fg=MUTED,
            font=FONT,
            anchor="w",
            justify="left",
            wraplength=330,
        )
        self.sub.pack(fill="x")
        self.unlock_btn = self._btn(top, "Unlock", self._unlock)

        # bound folders
        c = self._card("BOUND FOLDERS  ·  always encrypted on disk")
        self.listbox = tk.Listbox(
            c,
            height=6,
            bg=BG,
            fg=TEXT,
            selectbackground="#1d3350",
            highlightthickness=0,
            bd=0,
            font=("Segoe UI", 9),
            activestyle="none",
        )
        self.listbox.pack(fill="x")
        row = tk.Frame(c, bg=PANEL)
        row.pack(fill="x", pady=(8, 0))
        self._btn(row, "+ Add folder", self._add, fg=CYAN).pack(side="left")
        self._btn(row, "Encrypt now", self._protect).pack(side="left", padx=6)
        self._btn(row, "Open", self._reveal).pack(side="left")
        self._btn(row, "Remove", self._remove, fg=RED).pack(side="right")

        # quick jobs
        c = self._card("ONE-OFF  ·  result goes next to the original")
        row = tk.Frame(c, bg=PANEL)
        row.pack(fill="x")
        self._btn(row, "Encrypt files...", lambda: self._quick(True), fg=CYAN).pack(side="left")
        self._btn(row, "Decrypt files...", lambda: self._quick(False), fg=AMBER).pack(
            side="left", padx=6
        )
        self.delete_src = tk.BooleanVar(value=True)
        self._check(c, "Delete the source afterwards", self.delete_src, lambda: None)

        # settings
        c = self._card("SETTINGS")
        self.auto = tk.BooleanVar(value=self.guard.bound.auto)
        self._check(c, "Auto-encrypt new files in bound folders", self.auto, self._set_auto)
        self.assoc = tk.BooleanVar(value=self._assoc_ok())
        self._check(c, "Double-click a .utenc file to open it", self.assoc, self._set_assoc)
        self.login = tk.BooleanVar(value=self._login_ok())
        self._check(c, "Start with Windows", self.login, self._set_login)

        # log
        self.log = tk.Text(
            r,
            height=6,
            bg="#070c15",
            fg="#b7c8e2",
            bd=0,
            highlightthickness=0,
            font=("Consolas", 9),
            wrap="word",
            state="disabled",
        )
        self.log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def _say(self, msg: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", time.strftime("%H:%M:%S  ") + msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _tick(self) -> None:
        while True:
            try:
                self._say(self.events.get_nowait())
            except queue.Empty:
                break
        g = self.guard
        if g.status == "unlocked":
            color, title, sub = (
                GREEN,
                "Unlocked",
                f"Drive {g.mount}  ·  .utenc files open on double-click",
            )
        elif g.status == "error" or self.declined:
            color, title, sub = RED, "Locked", g.detail
        else:
            color, title, sub = (
                AMBER,
                "Waiting for the USB drive",
                "Plug in your enrolled drive. Files stay encrypted.",
            )
        self.dot.itemconfigure(self.dot_id, fill=color)
        self.title.configure(text=title)
        self.sub.configure(text=sub)
        if g.status == "error" or self.declined:
            self.unlock_btn.pack(side="right")
        else:
            self.unlock_btn.pack_forget()
        items = [
            f"{p}    " + (f"{e} encrypted · {n} plain" if ok else "missing")
            for p, ok, e, n in self.snapshot
        ]
        if items != list(self.listbox.get(0, "end")):
            sel: tuple[int, ...] = self.listbox.curselection()  # type: ignore[no-untyped-call]
            self.listbox.delete(0, "end")
            for it in items:
                self.listbox.insert("end", it)
            for i in sel:
                if i < len(items):
                    self.listbox.selection_set(i)
        self.root.after(400, self._tick)

    # -- actions --------------------------------------------------------------------------

    def _selected(self) -> Path | None:
        sel: tuple[int, ...] = self.listbox.curselection()  # type: ignore[no-untyped-call]
        if not sel or sel[0] >= len(self.snapshot):
            self._say("Select a folder first.")
            return None
        return self.snapshot[sel[0]][0]

    def _unlock(self) -> None:
        self.declined = False
        self.guard.status = "waiting"
        self.jobs.put(lambda: None)

    def _add(self) -> None:
        d = filedialog.askdirectory(parent=self.root, title="Folder to keep encrypted")
        if not d:
            return
        folder = Path(d)

        def job() -> None:
            self.guard.bound.add(folder)
            self.events.put(f"Bound {folder}")
            if self.guard.bound.auto:
                self.guard.protect_all()

        self.jobs.put(job)

    def _remove(self) -> None:
        f = self._selected()
        if f and messagebox.askyesno(
            TITLE, f"Stop watching {f}?\nIts files stay as they are.", parent=self.root
        ):
            folder = f

            def job() -> None:
                self.guard.bound.remove(folder)
                self.events.put(f"Unbound {folder}")

            self.jobs.put(job)

    def _protect(self) -> None:
        def job() -> None:
            self.guard.protect_all()

        self.jobs.put(job)

    def _reveal(self) -> None:
        f = self._selected()
        if f and sys.platform == "win32":
            os.startfile(f)  # noqa: S606

    def _quick(self, encrypt: bool) -> None:
        if encrypt:
            paths = filedialog.askopenfilenames(parent=self.root, title="Files to encrypt")
        else:
            paths = filedialog.askopenfilenames(
                parent=self.root, title="Files to decrypt", filetypes=[("usbtether", f"*{SUFFIX}")]
            )
        if not paths:
            return
        keep = not self.delete_src.get()

        def job() -> None:
            key = self.guard.ensure_key()
            n = 0
            for raw in paths:
                p = Path(raw)
                if p.name.endswith(SUFFIX) == encrypt:
                    continue
                (encrypt_file if encrypt else decrypt_file)(p, key, keep=keep)
                n += 1
            self.events.put(f"{'Encrypted' if encrypt else 'Decrypted'} {n} file(s).")

        self.jobs.put(job)

    def _set_auto(self) -> None:
        self.guard.bound.auto = self.auto.get()
        self._say("Auto-encrypt " + ("on." if self.auto.get() else "off: use Encrypt now."))

    def _assoc_ok(self) -> bool:
        try:
            return association_command() == default_command()
        except UsbTetherError:
            return False

    def _set_assoc(self) -> None:
        try:
            if self.assoc.get():
                register_association(default_command())
                self._say("Double-click registered for .utenc files.")
            else:
                unregister_association()
                self._say("Double-click registration removed.")
        except UsbTetherError as exc:
            self._say(str(exc))
            self.assoc.set(self._assoc_ok())

    def _login_ok(self) -> bool:
        try:
            return run_at_login()
        except UsbTetherError:
            return False

    def _set_login(self) -> None:
        try:
            set_run_at_login(self.login.get())
            self._say("Starts at sign-in." if self.login.get() else "Will not start at sign-in.")
        except UsbTetherError as exc:
            self._say(str(exc))
            self.login.set(self._login_ok())

    def _close(self) -> None:
        if messagebox.askyesno(
            TITLE,
            "Quit the panel?\n\nNew files in bound folders will not be encrypted until it runs "
            "again. Double-clicking .utenc files keeps working.",
            parent=self.root,
        ):
            self.stop.set()
            self.root.destroy()

    def run(self, minimized: bool) -> None:
        global _ui_asker
        _ui_asker = self._ask_on_ui
        with contextlib.suppress(UsbTetherError):  # first run: make double-click work
            if association_command() is None:
                register_association(default_command())
                self.assoc.set(True)
                self._say("Registered double-click for .utenc files.")
        threading.Thread(target=self._worker, name="usbtether-panel", daemon=True).start()
        if minimized:
            self.root.iconify()
        self.root.after(100, self._tick)
        self.root.mainloop()
        self.stop.set()
        _ui_asker = None


def run_app(agent: Agent, verifier: Verifier, home: Path, *, minimized: bool = False) -> int:
    if not _single_instance():
        return 0
    Panel(agent, verifier, home).run(minimized)
    return 0
