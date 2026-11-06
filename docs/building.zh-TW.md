# 建置 usbtether

[English](building.md) · [繁體中文](building.zh-TW.md)

如何建立開發環境、執行檢查、建置 Windows 安裝程式。*使用*方式見 [usage.zh-TW.md](usage.zh-TW.md)；桌面 App 的使用說明見 [packaging/README.md](../packaging/README.md)。

## 1. 需要的東西

| 項目 | 用途 | 說明 |
|---|---|---|
| Python 3.10 以上（64 位元） | 全部 | 建議用 python.org 的版本，內含 tkinter（桌面面板需要） |
| Git | 取得原始碼 | |
| Inno Setup 6 | 只有建置安裝程式時需要 | `winget install JRSoftware.InnoSetup` |
| 有序號的 USB 隨身碟 | 實際試用 | `usbtether devices` 會告訴你能不能用 |

## 2. 開發環境

```powershell
git clone https://github.com/ChouYangEn0401/usbtether.git
cd usbtether
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

`-e` 是可編輯模式：改 `src/` 底下的程式碼不必重新安裝。

## 3. 檢查（每次 commit 前執行）

```powershell
ruff check .
ruff format --check .
mypy
pytest
```

CI 會在 Windows 與 Linux 跑同樣的檢查（`.github/workflows/ci.yml`）。測試不會碰到你真正的狀態資料夾（`USBTETHER_HOME` 被導向暫存目錄），也不會動到真正的檔案關聯（使用測試用的登錄機碼）。

## 4. 從原始碼執行

```powershell
usbtether devices                    # 隨身碟能不能用？
usbtether enroll E: --remember       # 每支隨身碟做一次
usbtether app                        # 桌面面板
python examples\web_demo\app.py      # 網頁 demo，http://127.0.0.1:8000
```

## 5. 建置 Windows 安裝程式

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

它會：

1. 把 PyInstaller 和本套件裝進 `.venv`（沒有就用 `PATH` 上的 `python`）。
2. 用 PyInstaller 建出 `build\dist\usbtether\usbtether.exe`：單一資料夾、沒有主控台視窗，入口是 [packaging/usbtether_entry.py](../packaging/usbtether_entry.py)（不帶參數開啟面板；其他參數就是一般 CLI，例如 `usbtether.exe open "<檔案>"`）。
3. 找到 Inno Setup（`$env:ISCC`、`PATH`、它的解除安裝登錄資料、常見資料夾），編譯 [packaging/usbtether.iss](../packaging/usbtether.iss)。

產出：`build\installer\usbtether-setup-<版本>.exe`（約 13 MB）。版本號取自 `src/usbtether/__init__.py`。

安裝程式是「目前使用者」安裝（`%LOCALAPPDATA%\Programs\usbtether`，不需要系統管理員）。會顯示授權條款、寫入 `.utenc` 關聯，並依選擇建立桌面捷徑與開機啟動。解除安裝會移除這些，但刻意保留 `%APPDATA%\usbtether`。

### 發布前的冒煙測試

1. 安裝新的 `usbtether-setup-<版本>.exe`。
2. 從開始功能表開啟 *usbtether*：面板顯示 *Waiting for the USB drive*。
3. 插入已註冊的隨身碟：變成綠色（*Unlocked*）。
4. 用 *+ Add folder* 綁定一個放了 `.txt` 的測試資料夾：檔案變成 `.txt.utenc`。
5. 雙擊它：用記事本開啟。修改、存檔、關閉。
6. 拔掉隨身碟：`%APPDATA%\usbtether\open` 是空的。
7. 從「設定 > 應用程式」解除安裝。

## 6. 發布新版本

1. 修改 `src/usbtether/__init__.py` 的 `__version__`，並把 [CHANGELOG.md](../CHANGELOG.md) 中 *Unreleased* 的項目移到新版本底下。
2. 執行檢查（第 3 節）、建置（第 5 節）、冒煙測試。
3. Commit、打 tag（`git tag v<版本>`）、連同 tag 一起 push。
4. 在 GitHub 建立 release，附上 `usbtether-setup-<版本>.exe`。

執行檔沒有程式碼簽章，所以 Windows SmartScreen 第一次執行時可能會警告（「其他資訊 > 仍要執行」）。要簽章需要程式碼簽章憑證；取得後在 `.iss` 加上 `SignTool=`。

## 7. 修改圖示

圖示是 `src/usbtether/usbtether.ico`，由 [packaging/make_icon.py](../packaging/make_icon.py) 只用標準函式庫畫出。修改那裡的繪圖程式後執行 `python packaging\make_icon.py`。

## 8. 建置疑難排解

| 問題 | 解法 |
|---|---|
| `Inno Setup 6 not found` | 安裝它，或把 `$env:ISCC` 設成 `ISCC.exe` 的完整路徑 |
| `running scripts is disabled` | 照上面用 `powershell -ExecutionPolicy Bypass -File ...` 執行 |
| 建好的 exe 開不起面板 | exe 沒有主控台，看不到錯誤；從原始碼執行 `python -m usbtether app` 就看得到 |
| 防毒軟體隔離 exe | 未簽章的 PyInstaller 執行檔常見；簽章或把建置資料夾加入排除 |
| `No module named tkinter` | 改用 python.org 的 Python（有些發行版沒附 Tk） |
