# 使用指南

以 Windows 為主的逐步教學（Linux 差異另行註明），以及日常管理與疑難排解。English: [usage.md](usage.md)。

## 1. 安裝

需要 Python 3.10 以上。在專案資料夾內：

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements-demo.txt      # 函式庫 + CLI + Web demo
```

* `requirements.txt` 只裝函式庫與 CLI；`requirements-dev.txt` 另外包含測試與 lint 工具。
* 如果 PowerShell 擋住 `activate`（執行原則），先執行 `Set-ExecutionPolicy -Scope Process RemoteSigned`，或改用傳統命令提示字元。
* 也可以不啟用虛擬環境，直接呼叫 `.venv\Scripts\usbtether.exe`。

Linux 請用 `python3 -m venv .venv && source .venv/bin/activate`。

## 2. 確認你的隨身碟能不能用

插上隨身碟，執行：

```
usbtether devices
```

```
[1] 0781:5567  SanDisk Cruzer Blade USB Device
    serial   : 4C530001230101117333  (good)
    mounted  : E:\
    bindable : yes
```

`bindable : yes` 表示隨身碟回報了真正的序號，可以註冊。
`bindable : NO` 表示它沒有回報序號、回報的是佔位值，或是 Windows 依連接埠自己編的號碼；usbtether 會拒絕這類隨身碟，因為分不出是哪一支。請換一支試試。如果你有兩支同型號的碟，請確認它們的序號不一樣。

## 3. 註冊（每支隨身碟做一次）

```
usbtether enroll E: --label "my key" --remember
```

* `E:` 是**目前**的磁碟機代號。代號不屬於身分資訊，之後變動也沒關係。
* `--label` 是備註文字，會顯示在 `usbtether list`。
* 保護選項決定碟上的私鑰如何存放：

| 選項 | 要輸入嗎 | 意義 |
|---|---|---|
| `--remember`（**在自己的電腦上建議使用**） | 不用 | 私鑰用一個隨機密鑰加密，這個密鑰只存在**這台電腦**（Windows DPAPI，綁定你的 Windows 帳號），不會放在隨身碟上。插上就能用。沒有這台電腦的密鑰，隨身碟本身無法簽署任何東西。只能在這台電腦、這個帳號解鎖。 |
| `--passphrase` | 每次都要 | 私鑰用口令加密，現在輸入兩次，之後每次使用都要輸入。可用在任何電腦。**口令無法找回**；忘記時用 `--force` 重新註冊。 |
| （都不加） | 不用 | 私鑰不加密。拿到隨身碟的人就等於拿到金鑰。 |

過程：在隨身碟的 `.usbtether` 資料夾建立金鑰對；把公鑰與這支碟的硬體指紋存在**這台電腦**；再跑一次真正的 challenge-response 當自我測試。只有看到 `A challenge-response self-test passed.` 才算成功，任何失敗都會把寫入的東西全部清掉，包括記住的密鑰。

隨身碟照常可以存一般檔案，只要不要刪除或修改 `.usbtether`。

## 4. 驗證

```
usbtether verify
```

`OK  token <id>` 代表：正確的金鑰、在正確的實體隨身碟上、而且是現在。如果同時插了多支已註冊的碟，要指定一支：`usbtether verify E:`。

用 `--remember` 註冊的不會問任何東西；用 `--passphrase` 的才會要求輸入口令。

## 5. 確認複製沒有用

用第二支隨身碟 `F:`：

```
xcopy /E /I E:\.usbtether F:\.usbtether
usbtether verify F:
```

預期結果：`FAILED  device_mismatch`。金鑰是有效的，但它不在當初註冊的那支隨身碟上。（回報與原碟相同 USB 描述資訊的裝置會通過，見 [threat-model.md](threat-model.md)。）

## 6. 在你自己的程式裡使用

```python
from usbtether import Agent, Authorizer, PresenceMonitor, Registry, Verifier, default_probe

probe = default_probe()
authorizer = Authorizer(Verifier(Registry.default()))
agent = Agent(probe)

session = authorizer.open_session_local(agent)  # 開始時驗證一次
with PresenceMonitor(probe, authorizer):  # 拔除就撤銷 session
    cap = authorizer.issue_capability_local(  # 針對這個操作的全新 challenge
        agent, session.session_id, resource="database", action="write"
    )
    authorizer.consume(cap, resource="database", action="write")  # 僅能使用一次
    do_the_sensitive_thing()
```

* **Session** 本身不給任何權限。每個受保護的操作都要自己的 capability，而取得 capability 需要與隨身碟重新做一次 challenge-response。
* Capability 只能用一次、只限一組 `(resource, action)`、8 秒內有效。
* 失敗會丟出 `usbtether.UsbTetherError`（沒插碟、碟不對、金鑰被鎖…）或 `usbtether.AuthorizationError`（帶有穩定的 `.reason`，例如 `session_inactive`、`capability_used`、`device_mismatch`）。
* 私鑰有保護？用 `--remember` 註冊的會自動解鎖（agent 會先查 host 端的密鑰庫）。`--passphrase` 的金鑰則用 `Agent(probe, passphrase=b"...")`，或傳入一個回傳口令的函式（只有金鑰真的有加密時才會被呼叫）。

完整且有測試的範例：[examples/sdk_quickstart.py](../examples/sdk_quickstart.py)。

## 7. Web demo

```
python examples\web_demo\app.py
```

開啟 <http://127.0.0.1:8000>。用 `--remember` 註冊的直接可用；`--passphrase` 的要先設環境變數：`$env:USBTETHER_PASSPHRASE="..."`（PowerShell）或 `set USBTETHER_PASSPHRASE=...`（cmd）。詳見 [examples/web_demo/README.md](../examples/web_demo/README.md)。

## 8. 日常管理

| 想做什麼 | 指令 |
|---|---|
| 列出已註冊的 token | `usbtether list` |
| 撤銷 token（隨身碟遺失或被偷） | `usbtether revoke <token id>`（id 從 `list` 取得） |
| 重新註冊同一支碟 | `usbtether enroll E: --force`（舊的 token 會被撤銷） |
| 在多支已註冊的碟中指定一支 | `usbtether verify E:` |
| 改用其他狀態資料夾 | `--home <dir>` 或環境變數 `USBTETHER_HOME` |

**隨身碟遺失或被偷。** 執行 `usbtether revoke <id>`，在這台電腦上立刻失效。撤銷**不會自動同步**：每一台持有 registry 副本的電腦都要各做一次。

**隨身碟被格式化或清空。** 碟上的 token 沒了，但這台電腦還記得它。執行 `usbtether enroll E: --force`。

**忘記口令，或遺失記住的密鑰**（重灌 Windows、換了 Windows 帳號）。沒有任何方法可以找回金鑰。用 `usbtether enroll E: --force` 換一把新的（這個流程不需要舊金鑰）。

**更改金鑰的保護方式。** 重新註冊：`usbtether enroll E: --remember --force`（或 `--passphrase`、或都不加）。先前的 token 會被撤銷。

**同一支碟在多台電腦使用。** 每台電腦各自依自己的 registry 判斷。隨身碟的硬體指紋在每台電腦上都一樣，所以把註冊那台的 registry 檔複製到另一台的相同位置即可（見第 9 節）。目前沒有自動同步。**不要**在第二台電腦上執行 `enroll --force`，那會替換碟上的金鑰，讓第一台失效。用 `--remember` 的金鑰只能在註冊它的那台電腦解鎖；要在多台電腦使用，請用 `--passphrase`（或不加密）。

## 9. 資料存放位置

| 內容 | 位置 |
|---|---|
| 私鑰、token 說明檔 | 在隨身碟上：`<磁碟機>\.usbtether\private_key.pem`、`token.json` |
| 公鑰、裝置指紋、撤銷紀錄 | Windows：`%APPDATA%\usbtether\registry.json`；Linux：`~/.local/share/usbtether/registry.json` |
| `--remember` 金鑰的密鑰 | Windows：`%APPDATA%\usbtether\secrets\<token id>.bin`，以 DPAPI 封裝（只有你的 Windows 帳號讀得出來）；Linux：同路徑，僅擁有者可讀的檔案權限 |
| Session、capability、challenge | 只在程式記憶體中，程式結束就消失 |

請把 `registry.json` 當成憑證庫看待（誰能寫入它，誰就能註冊 token），並且不要把 `.usbtether/` 或 `registry.json` 提交到版本控制（專案的 `.gitignore` 已排除）。

## 10. 結束代碼（CLI）

| 代碼 | 意義 |
|---|---|
| 0 | 成功 |
| 1 | 操作失敗（驗證失敗、拒絕註冊…） |
| 2 | 指令用法錯誤 |
| 3 | 平台或 USB 查詢失敗（找不到 PowerShell、不支援的作業系統） |

## 11. 疑難排解

| 你看到的訊息 | 意義與處理 |
|---|---|
| `No USB mass-storage devices found.` | 沒偵測到任何碟。重新插拔、換個連接埠，插上後等幾秒。 |
| `bindable : NO` / `error: this drive cannot be bound: its serial number is ...` | 這支碟沒有可用的序號，請換一支。 |
| `error: no USB drive is mounted at 'F:'` | 代號錯了，或碟沒有掛載。用 `usbtether devices` 確認。 |
| `error: no USB drive with a usbtether token is plugged in` | 碟沒插、或還沒註冊。請先註冊（第 3 節）。 |
| `error: several enrolled drives are plugged in (...)` | 指定其中一支：`usbtether verify E:`。 |
| `error: this drive is already enrolled; ... (--force)` | 加上 `--force` 重新註冊（會撤銷舊 token）。 |
| `FAILED  device_mismatch` | token 所在的實體隨身碟與註冊的不同（被複製，或是另一支碟）。 |
| `FAILED  unknown_token` | 這台電腦的 registry 沒有這個 token：在別台註冊的，或 registry 被刪了。複製 `registry.json` 或重新註冊。 |
| `FAILED  token_revoked` | 這個 token 已在這台電腦上被撤銷。用 `--force` 重新註冊。 |
| `FAILED  device_unsupported` | 這支碟沒有回報可用的序號。 |
| `FAILED  bad_signature` | 金鑰與 registry 不符（被替換或損毀）。重新註冊。 |
| `error: wrong passphrase or corrupt private key` | 重新輸入口令；忘記的話見第 8 節。 |
| Web demo：`The key is passphrase-protected. Enroll it again with 'usbtether enroll <drive> --remember --force' ...` | 金鑰需要口令，而 demo 無法詢問。用 `--remember --force` 重新註冊，或設定 `USBTETHER_PASSPHRASE` 後重啟。 |
| `error: the private key is passphrase-protected` | 函式庫呼叫遇到加密的金鑰，卻沒有密鑰可用。用 `--remember` 註冊，或對 `Agent` 傳入 `passphrase=`。 |
| `error: cannot unprotect the stored secret (was it saved by another Windows user?)` | `--remember` 的密鑰是在別的 Windows 帳號或別台電腦存的。在這個帳號用 `--remember --force` 重新註冊。 |
| `error: could not run PowerShell: ...` / `PowerShell exited with ...` | 找不到 `powershell.exe`、被政策封鎖，或太慢。執行 `powershell -NoProfile -Command "Get-CimInstance Win32_DiskDrive"` 看它本身能不能運作。 |
| `error: usbtether has no USB probe for platform 'darwin'` | 只支援 Windows 與 Linux。 |
| `error: cannot read registry ...` | `registry.json` 損毀或無法讀取。還原備份，或刪除後重新註冊。 |

如果 `usbtether devices` 對你的碟判斷有誤，請開一個 *Drive report* issue，貼上 `usbtether devices --json --redact` 的輸出（序號會被遮蔽）。

## 12. 常見問題

**隨身碟還能正常存檔案嗎？** 可以。token 只是 `.usbtether` 裡兩個很小的檔案，不要刪掉資料夾就好。

**磁碟機代號有影響嗎？** 沒有。每次插拔或換電腦都可能不同。

**插哪個 USB 埠有差嗎？** 沒有（前提是這支碟有真正的序號）。

**能防止隨身碟被複製嗎？** 能擋隨手複製。擋不住能讓裝置回報相同 USB 描述資訊的人，也擋不住你電腦上的惡意程式。仰賴它之前請先讀 [threat-model.md](threat-model.md)。
