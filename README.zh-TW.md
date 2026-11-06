# usbtether

**把工作階段（session）綁定到一支普通的 USB 隨身碟。**

[English](README.md) · [繁體中文](README.zh-TW.md)

[![CI](https://github.com/ChouYangEn0401/usbtether/actions/workflows/ci.yml/badge.svg)](https://github.com/ChouYangEn0401/usbtether/actions/workflows/ci.yml)

usbtether 把一般的 USB 隨身碟變成「在場證明型」憑證：程式可以要求「必須插著當初註冊過的那一支隨身碟」才能開啟工作階段，並且在每個敏感步驟重新確認。

* **綁定實體裝置**：憑證是存放在隨身碟上的 Ed25519 金鑰，並且在主機端與該隨身碟的 USB 描述資訊（廠商 ID、產品 ID、序號）綁定。把檔案複製到另一支隨身碟，得到的不是可用的複本。
* **挑戰—回應（challenge-response）**：每次驗證都是全新、單次使用、綁定用途的 challenge，由 token 簽章，無法重放。
* **短效授權**：Session 本身不給任何權限。每個受保護的操作都需要自己的 challenge，並取得單次使用、限定範圍、數秒內到期的 capability。拔掉隨身碟會撤銷 session。
* **插上就能用**：`--remember` 用一個只存在*你電腦*上的密鑰（Windows DPAPI）加密私鑰，不用輸入任何東西，而且沒有那台電腦，隨身碟本身無法簽章。
* **用你現有的隨身碟就能做**：不需要特殊硬體。

> [!IMPORTANT]
> **安全等級：便利性等級。** 普通 USB 隨身碟無法自行運算簽章，也無法隱藏金鑰。usbtether 能擋的是「隨手複製憑證」；**擋不住**能讓另一個裝置回報相同 USB 描述資訊的攻擊者，也擋不住已被入侵的主機。如果這些對你很重要，請改用 FIDO2/WebAuthn 安全金鑰。詳見 [docs/threat-model.md](docs/threat-model.md)（英文）。

## 狀態

Alpha（0.1.x）。1.0 之前，協定、token 格式與 API 都可能變動。

| 平台 | 支援程度 |
|---|---|
| Windows 10/11 | 主要目標。裝置探測使用 PowerShell/CIM。已在一台真實 Windows 電腦、搭配一支 USB 3.0 隨身碟上確認可用（註冊與驗證）；解析器有用錄製的輸出做單元測試，CI 也會執行腳本做冒煙測試。尚未在大量隨身碟上驗證，歡迎回報你的結果。 |
| Linux | 實驗性（sysfs），主要供開發與 CI 使用。 |
| macOS | 不支援。 |

需要 Python 3.10 以上。唯一的執行期相依套件是 [`cryptography`](https://cryptography.io/)。

## 安裝

尚未發佈到 PyPI。請在原始碼目錄中安裝：

```bash
pip install .            # 函式庫 + CLI
pip install ".[demo]"    # 另加 Web demo 所需套件
pip install -e ".[dev]"  # 開發環境
```

習慣用 requirements 檔也可以，它們只是指向 `pyproject.toml`（唯一的依賴來源）：
`pip install -r requirements.txt`（函式庫）、`requirements-demo.txt`（加 Web demo）、`requirements-dev.txt`（開發）。

## 快速開始（CLI）

Windows 逐步教學、日常管理與疑難排解：**[docs/usage.zh-TW.md](docs/usage.zh-TW.md)**。

```console
> usbtether devices
[1] 0781:5567  SanDisk Cruzer Blade USB Device
    serial   : 4C530001230101117333  (good)
    mounted  : E:\
    bindable : yes

> usbtether enroll E: --label "desk key" --remember
Enrolled E:
  token id   : 0b6a0c4e-6c67-4b0c-9a58-2a7d1f4a8d11
  device     : 0781:5567
  protected  : secret stored on this computer
  note       : unlocks automatically on this computer only
A challenge-response self-test passed.

> usbtether verify
OK  token 0b6a0c4e-6c67-4b0c-9a58-2a7d1f4a8d11
```

把 `.usbtether` 資料夾複製到另一支隨身碟後，`usbtether verify F:` 會失敗並回報 `device_mismatch`。`usbtether list` 列出已註冊的 token，`usbtether revoke <id>` 撤銷一個。

用 `usbtether devices` 可以確認你的隨身碟能不能用。**沒有回報序號、或序號是佔位值的隨身碟無法註冊**，很多便宜的隨身碟就是這樣。

## 快速開始（函式庫）

```python
from usbtether import Agent, Authorizer, PresenceMonitor, Registry, Verifier, default_probe

probe = default_probe()
authorizer = Authorizer(Verifier(Registry.default()))
agent = Agent(probe)

session = authorizer.open_session_local(agent)  # 需要已註冊的隨身碟
with PresenceMonitor(probe, authorizer):  # 拔除時撤銷 session
    cap = authorizer.issue_capability_local(  # 針對這個動作的全新 challenge
        agent, session.session_id, resource="database", action="write"
    )
    authorizer.consume(cap, resource="database", action="write")  # 僅能使用一次
```

完整且有測試的範例在 [examples/sdk_quickstart.py](examples/sdk_quickstart.py)。所有錯誤都繼承自 `usbtether.UsbTetherError`；授權失敗為 `AuthorizationError`，帶有穩定的 `reason` 代碼。

## Web demo

用來實驗的測試台（不是可部署的服務），在瀏覽器中走完整個流程：12 步驟的受保護工作流程，以及保險箱解鎖實驗。見 [examples/web_demo](examples/web_demo/README.md)。

```bash
pip install ".[demo]"
usbtether enroll E:
python examples/web_demo/app.py        # http://127.0.0.1:8000
```

## 運作原理

```
 註冊（一次）                            驗證（每次）

 USB 隨身碟                              Verifier                     Agent
 +--------------+   公鑰、               +-----------+   challenge    +-----------+
 | 私鑰         |   裝置指紋             | registry  | -------------> | 讀取 USB  |
 | token.json   | -------------------> | （主機端）|                | 並簽章    |
 +--------------+                       |           | <------------- |           |
                                        +-----------+  已簽章回應    +-----------+
```

1. **註冊**：在隨身碟上產生金鑰對；把公鑰與裝置指紋存進**主機端**的 registry；自我測試；任何一步失敗就完整回滾。
2. **驗證**：verifier 發出 challenge；agent 把它與所觀察到的裝置資訊一起簽章；verifier 檢查 challenge、token、簽章，以及裝置指紋是否等於註冊時的指紋。
3. **授權**：在驗證之上建立 session 與單次使用的 capability。

關鍵在於：用來辨識隨身碟的資料存在**主機端**而不是隨身碟上，所以複製出去的檔案雖然帶著有效的金鑰，卻帶不走正確的硬體身分。

完整規格：[docs/protocol.md](docs/protocol.md) · 架構：[docs/architecture.md](docs/architecture.md) · 裝置身分：[docs/device-identity.md](docs/device-identity.md)（文件為英文）。

## 能防什麼、不能防什麼

| | |
|---|---|
| 把 token 檔案複製到另一支隨身碟 | 能擋 |
| 重放攔截到的回應 | 能擋 |
| 把回應拿去用在別的動作 | 能擋 |
| 使用沒有真實序號的隨身碟 | 拒絕 |
| 隨身碟拔除後繼續操作 | 能擋（輪詢偵測，加上 capability 8 秒壽命） |
| 回報相同 USB 描述資訊的裝置（改寫控制器韌體、虛擬裝置） | **擋不住** |
| 主機上的惡意程式 | **擋不住** |
| 有人拿到沒有加密的隨身碟 | 在你撤銷之前**擋不住**；請使用 `--remember` 或 `--passphrase` |

## 相關作品

* **[pam_usb](https://wiki.archlinux.org/title/Pam_usb)**（Linux）用普通 USB 隨身碟做使用者驗證：檢查序號、廠商與型號，並在每次登入後改寫隨身碟上的一次性 pad，讓被複製的版本過期。usbtether 的想法與它一致，但面向 Windows 與函式庫用途；滾動密鑰列在[路線圖](#路線圖)中。
* **YubiKey、FIDO2/WebAuthn、智慧卡、OpenPGP token** 把私鑰放在防竄改的硬體內，是「必須做到無法複製」時的正解。usbtether 適用於拿不到這類硬體的情況。

## 路線圖

* 在更多真實隨身碟上驗證 Windows 探測，並收集回報（[docs/device-identity.md](docs/device-identity.md)）。
* 以滾動密鑰來*偵測*被複製的隨身碟。
* Windows 上改用事件驅動的拔除偵測。
* 簽章的 registry 與撤銷清單。
* 為「agent / verifier 分離部署」提供傳輸層與參考 helper。

## 開發

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest
```

見 [CONTRIBUTING.md](CONTRIBUTING.md)。安全問題回報：[SECURITY.md](SECURITY.md)。變更紀錄：[CHANGELOG.md](CHANGELOG.md)。

## 緣起

usbtether 源自一個小型的「USB crypto playground」實驗（capability 授權加上 USB 輔助解鎖）。那個實驗的 HMAC 檢查是在單一程序內、對一個可複製的金鑰檔進行，因此並沒有證明任何關於隨身碟的事。本專案以綁定裝置的 token 與可驗證的交換流程取代了它。

## 授權

[MIT](LICENSE)
