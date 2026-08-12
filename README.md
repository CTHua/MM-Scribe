# MM-Scribe

《瑪奇Mobile》個人傷害統計工具
僅適用於台港澳版本

---

## 免責聲明

【 MM Scribe 使用免責聲明 】

一、本工具由社群個人開發，與任何遊戲廠商、發行商並無合作、
    授權或關聯關係，亦非任何官方認可之工具。

二、本工具僅供個人學習研究與傷害分析用途，
    請勿用於任何商業行為或不當競技目的。

三、透過網路封包擷取遊戲資訊，可能違反相關遊戲之服務條款。
    使用者需自行評估風險與後果，包含但不限於
    帳號警告、停權或永久封鎖。

四、本工具僅在本機端解析封包內容，
    不會蒐集、儲存或傳送任何個人資料至外部伺服器。

五、開發者不對使用本工具所產生之任何直接或間接損失
    負任何法律或道義責任。

六、使用本工具即視為您已閱讀並同意上述所有條款。
    若不同意，請立即停止使用並刪除本程式。

---

## 主要功能

- **即時傷害統計**：累積傷害、DPS、爆擊 / 強擊 / 連擊覆蓋率

---

## 系統需求

### Windows

- Windows 10 / 11
- [Npcap](https://npcap.com/) 驅動
- 系統管理員權限（scapy 抓包需要）
- 原始碼版另需 Python 3.x 與相依套件：`customtkinter`、`scapy`

### macOS

- macOS 13 以上（Apple Silicon / Intel）
- libpcap 為系統內建，**不需要**安裝 Npcap 之類的驅動
- 抓包需要 BPF 裝置權限，二選一：
  - 安裝 [Wireshark](https://www.wireshark.org/) 內附的 **ChmodBPF**（一次設定，之後免 sudo）
  - 或以 `sudo` 執行
- Python 3.12 與相依套件：`customtkinter`、`scapy`

遊戲在 macOS 上是透過 App Store 安裝的 **iOS App on Mac**，
封包直接走實體網卡，不需要模擬器、網路共享或任何轉送設定。
封包格式與 Windows 端相同，解析邏輯共用。

#### 快速開始

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python scapy==2.7.0 customtkinter==5.2.2
./run-macos.sh
```

`run-macos.sh` 會自動判斷是否需要提權，並處理 uv 版 Python 的 Tcl/Tk 路徑問題。

---

## 設定檔說明

設定檔須放在 `MM Scribe.exe` 同一資料夾（或原始碼版的 [Score/](Score/) 資料夾內），修改後重啟程式生效。

macOS 打包成 `.app` 之後，設定檔改放在 `~/Library/Application Support/MM Scribe/`
（`.app` 內部不可寫，首次啟動會自動把預設檔複製過去）；直接跑原始碼時仍然是讀 [Score/](Score/)。

### [skills.ini](Score/skills.ini) — 技能 ID 對照與合併群組

```ini
[職業名稱]
0x技能ID = 顯示名稱

[合併群組-職業名稱]
合併名稱 = 顯示名稱1, 顯示名稱2, 顯示名稱3
```

- 技能 ID 支援 `0x64d5b11d` 或 `64d5b11d` 兩種寫法，大小寫皆可
- 以 `;` 或 `#` 開頭的行為註解
- 找不到對應 ID 的技能會顯示原始 hex ID

### [settings.ini](Score/settings.ini) — 顯示 / 追蹤 / 排版

```ini
[Display]
font_scale = 1.00              ; 字體縮放 1.0 ~ 2.0

[Tracking]
track_damage = true            ; 攻擊數值追蹤
track_heal = false             ; 治癒數值追蹤（Beta）

[Layout]
popout_log = false             ; 攻擊事件日誌獨立視窗
popout_skill = false           ; 技能傷害排行獨立視窗
```

---

## 打包方式

### Windows

**開發版**（顯示開發者選項）：

```bash
python -m PyInstaller --onefile --noconsole --collect-data customtkinter MabinogiMobileScribe_Beta_V0.43.py
```

**發布版**（隱藏開發者選項）：

```bash
type nul > RELEASE.marker
python -m PyInstaller --onefile --noconsole --collect-data customtkinter --add-data "RELEASE.marker;." MabinogiMobileScribe_Beta_V0.43.py
```

### macOS

`--add-data` 的分隔符是 `:` 而非 `;`，且要用 `--windowed` 產生 `.app`：

```bash
touch RELEASE.marker
python -m PyInstaller --windowed --collect-data customtkinter --add-data "RELEASE.marker:." MabinogiMobileScribe_Beta_V0.43.py
```

未經簽章與公證的 `.app` 會被 Gatekeeper 攔下，首次開啟需右鍵 →「打開」。
另外 `.app` 沒有「以系統管理員身分執行」這種選項，所以發布版建議搭配 ChmodBPF，
否則使用者只能從終端機以 `sudo` 啟動。

程式啟動時會偵測 EXE 內是否包含 `RELEASE.marker` 檔案，存在則隱藏開發者選項按鈕（釋出給他人使用）。

---

## 社群 / 回報問題

- Discord：<https://discord.gg/NaddqvBVvb>
- GitHub Issues：歡迎回報缺漏的技能 ID、封包格式異常或功能建議
