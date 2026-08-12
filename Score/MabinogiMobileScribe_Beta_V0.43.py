"""
瑪奇即時傷害監控 - customtkinter 版
需求: pip install customtkinter scapy
抓封包需要提權:Windows 以系統管理員執行;macOS 需 root 或已放寬 /dev/bpf* 權限。

支援 Windows 10/11 與 macOS (Apple Silicon / Intel)。
macOS 上遊戲為 iOS App on Mac,流量直接走實體網卡,抓法與 Windows 端相同。

打包說明:
  Windows 開發版 (顯示開發者選項):
    python -m PyInstaller --onefile --noconsole --collect-data customtkinter MabinogiMobileScribe_Beta_V0.43.py

  Windows 發布版 (隱藏開發者選項):
    type nul > RELEASE.marker
    python -m PyInstaller --onefile --noconsole --collect-data customtkinter --add-data "RELEASE.marker;." MabinogiMobileScribe_Beta_V0.43.py

  macOS (--add-data 分隔符是 ':' 不是 ';'):
    touch RELEASE.marker
    python -m PyInstaller --windowed --collect-data customtkinter --add-data "RELEASE.marker:." MabinogiMobileScribe_Beta_V0.43.py

  程式啟動時會偵測執行檔內是否包含 RELEASE.marker 檔案,
  存在則隱藏開發者選項按鈕(釋出給他人使用)。
"""
import configparser
import os
import struct
import sys
import threading
import time
import tkinter as tk  # 只用 StringVar / BooleanVar
import webbrowser
import customtkinter as ctk
from scapy.all import sniff, TCP, IP

# ----------------------------------------------------
# 平台差異
# ----------------------------------------------------
IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

# 字體:兩邊都需要「中文 UI 字體 + 等寬數字字體」,等寬是傷害欄位對齊的前提
if IS_MACOS:
    FONT_UI = "PingFang TC"
    FONT_MONO = "Menlo"
else:
    FONT_UI = "Microsoft JhengHei"
    FONT_MONO = "Consolas"


def is_release_build():
    """判定是否為 release 打包版。
    - 打包成 EXE 且內含 RELEASE.marker → True
    - 或環境變數 LDM_RELEASE=1 (方便開發時預覽發布 UI)
    - 其他情況 (含未打包的原始碼直接執行) → False
    """
    if getattr(sys, "frozen", False):
        marker_path = os.path.join(getattr(sys, "_MEIPASS", ""), "RELEASE.marker")
        if os.path.exists(marker_path):
            return True
    return os.environ.get("LDM_RELEASE") == "1"

# ----------------------------------------------------
# 設定
# ----------------------------------------------------
VERSION_STR = "Beta V0.43"
COVERAGE_MIN_HITS = 10  # 覆蓋率計算所需最少樣本數
SKILL_CFG_NAME = "skills.ini"
SETTINGS_CFG_NAME = "settings.ini"
FONT_SCALE_MIN = 1.0
FONT_SCALE_MAX = 2.0
FONT_SCALE_DEFAULT = 1.0
MERGE_GROUP_SECTION = "合併群組"
# Skill ID 提取 (見 HEAL_SHIELD_SKILL_ID.md §4)
HEAL_SHIELD_SKILL_NEAR_WINDOW = 300  # Near 掃描單向視窗大小 (bytes)
ALT_SKILL_MAX_GAP = 8                # 0x1ADE8 允許緊接 0x4EED 結束後的最大 gap
ALT_SKILL_BACKSCAN = 64              # 往前找 0x4EED 的搜尋深度
DISCORD_INVITE_URL = "https://discord.gg/NaddqvBVvb"
# 日誌欄位停靠點 (像素位置,交給 Text widget tab stop 對齊)
# 布局: [技能名稱] \t [傷害值 (右對齊)] \t [標籤]
LOG_TAB_STOPS = ("130", "240")
RELEASE_BUILD = is_release_build()


def get_resource_path(filename):
    """取得資源檔的實際路徑。
    - 打包成執行檔後: 資料位於 PyInstaller 解壓的臨時目錄 sys._MEIPASS
    - 未打包 (直接跑 .py): 使用腳本所在資料夾
    定義必須排在 get_external_path 之前 — 後者在 macOS 打包版會呼叫它,
    而 load_skill_config() 是在模組層級就執行的。
    """
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", "")
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, filename)


def get_external_path(filename):
    """取得 EXE 旁邊(或原始碼所在資料夾)的外部檔路徑。
    與 get_resource_path 不同,這是使用者可編輯的檔案位置,不是 PyInstaller bundled 資源。
    """
    if not getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

    if IS_MACOS:
        # .app 內的 Contents/MacOS 使用者根本不會去翻,而且 /Applications 通常
        # 也不可寫,所以改放 Application Support,並在首次執行時把 bundle 內的
        # 預設檔複製過去當種子。
        base = os.path.expanduser("~/Library/Application Support/MM Scribe")
        target = os.path.join(base, filename)
        if not os.path.exists(target):
            seed = get_resource_path(filename)
            if os.path.exists(seed):
                try:
                    import shutil
                    os.makedirs(base, exist_ok=True)
                    shutil.copy(seed, target)
                except OSError:
                    return seed  # 複製不過去就退回唯讀的 bundle 版本,至少能跑
        return target

    return os.path.join(os.path.dirname(sys.executable), filename)


def load_skill_config():
    """從 EXE 同資料夾下的 skills.ini 讀取 skill_id 對照與合併群組。
    格式範例:
        [戰士]
        0x64d5b11d = 普攻
        0x21dd59c4 = 旋風斬

        [合併群組]                ; 全域合併群組
        [合併群組-戰士]           ; 也接受後綴 (-/:/./_/空白) 用於分類整理
        爆裂射擊 = 爆裂射擊, 爆裂射擊+, 爆裂射擊(火藥), 爆裂射擊+(火藥)

    後綴僅為註記,所有合併群組區段共用同一命名空間;群組名跨區段重複時會觸發衝突。

    回傳 (skill_names, merge_groups, conflicts, errors)
      - skill_names:  dict[int skill_id, str display_name]
      - merge_groups: dict[str member_name, str group_name]
      - conflicts:    list[(member, first_group, ignored_group)] 供 UI 提示
      - errors:       list[str] 解析過程中的錯誤訊息 (檔案級 or 逐行) 供 UI 顯示
    檔案不存在回傳空結果 (errors 為空);解析失敗回傳已成功部分 + 錯誤訊息。
    """
    path = get_external_path(SKILL_CFG_NAME)
    if not os.path.exists(path):
        return {}, {}, [], []
    errors = []
    parser = configparser.ConfigParser()
    parser.optionxform = str  # 保留原大小寫,避免 0x64D 被轉小寫影響閱讀
    try:
        parser.read(path, encoding="utf-8")
    except configparser.DuplicateOptionError as e:
        errors.append(f"重複的 key:[{e.section}] '{e.option}' (第 {e.lineno} 行) — INI 同一區段內不允許同名 key")
        return {}, {}, [], errors
    except configparser.DuplicateSectionError as e:
        errors.append(f"重複的區段:[{e.section}] (第 {e.lineno} 行)")
        return {}, {}, [], errors
    except configparser.MissingSectionHeaderError as e:
        errors.append(f"缺少區段標頭:第 {e.lineno} 行 '{e.line.strip()}' — 檔案開頭必須先有 [區段名]")
        return {}, {}, [], errors
    except configparser.ParsingError as e:
        errors.append(f"解析錯誤:{e}")
        return {}, {}, [], errors
    except UnicodeDecodeError as e:
        errors.append(f"編碼錯誤:檔案不是 UTF-8 (byte {e.start}: {e.reason}) — 請以 UTF-8 存檔")
        return {}, {}, [], errors
    except Exception as e:
        errors.append(f"未預期錯誤:{type(e).__name__}: {e}")
        return {}, {}, [], errors
    names = {}
    groups = {}
    conflicts = []

    def _is_merge_section(name):
        # 允許 [合併群組] 或 [合併群組<sep>xxx],sep 可為 - : . _ 或空白
        if name == MERGE_GROUP_SECTION:
            return True
        if name.startswith(MERGE_GROUP_SECTION):
            return name[len(MERGE_GROUP_SECTION):len(MERGE_GROUP_SECTION)+1] in ("-", ":", ".", "_", " ")
        return False

    for section in parser.sections():
        if _is_merge_section(section):
            for group_name, members_str in parser.items(section):
                group_name = group_name.strip()
                if not group_name:
                    continue
                for member in members_str.split(","):
                    member = member.strip()
                    if not member:
                        continue
                    if member in groups:
                        conflicts.append((member, groups[member], group_name))
                        continue
                    groups[member] = group_name
            continue
        for key, value in parser.items(section):
            try:
                skill_id = int(key.strip(), 16)  # 支援 "0x..." 或純十六進位
            except ValueError:
                errors.append(f"[{section}] '{key}' 不是有效的十六進位 skill ID,已略過")
                continue
            name = value.strip()
            if name:
                names[skill_id] = name
    return names, groups, conflicts, errors


# 每次按下「開始」都會重新讀取 (見 start_monitoring)
# 開程式時預先載一次,方便主程式建立初始狀態
SKILL_NAMES, MERGE_GROUPS, _, _ = load_skill_config()


def load_settings():
    """讀取 settings.ini,回傳 dict。缺檔或解析失敗回傳預設值。"""
    defaults = {
        "font_scale": FONT_SCALE_DEFAULT,
        "track_damage": True,
        "track_heal": False,
        "popout_log": False,
        "popout_skill": False,
    }
    path = get_external_path(SETTINGS_CFG_NAME)
    if not os.path.exists(path):
        return defaults
    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return defaults
    result = dict(defaults)
    try:
        raw = parser.get("Display", "font_scale", fallback=str(FONT_SCALE_DEFAULT))
        scale = float(raw)
        # 夾到合法範圍,避免手改 ini 塞奇怪值
        result["font_scale"] = max(FONT_SCALE_MIN, min(FONT_SCALE_MAX, scale))
    except (ValueError, configparser.Error):
        pass
    try:
        result["track_damage"] = parser.getboolean("Tracking", "track_damage", fallback=True)
    except (ValueError, configparser.Error):
        pass
    try:
        result["track_heal"] = parser.getboolean("Tracking", "track_heal", fallback=False)
    except (ValueError, configparser.Error):
        pass
    try:
        result["popout_log"] = parser.getboolean("Layout", "popout_log", fallback=False)
    except (ValueError, configparser.Error):
        pass
    try:
        result["popout_skill"] = parser.getboolean("Layout", "popout_skill", fallback=False)
    except (ValueError, configparser.Error):
        pass
    return result


def save_settings(settings):
    """把 settings dict 寫回 settings.ini。寫入失敗靜默忽略 (下次載入用預設)。
    ini 內部以英文命名,避免非 ASCII 字元造成使用者手動編輯時的編碼疑慮。
    """
    path = get_external_path(SETTINGS_CFG_NAME)
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser["Display"] = {"font_scale": f"{settings.get('font_scale', FONT_SCALE_DEFAULT):.2f}"}
    parser["Tracking"] = {
        "track_damage": "true" if settings.get("track_damage", True) else "false",
        "track_heal": "true" if settings.get("track_heal", False) else "false",
    }
    parser["Layout"] = {
        "popout_log": "true" if settings.get("popout_log", False) else "false",
        "popout_skill": "true" if settings.get("popout_skill", False) else "false",
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            parser.write(f)
    except Exception:
        pass


def format_skill_name(skill_id):
    """把 skill_id 轉為顯示名稱。
    - 0x00000000  → 「疑似符文傷害」(依 PacketNotes §5,符文附加傷害的 skill ID 為 0)
    - SKILL_NAMES 有對應 → 使用者命名
    - 其他        → 顯示 hex ID
    """
    if skill_id == 0:
        return "疑似符文傷害"
    return SKILL_NAMES.get(skill_id) or f"0x{skill_id:08X}"


def check_capture_backend():
    """檢查抓封包所需的底層驅動是否就緒。
    - Windows: 需安裝 Npcap / WinPcap,檢查關鍵 DLL 是否存在
    - macOS:   libpcap 為系統內建,改為檢查是否有 BPF 裝置節點
    回傳 (ok: bool, hint: str) — hint 為失敗時要顯示給使用者的補救說明。
    """
    if IS_WINDOWS:
        candidates = [
            r"C:\Windows\System32\Npcap\wpcap.dll",       # Npcap 標準安裝路徑
            r"C:\Windows\System32\Npcap\Packet.dll",
            r"C:\Windows\SysWOW64\Npcap\wpcap.dll",       # 32-bit 相容位置
            r"C:\Windows\System32\wpcap.dll",             # 舊 WinPcap 或 Npcap 相容模式
            r"C:\Windows\SysWOW64\wpcap.dll",
        ]
        if any(os.path.exists(p) for p in candidates):
            return True, ""
        return False, "請至 https://npcap.com/ 下載並安裝"

    if IS_MACOS:
        # libpcap 自 macOS 11 起收進 dyld shared cache,檔案系統上看不到,
        # 因此不驗證 dylib,只確認 BPF 裝置節點存在 (權限另由 check_capture_permission 判斷)
        if any(os.path.exists(f"/dev/bpf{i}") for i in range(4)):
            return True, ""
        return False, "系統找不到 /dev/bpf* 裝置節點"

    return False, f"尚未支援的作業系統: {sys.platform}"


def check_capture_permission():
    """檢查目前是否具備開啟抓包裝置的權限。
    - Windows: 是否以系統管理員身分執行
    - macOS:   /dev/bpf* 多半是 root:wheel 0600,但裝了 Wireshark 的 ChmodBPF 後
               一般使用者也能讀,所以直接測「能不能真的開起來」而非只看 euid
    回傳 (ok: bool, detail: str)
    """
    if IS_WINDOWS:
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                return True, "scapy sniff 具備所需權限"
        except Exception:
            pass
        return False, "請關閉程式後對 exe 右鍵 →「以系統管理員身分執行」"

    if IS_MACOS:
        if os.geteuid() == 0:
            return True, "以 root 執行,具備 BPF 存取權限"
        for i in range(4):
            path = f"/dev/bpf{i}"
            if not os.path.exists(path):
                continue
            try:
                os.close(os.open(path, os.O_RDONLY))
                return True, "BPF 裝置可直接存取 (已套用 ChmodBPF)"
            except PermissionError:
                break
            except OSError:
                # 裝置存在但正被其他程式佔用 → 權限本身沒問題,換下一個試
                continue
        return False, ("BPF 裝置需要提權。建議安裝 Wireshark 內附的 ChmodBPF "
                       "(安裝後免 sudo),或改以 sudo 執行本程式")

    return False, f"尚未支援的作業系統: {sys.platform}"


def list_network_ifaces():
    """列舉可供 sniff 的網路介面,回傳統一格式的 dict 清單:
        {"name": 傳給 sniff(iface=) 的識別, "description": 顯示名稱, "ips": [IPv4...]}

    Windows 的 get_windows_if_list() 本來就是這個格式;macOS/Linux 走 scapy 的
    跨平台介面表,name 會是 BSD 名稱 (en0/en1/bridge100...)。
    """
    if IS_WINDOWS:
        from scapy.arch.windows import get_windows_if_list
        return list(get_windows_if_list())

    try:
        from scapy.interfaces import get_working_ifaces
        ifaces = get_working_ifaces()
    except ImportError:
        from scapy.config import conf
        ifaces = list(conf.ifaces.values())

    out = []
    for itf in ifaces:
        ip = getattr(itf, "ip", None)
        name = getattr(itf, "name", None) or str(itf)
        out.append({
            "name": name,
            "description": getattr(itf, "description", None) or name,
            "ips": [ip] if ip else [],
        })
    return out


def default_route_iface():
    """回傳預設路由所在的介面名稱,失敗則 None。
    掃描時把它排在最前面 — 遊戲流量幾乎都走這張。
    """
    try:
        from scapy.config import conf
        return conf.route.route("0.0.0.0")[0]
    except Exception:
        return None


# macOS 上這些介面依其用途就不可能承載遊戲流量,先剔除可省下大量掃描時間
# (一台開著虛擬機的 Mac 上,feth/bridge 之類的介面動輒十幾張)
_SKIP_IFACE_PREFIXES = ("lo", "feth", "gif", "stf", "awdl", "llw", "anpi", "ap")


def _is_never_game_traffic(name):
    """en/bridge/utun/vmenet 一律保留 — 實體網卡、虛擬機橋接、VPN 都可能是遊戲的出口。"""
    if not IS_MACOS or not name:
        return False
    return str(name).startswith(_SKIP_IFACE_PREFIXES)


IP_FILTER_NET = "43.0.0.0/8"
HIGHLIGHT_OPTIONS = ["無", "爆擊", "強擊", "破防", "無防備", "連擊", "多重打擊"]

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class LiveDamageMonitor:
    def __init__(self, root):
        self.root = root

        # 讀設定並在建立任何 widget 前先套用縮放 (widget/window scaling 都是全域狀態,
        # 提前設好 CTk 建立的元件會直接以正確尺寸誕生,不必事後重排)
        self.settings = load_settings()
        self.font_scale = self.settings["font_scale"]
        ctk.set_widget_scaling(self.font_scale)
        ctk.set_window_scaling(self.font_scale)

        self.root.title(f"MM Scribe {VERSION_STR}")
        # 初始高度 680;每個 popout 中的 pane 從初值扣 200,啟動就用正確高度,
        # 不能在 __init__ 尾端做 delta 調整 — 那時 winfo_height() 因視窗尚未 realize
        # 回傳 1,dcalc 後會被 clamp 到 200 → 主視窗變超小、看不到開始按鈕
        # 340 是「dmg_banner + 3 條控制列 + status_bar + padding」的合理下限,
        # 保證兩個都 popout 時也看得到計時器那排
        initial_h = 680
        if self.settings.get("popout_log", False):
            initial_h -= 200
        if self.settings.get("popout_skill", False):
            initial_h -= 200
        initial_h = max(340, initial_h)
        self.root.geometry(f"500x{initial_h}")

        # 設定視窗標題列 icon (優先用 dev icon,找不到再退回一般 icon)
        # macOS 的 Tk 不吃 .ico,改用 iconphoto 讀 PNG;打包成 .app 後
        # Dock 圖示是由 bundle 的 CFBundleIconFile 提供,這裡失敗不影響功能。
        if IS_MACOS:
            candidates = ("icon_dev.png" if not RELEASE_BUILD else "icon.png", "icon.png")
        else:
            candidates = ("icon_dev.ico" if not RELEASE_BUILD else "icon.ico", "icon.ico")
        for candidate in candidates:
            icon_path = get_resource_path(candidate)
            if not os.path.exists(icon_path):
                continue
            try:
                if IS_MACOS:
                    self._app_icon = tk.PhotoImage(file=icon_path)
                    self.root.iconphoto(True, self._app_icon)
                else:
                    self.root.iconbitmap(icon_path)
                break
            except Exception:
                pass
        # 最小尺寸:寬 400 高 180 (剛好夠塞看板+兩排控制列+日誌 header)
        self.root.minsize(400, 180)

        # 狀態變數
        self.total_damage = 0
        self.entity_map = {}
        self.entity_count = 0
        self.is_monitoring = False
        self.sniff_thread = None
        self.is_topmost = False
        self.is_dev_mode = False
        self.first_damage_time = None
        self.last_damage_time = None

        # 標籤覆蓋率統計 (資料筆數達 COVERAGE_MIN_HITS 才顯示)
        self.total_hits = 0
        self.tag_counts = {"爆擊": 0, "強擊": 0, "連擊": 0}

        # 技能傷害排行
        # skill_damage:    依 skill_id 累積的原始傷害
        # skill_hits:      依 skill_id 累積的命中次數 (含未攜帶標籤的普通擊)
        # skill_tag_counts: 依 skill_id 累積各標籤次數 (爆擊/強擊/連擊)
        # skill_rows:      已建立的顯示列 (以聚合後的 display name 為 key)
        self.skill_damage = {}
        self.skill_hits = {}
        self.skill_tag_counts = {}
        self.skill_rows = {}

        # 用 CTkFont 給 tk.Canvas 的技能列文字使用,才能跟 CTkLabel (detail) 走
        # 同一套字體/縮放管線 (widget_scaling × DPI scaling 都會自動套用),
        # 兩邊視覺大小一致。共用同一份 font instance,scale 變更時 CTk 會自動更新。
        self._skill_name_font = ctk.CTkFont(
            family=FONT_UI, size=12, weight="bold")
        self._skill_value_font = ctk.CTkFont(
            family=FONT_MONO, size=12, weight="bold")

        # Resize debounce: 拖窗期間暫停技能排行更新,停下 150ms 後補一次
        self._is_resizing = False
        self._resize_after_id = None

        # 自動選定的收包網卡 (由掃描結果決定,None = 讓 scapy 用預設)
        self.chosen_iface = None

        # 計時器:end_time 為 None 表示無倒數;after_id 用於取消已排程的 tick
        self.timer_end_time = None
        self.timer_after_id = None

        # 追蹤模式旗標 (由 settings 載入,可從設定畫面切換)
        self.track_damage = self.settings["track_damage"]
        self.track_heal = self.settings["track_heal"]
        self.track_damage_var = tk.BooleanVar(value=self.track_damage)
        self.track_heal_var = tk.BooleanVar(value=self.track_heal)

        # Popout 旗標 (獨立視窗顯示攻擊日誌 / 技能排行)
        # popout_log_win / popout_skill_win: Toplevel 或 None
        self.popout_log = self.settings["popout_log"]
        self.popout_skill = self.settings["popout_skill"]
        self.popout_log_var = tk.BooleanVar(value=self.popout_log)
        self.popout_skill_var = tk.BooleanVar(value=self.popout_skill)
        self._log_popout_win = None
        self._skill_popout_win = None

        # 提前建立 collapse 狀態與 merge_var,讓 pane 重建 (dock/popout) 時值可延續
        self.log_collapsed = False
        self._prev_height = None
        self.skill_collapsed = False
        self.merge_var = tk.BooleanVar(value=False)

        # 治癒統計 (heal_total = heal_self + heal_ally,累加自 0x5029 事件)
        self.heal_total = 0
        self.heal_self = 0
        self.heal_ally = 0
        # 本地玩家角色 ID:透過 0x502A ↔ 0x5029 交叉比對自動學習 (見 PacketNotes §5)
        # None 表示尚未學到;學到後整個 session 沿用
        # 護盾在 local_player_id 學到前無法可靠分類,一律走 heal_unknown (中性黃字)
        self.local_player_id = None

        # ----------------------------------------------------
        # 1. 頂部看板:傷害統計 (packing 交給 _apply_tracking_mode 依旗標控制)
        # ----------------------------------------------------
        self.dmg_banner = ctk.CTkFrame(root, corner_radius=0, fg_color="#1a1a1a")

        # -- 主要統計列: 累積傷害 + DPS --
        main_row = ctk.CTkFrame(self.dmg_banner, fg_color="transparent")
        main_row.pack(fill="x")

        left_stats = ctk.CTkFrame(main_row, corner_radius=0, fg_color="transparent")
        left_stats.pack(side="left", expand=True, fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(left_stats, text="累積傷害",
                     font=(FONT_UI, 12, "bold"),
                     text_color="#888888").pack()
        self.lbl_total_dmg = ctk.CTkLabel(left_stats, text="0",
                                          font=(FONT_MONO, 24, "bold"),
                                          text_color="#ff4d4d")
        self.lbl_total_dmg.pack(pady=(2, 0))

        right_stats = ctk.CTkFrame(main_row, corner_radius=0, fg_color="transparent")
        right_stats.pack(side="right", expand=True, fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(right_stats, text="DPS (每秒傷害)",
                     font=(FONT_UI, 12, "bold"),
                     text_color="#888888").pack()
        self.lbl_dps = ctk.CTkLabel(right_stats, text="0",
                                    font=(FONT_MONO, 24, "bold"),
                                    text_color="#ffcc4d")
        self.lbl_dps.pack(pady=(2, 0))

        # -- 覆蓋率列: 爆擊 / 強擊 / 連擊 (資料筆數 < COVERAGE_MIN_HITS 時顯示「—」) --
        cov_row = ctk.CTkFrame(self.dmg_banner, fg_color="transparent")
        cov_row.pack(fill="x", pady=(0, 8))

        self.lbl_cov = {}
        for tag_name in ("爆擊", "強擊", "連擊"):
            col = ctk.CTkFrame(cov_row, fg_color="transparent")
            col.pack(side="left", expand=True, fill="x", padx=4)
            ctk.CTkLabel(col, text=f"{tag_name}覆蓋率",
                         font=(FONT_UI, 12, "bold"),
                         text_color="#888888").pack()
            lbl = ctk.CTkLabel(col, text="—",
                               font=(FONT_MONO, 16, "bold"),
                               text_color="#88ccff")
            lbl.pack()
            self.lbl_cov[tag_name] = lbl

        # ----------------------------------------------------
        # 1.5 頂部看板:治癒統計 (packing 交給 _apply_tracking_mode)
        # ----------------------------------------------------
        self.heal_banner = ctk.CTkFrame(root, corner_radius=0, fg_color="#1a1a1a")

        # -- 主要統計: 治癒總量 --
        heal_total_row = ctk.CTkFrame(self.heal_banner, fg_color="transparent")
        heal_total_row.pack(fill="x")
        heal_total_col = ctk.CTkFrame(heal_total_row, fg_color="transparent")
        heal_total_col.pack(expand=True, fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(heal_total_col, text="治癒總量",
                     font=(FONT_UI, 12, "bold"),
                     text_color="#888888").pack()
        self.lbl_heal_total = ctk.CTkLabel(heal_total_col, text="0",
                                            font=(FONT_MONO, 24, "bold"),
                                            text_color="#4dd471")
        self.lbl_heal_total.pack(pady=(2, 0))

        # -- 子統計: 自身治癒 / 隊友治癒 --
        heal_sub_row = ctk.CTkFrame(self.heal_banner, fg_color="transparent")
        heal_sub_row.pack(fill="x", pady=(0, 8))
        self_col = ctk.CTkFrame(heal_sub_row, fg_color="transparent")
        self_col.pack(side="left", expand=True, fill="x", padx=4)
        ctk.CTkLabel(self_col, text="自身治癒",
                     font=(FONT_UI, 11, "bold"),
                     text_color="#888888").pack()
        self.lbl_heal_self = ctk.CTkLabel(self_col, text="0",
                                           font=(FONT_MONO, 16, "bold"),
                                           text_color="#4dd471")
        self.lbl_heal_self.pack()
        ally_col = ctk.CTkFrame(heal_sub_row, fg_color="transparent")
        ally_col.pack(side="left", expand=True, fill="x", padx=4)
        ctk.CTkLabel(ally_col, text="隊友治癒",
                     font=(FONT_UI, 11, "bold"),
                     text_color="#888888").pack()
        self.lbl_heal_ally = ctk.CTkLabel(ally_col, text="0",
                                           font=(FONT_MONO, 16, "bold"),
                                           text_color="#88ccff")
        self.lbl_heal_ally.pack()

        # ----------------------------------------------------
        # 2. 控制列 Row 1: 啟停/清除/置頂/開發者
        # ----------------------------------------------------
        self.ctrl_row1 = ctk.CTkFrame(root, corner_radius=0)
        self.ctrl_row1.pack(fill="x", padx=10, pady=3)
        ctrl_row1 = self.ctrl_row1  # local alias 保留現有引用

        self.btn_start = ctk.CTkButton(ctrl_row1, text="▶ 開始", width=70, corner_radius=8,
                                       command=self.start_monitoring)
        self.btn_start.pack(side="left", padx=(6, 2), pady=6)
        self.btn_stop = ctk.CTkButton(ctrl_row1, text="⏹ 停止", width=70, corner_radius=8,
                                      state="disabled", command=self.stop_monitoring)
        self.btn_stop.pack(side="left", padx=2, pady=6)
        # 記住停止按鈕預設樣式,用於停止監控後還原
        self._btn_stop_default_fg = self.btn_stop.cget("fg_color")
        self._btn_stop_default_hover = self.btn_stop.cget("hover_color")
        self.btn_clear = ctk.CTkButton(ctrl_row1, text="🧹 清除", width=70, corner_radius=8,
                                       fg_color="#6a5a5a", hover_color="#8a6a6a",
                                       command=self.clear_data)
        self.btn_clear.pack(side="left", padx=2, pady=6)

        self.topmost_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(ctrl_row1, text="📌 置頂", variable=self.topmost_var,
                        command=self.toggle_topmost, corner_radius=5,
                        checkbox_width=18, checkbox_height=18).pack(side="left", padx=(8, 4), pady=6)
        self.dev_var = tk.BooleanVar(value=False)
        # 發布版隱藏開發者選項按鈕 (dev_var 保留供後續程式碼安全存取,但沒有 UI 也永不觸發)
        if not RELEASE_BUILD:
            ctk.CTkCheckBox(ctrl_row1, text="🛠 開發者", variable=self.dev_var,
                            command=self.toggle_dev_mode, corner_radius=5,
                            checkbox_width=18, checkbox_height=18).pack(side="left", padx=4, pady=6)

        # ----------------------------------------------------
        # 3. 控制列 Row 2: 標籤高亮 + 視窗透明度
        # ----------------------------------------------------
        self.ctrl_row2 = ctk.CTkFrame(root, corner_radius=0)
        self.ctrl_row2.pack(fill="x", padx=10, pady=(0, 3))
        ctrl_row2 = self.ctrl_row2  # local alias 保留現有引用

        ctk.CTkLabel(ctrl_row2, text="🎯 高亮:").pack(side="left", padx=(8, 3), pady=6)
        self.highlight_var = tk.StringVar(value="無")
        self.highlight_combo = ctk.CTkComboBox(ctrl_row2, values=HIGHLIGHT_OPTIONS,
                                               variable=self.highlight_var, state="readonly",
                                               width=95, corner_radius=8)
        self.highlight_combo.pack(side="left", padx=(0, 8), pady=6)

        ctk.CTkLabel(ctrl_row2, text="🪟 透明度:").pack(side="left", padx=(4, 3), pady=6)
        self.alpha_slider = ctk.CTkSlider(ctrl_row2, from_=30, to=100, number_of_steps=70,
                                          width=140, command=self.set_alpha)
        self.alpha_slider.set(100)
        self.alpha_slider.pack(side="left", padx=(0, 4), pady=6)
        self.lbl_alpha = ctk.CTkLabel(ctrl_row2, text="100%", width=40)
        self.lbl_alpha.pack(side="left", padx=(0, 8), pady=6)

        # ----------------------------------------------------
        # 3.5 控制列 Row 3: 計時器 (分/秒輸入 + 開始 + 倒數顯示)
        # ----------------------------------------------------
        self.ctrl_row3 = ctk.CTkFrame(root, corner_radius=0)
        self.ctrl_row3.pack(fill="x", padx=10, pady=(0, 3))
        ctrl_row3 = self.ctrl_row3  # local alias 保留現有引用

        ctk.CTkLabel(ctrl_row3, text="⏱ 計時:").pack(side="left", padx=(8, 3), pady=6)
        self.timer_min_var = tk.StringVar(value="1")
        self.timer_sec_var = tk.StringVar(value="0")
        ctk.CTkEntry(ctrl_row3, textvariable=self.timer_min_var, width=45,
                     justify="center", corner_radius=6).pack(side="left", padx=(0, 2), pady=6)
        ctk.CTkLabel(ctrl_row3, text="分").pack(side="left", padx=(0, 4), pady=6)
        ctk.CTkEntry(ctrl_row3, textvariable=self.timer_sec_var, width=45,
                     justify="center", corner_radius=6).pack(side="left", padx=(0, 2), pady=6)
        ctk.CTkLabel(ctrl_row3, text="秒").pack(side="left", padx=(0, 8), pady=6)

        self.btn_timer = ctk.CTkButton(ctrl_row3, text="⏱ 計時開始", width=95,
                                       corner_radius=8,
                                       fg_color="#5a8a5a", hover_color="#6aa06a",
                                       command=self.start_timer)
        self.btn_timer.pack(side="left", padx=(0, 8), pady=6)
        # 記住預設(閒置)樣式,計時停止後還原用
        self._btn_timer_idle_fg = self.btn_timer.cget("fg_color")
        self._btn_timer_idle_hover = self.btn_timer.cget("hover_color")

        self.lbl_timer_remaining = ctk.CTkLabel(ctrl_row3, text="",
                                                 font=(FONT_MONO, 13, "bold"),
                                                 text_color="#88ccff")
        self.lbl_timer_remaining.pack(side="left", padx=(0, 8), pady=6)

        # ----------------------------------------------------
        # 0. 頂部狀態列 (快捷按鈕:Discord / 免責聲明 靠左, 設定 靠右)
        #    放最上方,side="top" + before=ctrl_row1 保證它永遠是第一個元件
        #    網路檢測按鈕已搬到「設定」內,Npcap 狀態不再直接顯示於此
        # ----------------------------------------------------
        self.status_bar = ctk.CTkFrame(root, corner_radius=0, height=28, fg_color="#1a1a1a")
        self.status_bar.pack(side="top", fill="x", padx=10, pady=(8, 0),
                              before=self.ctrl_row1)

        # 左側:Discord + 免責聲明 (pack 順序決定顯示順序; side=left 是從左往右堆)
        ctk.CTkButton(self.status_bar, text="💬 Discord",
                      width=90, height=22, corner_radius=6,
                      fg_color="#5865f2", hover_color="#4752c4",
                      font=(FONT_UI, 10),
                      command=self.open_discord).pack(side="left", padx=(8, 4), pady=2)
        ctk.CTkButton(self.status_bar, text="⚠ 免責聲明",
                      width=90, height=22, corner_radius=6,
                      fg_color="#4a4a4a", hover_color="#6a6a6a",
                      font=(FONT_UI, 10),
                      command=self.show_disclaimer).pack(side="left", padx=4, pady=2)

        # 右側:設定
        ctk.CTkButton(self.status_bar, text="⚙ 設定",
                      width=70, height=22, corner_radius=6,
                      fg_color="#4a4a4a", hover_color="#6a6a6a",
                      font=(FONT_UI, 10),
                      command=self.show_settings).pack(side="right", padx=(4, 8), pady=2)

        # ----------------------------------------------------
        # 5. 即時攻擊事件日誌 + 5.5 技能傷害排行
        #    抽成 _build_*_pane(parent) 方法,dock/popout 兩情境共用建立邏輯
        #    起始時 parent = root,若 popout_* 為 True,__init__ 尾端會 pop 出去
        # ----------------------------------------------------
        self._build_log_pane(root)
        self._build_skill_pane(root)

        # ----------------------------------------------------
        # 5.6 治癒事件日誌 (可折疊,packing 交給 _apply_tracking_mode)
        # ----------------------------------------------------
        self.heal_log_pane = ctk.CTkFrame(root, corner_radius=0)

        self.heal_collapsed = False
        heal_header = ctk.CTkFrame(self.heal_log_pane, fg_color="transparent")
        heal_header.pack(fill="x", padx=6, pady=(6, 0))
        self.btn_heal_toggle = ctk.CTkButton(
            heal_header,
            text="▼ 治癒事件日誌",
            font=(FONT_UI, 11, "bold"),
            fg_color="transparent",
            hover_color="#2a2a2a",
            anchor="w",
            corner_radius=6,
            height=26,
            command=self.toggle_heal_collapse,
        )
        self.btn_heal_toggle.pack(side="left", fill="x", expand=True)

        self.heal_log_area = ctk.CTkTextbox(self.heal_log_pane, wrap="word",
                                             font=(FONT_MONO, 13),
                                             corner_radius=0)
        self.heal_log_area.pack(fill="both", expand=True, padx=6, pady=6)
        # 治療自己 (綠) / 治療他人 (藍) 顏色標籤
        self.heal_log_area._textbox.tag_config("heal_self", foreground="#4dd471")
        self.heal_log_area._textbox.tag_config("heal_ally", foreground="#88ccff")
        # 尚未識別本地玩家 ID 前的中性配色 (黃),用來標示「無法判定自己/他人」的事件
        self.heal_log_area._textbox.tag_config("heal_unknown", foreground="#ffcc4d")
        self.heal_log_area.configure(state="disabled")

        # ----------------------------------------------------
        # 6. 開發者 LOG (勾選開發者才顯示)
        # ----------------------------------------------------
        self.dev_pane = ctk.CTkFrame(root, corner_radius=0)
        ctk.CTkLabel(self.dev_pane, text="🛠 開發者 Flag 診斷",
                     font=(FONT_UI, 11, "bold")).pack(anchor="w", padx=10, pady=(6, 0))
        self.dev_log_area = ctk.CTkTextbox(self.dev_pane, wrap="word", font=(FONT_MONO, 12),
                                           corner_radius=0, height=140)
        self.dev_log_area.pack(fill="both", expand=True, padx=6, pady=6)
        self.dev_log_area.configure(state="disabled")

        # 監聽視窗 resize,拖動期間跳過技能排行更新,結束後補刷一次
        root.bind("<Configure>", self._on_root_configure)

        # 若 popout 設定為 True,把對應 pane 移到獨立 Toplevel
        # (順序:先 popout 再 apply_tracking_mode,避免主視窗還 pack 那些 pane)
        # 啟動時主視窗高度已在 geometry() 呼叫時預先扣減,這裡只做 popout 動作
        # 不再走 delta (winfo_height 此時未 realize 會回 1,delta 後會被夾到 200)
        if self.popout_log:
            self._popout_log()
        if self.popout_skill:
            self._popout_skill()

        # 依 track_damage / track_heal 旗標,把 banner + pane 一次性 pack 到位
        self._apply_tracking_mode()

        # 開啟後自動在背景掃描一次收包網卡,結果會設到 self.chosen_iface
        # 500ms 延遲讓主視窗先完全渲染出來
        self.root.after(500, self._auto_detect_iface_on_startup)

    # ================================================
    # 事件處理
    # ================================================
    def _on_root_configure(self, event):
        """視窗 resize 事件:拖動中把 _is_resizing 設 True,結束後 150ms 補一次刷新。
        只認 root 自己的 Configure,忽略子元件的冒泡事件。
        """
        if event.widget is not self.root:
            return
        self._is_resizing = True
        if self._resize_after_id is not None:
            try:
                self.root.after_cancel(self._resize_after_id)
            except Exception:
                pass
        self._resize_after_id = self.root.after(150, self._end_resize)

    def _end_resize(self):
        self._is_resizing = False
        self._resize_after_id = None
        # 拖動期間累加的傷害,resize 結束後補一次完整刷新
        self.update_skill_ranking()

    # ================================================
    # 追蹤模式:banner + pane 的統一 pack 管理
    # ================================================
    # ================================================
    # Pane builders (可 pack 於 root 或 Toplevel,支援 dock ↔ popout 切換)
    # ================================================
    def _build_log_pane(self, parent):
        """建立即時攻擊事件日誌 pane。設定 self.log_pane / self.log_area /
        self.btn_log_toggle。呼叫方負責 pack self.log_pane 到適當位置。
        """
        self.log_pane = ctk.CTkFrame(parent, corner_radius=0)
        self.btn_log_toggle = ctk.CTkButton(
            self.log_pane,
            text=("▶ 即時攻擊事件日誌 (已折疊)" if self.log_collapsed
                  else "▼ 即時攻擊事件日誌"),
            font=(FONT_UI, 11, "bold"),
            fg_color="transparent",
            hover_color="#2a2a2a",
            anchor="w",
            corner_radius=6,
            height=26,
            command=self.toggle_log_collapse,
        )
        self.btn_log_toggle.pack(fill="x", padx=6, pady=(6, 0))
        self.log_area = ctk.CTkTextbox(self.log_pane, wrap="word",
                                        font=(FONT_MONO, 13), corner_radius=0)
        # 折疊狀態下不 pack log_area,由 toggle_log_collapse 處理
        if not self.log_collapsed:
            self.log_area.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_area._textbox.tag_config("highlight", foreground="#ff4d4d")
        self.log_area._textbox.configure(tabs=self._scaled_tab_stops())
        self.log_area.configure(state="disabled")
        return self.log_pane

    def _build_skill_pane(self, parent):
        """建立技能傷害排行 pane。設定 self.skill_pane / self.btn_skill_toggle /
        self.skill_scroll。self.skill_rows 需被清空並重建 (資料還在 skill_damage 內,
        呼叫 update_skill_ranking 即可補回)。
        """
        self.skill_pane = ctk.CTkFrame(parent, corner_radius=0)
        skill_header = ctk.CTkFrame(self.skill_pane, fg_color="transparent")
        skill_header.pack(fill="x", padx=6, pady=(6, 0))
        self.btn_skill_toggle = ctk.CTkButton(
            skill_header,
            text=("▶ 技能傷害排行 (已折疊)" if self.skill_collapsed
                  else "▼ 技能傷害排行"),
            font=(FONT_UI, 11, "bold"),
            fg_color="transparent",
            hover_color="#2a2a2a",
            anchor="w",
            corner_radius=6,
            height=26,
            command=self.toggle_skill_collapse,
        )
        self.btn_skill_toggle.pack(side="left", fill="x", expand=True)
        # merge_var 已在 __init__ 建立,重建時 checkbox 綁回同一個 var 保留勾選狀態
        ctk.CTkCheckBox(
            skill_header, text="合併同技能", variable=self.merge_var,
            command=self.update_skill_ranking,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 11),
        ).pack(side="right", padx=(6, 4))
        self.skill_scroll = ctk.CTkScrollableFrame(self.skill_pane,
                                                     corner_radius=0,
                                                     fg_color="#242424")
        if not self.skill_collapsed:
            self.skill_scroll.pack(fill="both", expand=True, padx=6, pady=6)
        self.skill_pane.bind("<Enter>", self._skill_area_enter)
        self.skill_pane.bind("<Leave>", self._skill_area_leave)
        # 舊 row widgets 已隨舊 pane 銷毀,清空 dict;update_skill_ranking 會依
        # skill_damage 重建列
        self.skill_rows = {}
        return self.skill_pane

    # ================================================
    # Popout / dock:攻擊日誌 & 技能排行的獨立視窗切換
    # ================================================
    def _dump_log_content(self):
        """撈出 log_area 的純文字內容 (tags 不會保留)。"""
        self.log_area.configure(state="normal")
        s = self.log_area.get("1.0", "end-1c")
        self.log_area.configure(state="disabled")
        return s

    def _restore_log_content(self, s):
        if not s:
            return
        self.log_area.configure(state="normal")
        self.log_area.insert("1.0", s)
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def _popout_log(self):
        """把 log_pane 從 root 移到獨立 CTkToplevel。"""
        if self._log_popout_win is not None:
            return
        old_content = self._dump_log_content()
        if hasattr(self, "log_pane") and self.log_pane:
            self.log_pane.destroy()
        win = ctk.CTkToplevel(self.root)
        win.title("MM Scribe — 即時攻擊事件日誌")
        win.geometry("500x400")
        win.minsize(300, 200)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_popout_closed("log"))
        self._log_popout_win = win
        self._build_log_pane(win)
        self.log_pane.pack(fill="both", expand=True, padx=6, pady=6)
        self._restore_log_content(old_content)
        # 主視窗如果目前是置頂,新開的 popout 也要一起置頂
        self._apply_topmost_all()

    def _dock_log(self):
        """把 log_pane 從 Toplevel 收回 root。"""
        old_content = self._dump_log_content() if hasattr(self, "log_area") else ""
        if hasattr(self, "log_pane") and self.log_pane:
            self.log_pane.destroy()
        if self._log_popout_win is not None:
            try:
                self._log_popout_win.destroy()
            except Exception:
                pass
            self._log_popout_win = None
        self._build_log_pane(self.root)
        self._restore_log_content(old_content)

    def _popout_skill(self):
        """把 skill_pane 從 root 移到獨立 CTkToplevel。
        skill_rows 資料 (skill_damage 等) 都在 self 層,重建 pane 後
        呼叫 update_skill_ranking 即可補回顯示。
        """
        if self._skill_popout_win is not None:
            return
        if hasattr(self, "skill_pane") and self.skill_pane:
            self.skill_pane.destroy()
        win = ctk.CTkToplevel(self.root)
        win.title("MM Scribe — 技能傷害排行")
        win.geometry("500x400")
        win.minsize(300, 200)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_popout_closed("skill"))
        self._skill_popout_win = win
        self._build_skill_pane(win)
        self.skill_pane.pack(fill="both", expand=True, padx=6, pady=6)
        self.update_skill_ranking()  # 重建 row widgets
        # 主視窗如果目前是置頂,新開的 popout 也要一起置頂
        self._apply_topmost_all()

    def _dock_skill(self):
        if hasattr(self, "skill_pane") and self.skill_pane:
            self.skill_pane.destroy()
        if self._skill_popout_win is not None:
            try:
                self._skill_popout_win.destroy()
            except Exception:
                pass
            self._skill_popout_win = None
        self._build_skill_pane(self.root)
        self.update_skill_ranking()

    def _on_popout_closed(self, kind):
        """使用者點 Toplevel 的 X → 對應 checkbox 取消勾選 → dock 回主視窗。
        dock 回來會增加主視窗高度,和 checkbox 走同一條 delta 調整。
        """
        if kind == "log":
            self.popout_log = False
            self.popout_log_var.set(False)
            self.settings["popout_log"] = False
            save_settings(self.settings)
            self._dock_log()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
            self._apply_tracking_mode()
        elif kind == "skill":
            self.popout_skill = False
            self.popout_skill_var.set(False)
            self.settings["popout_skill"] = False
            save_settings(self.settings)
            self._dock_skill()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
            self._apply_tracking_mode()

    # popout 出去時主視窗少一區,縮短高度;dock 回來時補回高度。
    # 200px 是「一個中段 pane 的合理視覺占比」估值,scale 會乘上去。
    _POPOUT_HEIGHT_ESTIMATE = 200

    def _adjust_root_height_delta(self, delta_px):
        """調整主視窗高度 delta 像素;寬度保持不變。
        考慮 font_scale:winfo_height 回實際像素,delta 也乘 scale 轉實際像素,
        傳給 geometry 時再除回 scale (因為 CTk 的 geometry 會再乘一次)。
        floor 340 邏輯像素 * scale = 實際像素,保證兩個 popout 時計時器仍看得到。
        """
        scale = self.font_scale
        curw = self.root.winfo_width()
        curh = self.root.winfo_height()
        floor_real = int(340 * scale)
        new_h = max(floor_real, curh + int(delta_px * scale))
        self.root.geometry(f"{int(curw / scale)}x{int(new_h / scale)}")

    def _on_popout_log_change(self):
        new_state = self.popout_log_var.get()
        if new_state == self.popout_log:
            return
        self.popout_log = new_state
        self.settings["popout_log"] = new_state
        save_settings(self.settings)
        if new_state:
            self._popout_log()
            self._adjust_root_height_delta(-self._POPOUT_HEIGHT_ESTIMATE)
        else:
            self._dock_log()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
        self._apply_tracking_mode()

    def _on_popout_skill_change(self):
        new_state = self.popout_skill_var.get()
        if new_state == self.popout_skill:
            return
        self.popout_skill = new_state
        self.settings["popout_skill"] = new_state
        save_settings(self.settings)
        if new_state:
            self._popout_skill()
            self._adjust_root_height_delta(-self._POPOUT_HEIGHT_ESTIMATE)
        else:
            self._dock_skill()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
        self._apply_tracking_mode()

    def _apply_tracking_mode(self):
        """依 self.track_damage / self.track_heal 重新佈局所有可切換的 banner / pane。
        - status_bar 位於視窗最上方 (side=top),不可被壓縮
        - Banner (dmg_banner, heal_banner) 用 `before=ctrl_row1` 插入到控制列上方
        - 中段 pane (log_pane, skill_pane, heal_log_pane, dev_pane) 全部 forget 後
          按順序 pack 於末端 (list 尾端 = 視覺上位於控制列下方)
        - dev_pane 一律 pack 在最後,讓開發者面板始終位於中段的最下方
        """
        # === Banners ===
        self.dmg_banner.pack_forget()
        self.heal_banner.pack_forget()
        if self.track_damage:
            self.dmg_banner.pack(fill="x", padx=10, pady=(6, 6),
                                  before=self.ctrl_row1)
        if self.track_heal:
            top_pad = 0 if self.track_damage else 6
            self.heal_banner.pack(fill="x", padx=10, pady=(top_pad, 6),
                                   before=self.ctrl_row1)

        # === 中段 panes ===
        # popout 中的 pane 已 pack 在自己的 Toplevel,主視窗這邊要跳過 (不能對它
        # 呼叫 pack_forget,因為 Toplevel 的 pack 不是 root 管的)
        if not self.popout_log:
            self.log_pane.pack_forget()
        if not self.popout_skill:
            self.skill_pane.pack_forget()
        self.heal_log_pane.pack_forget()
        if getattr(self, "is_dev_mode", False):
            self.dev_pane.pack_forget()

        if self.track_damage:
            if not self.popout_log:
                self.log_pane.pack(fill="both", expand=True, padx=10, pady=(3, 3))
            if not self.popout_skill:
                self.skill_pane.pack(fill="both", expand=True, padx=10, pady=(0, 3))
        if self.track_heal:
            self.heal_log_pane.pack(fill="both", expand=True, padx=10, pady=(0, 3))
        if getattr(self, "is_dev_mode", False):
            self.dev_pane.pack(fill="both", expand=False, padx=10, pady=(0, 6))

        # 依當前佈局重算 minsize,確保 status_bar 不會被 log/skill/heal 這些
        # expand=True 的面板擠掉。用 after(0) 讓 Tk 完成本次 pack 再量高度
        self.root.after(0, self._refresh_minsize)

    def _refresh_minsize(self):
        """依「當前顯示的 banner + 3 條控制列 + status_bar」總高度,
        算出最小視窗高度並套用到 wm_minsize。
        - winfo_reqheight 回傳實際像素 (含 CTk scaling),故不用再乘 font_scale
        - 用 wm_minsize 而非 CTk 的 minsize 以避免二次縮放
        """
        self.root.update_idletasks()
        parts = [self.ctrl_row1, self.ctrl_row2, self.ctrl_row3, self.status_bar]
        if self.track_damage:
            parts.append(self.dmg_banner)
        if self.track_heal:
            parts.append(self.heal_banner)
        req_h = sum(w.winfo_reqheight() for w in parts)
        # 再留 80px 給日誌區最小可視高度 + padding,不然 status_bar 剛好貼滿反而擠日誌
        min_h = req_h + 80
        self.root.wm_minsize(400, int(min_h))

    def _on_track_damage_change(self):
        self.track_damage = self.track_damage_var.get()
        self.settings["track_damage"] = self.track_damage
        save_settings(self.settings)
        self._apply_tracking_mode()

    def _on_track_heal_change(self):
        self.track_heal = self.track_heal_var.get()
        self.settings["track_heal"] = self.track_heal
        save_settings(self.settings)
        self._apply_tracking_mode()

    def toggle_heal_collapse(self):
        """折疊/展開治癒事件日誌。折疊時 heal_log_area 隱藏但持續寫入。"""
        if self.heal_collapsed:
            self.heal_log_area.pack(fill="both", expand=True, padx=6, pady=6)
            self.heal_log_pane.pack_configure(expand=True, fill="both")
            self.btn_heal_toggle.configure(text="▼ 治癒事件日誌")
            self.heal_collapsed = False
        else:
            self.heal_log_area.pack_forget()
            self.heal_log_pane.pack_configure(expand=False, fill="x")
            self.btn_heal_toggle.configure(text="▶ 治癒事件日誌 (已折疊)")
            self.heal_collapsed = True

    def open_discord(self):
        """開啟預設瀏覽器前往 Discord 邀請連結。"""
        try:
            webbrowser.open(DISCORD_INVITE_URL)
        except Exception as e:
            self.log(f"❌ 無法開啟 Discord 連結: {e}")

    def show_network_check(self):
        """建立網路環境檢測覆蓋層,列出各項診斷結果讓使用者判斷抓不到封包的原因。"""
        if getattr(self, "_netcheck_overlay", None) is not None:
            return

        overlay = ctk.CTkFrame(self.root, fg_color="#0a0a0a", corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._netcheck_overlay = overlay

        # 標題 + 按鈕列
        header = ctk.CTkFrame(overlay, fg_color="transparent", height=44)
        header.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(header, text="🌐 網路環境檢測",
                     font=(FONT_UI, 16, "bold"),
                     text_color="#4dccff").pack(side="left", padx=6)
        ctk.CTkButton(header, text="✕", width=32, height=32, corner_radius=16,
                      fg_color="#3a3a3a", hover_color="#c94a4a",
                      font=(FONT_MONO, 14, "bold"),
                      command=self.hide_network_check).pack(side="right", padx=6)
        ctk.CTkButton(header, text="🔄 重新檢測", width=100, height=32,
                      corner_radius=8,
                      command=lambda: self._run_network_checks()).pack(side="right", padx=6)
        self._btn_scan_iface = ctk.CTkButton(
            header, text="🔍 掃描收包網卡", width=140, height=32, corner_radius=8,
            command=self._start_iface_scan,
        )
        self._btn_scan_iface.pack(side="right", padx=6)

        # 結果顯示區
        self._netcheck_result = ctk.CTkTextbox(overlay, wrap="word",
                                                font=(FONT_MONO, 11),
                                                corner_radius=0,
                                                fg_color="#1a1a1a")
        self._netcheck_result.pack(fill="both", expand=True, padx=16, pady=12)

        # 狀態顏色
        self._netcheck_result._textbox.tag_config("tag_ok", foreground="#4dd471")
        self._netcheck_result._textbox.tag_config("tag_warn", foreground="#ffcc4d")
        self._netcheck_result._textbox.tag_config("tag_fail", foreground="#ff5555")
        self._netcheck_result._textbox.tag_config("tag_info", foreground="#4dccff")
        self._netcheck_result._textbox.tag_config("tag_active", foreground="#66ffa0")
        self._netcheck_result._textbox.tag_config("tag_header",
                                                   foreground="#ffffff",
                                                   font=(FONT_UI, 12, "bold"))

        self._run_network_checks()

    def hide_network_check(self):
        overlay = getattr(self, "_netcheck_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self._netcheck_overlay = None
        self._netcheck_result = None

    def _append_netcheck(self, status, title, *details):
        """在檢測結果區加一段訊息 (執行在 main thread)。"""
        area = getattr(self, "_netcheck_result", None)
        if area is None:
            return
        icon = {"ok": "✓", "warn": "⚠", "fail": "✗",
                "info": "ℹ", "active": "⭐"}.get(status, "•")
        area.configure(state="normal")
        area._textbox.insert("end", f"[{icon}] {title}\n", f"tag_{status}")
        for d in details:
            area._textbox.insert("end", f"    {d}\n")
        area._textbox.insert("end", "\n")
        area._textbox.see("end")
        area.configure(state="disabled")

    # ---- 收包網卡掃描:核心邏輯,供啟動時自動偵測與手動按鈕共用 ----
    def _scan_ifaces_for_traffic(self, per_iface_timeout, on_progress, on_done):
        """對每張有 IPv4 的介面短暫 sniff,回報收到多少目標封包。
        - per_iface_timeout: 每張介面掃多久 (秒)
        - on_progress(status, title, *details): 每張介面掃完 & 開始時的即時回報
        - on_done(best_iface_dict or None, hits_list): 全部掃完時的最終回呼
        本函式會在自己的背景 thread 執行,呼叫方不需自己開 thread。
        """
        def _worker():
            try:
                from scapy.all import sniff as _sniff

                def _extract_ipv4(raw):
                    out = []
                    if isinstance(raw, dict):
                        for iplist in raw.values():
                            if isinstance(iplist, (list, tuple)):
                                out.extend(iplist)
                    elif isinstance(raw, (list, tuple)):
                        out = list(raw)
                    return [str(ip) for ip in out
                            if ":" not in str(ip)
                            and str(ip) != "0.0.0.0"
                            and not str(ip).startswith("169.254.")]

                try:
                    raw_ifs = list_network_ifaces()
                except Exception as e:
                    self.root.after(0, lambda err=e: on_progress(
                        "warn", f"無法列出介面: {err}"))
                    self.root.after(0, lambda: on_done(None, []))
                    return

                ifs = [i for i in raw_ifs if _extract_ipv4(i.get("ips"))]
                ifs = [i for i in ifs if not _is_never_game_traffic(i.get("name"))]
                if not ifs:
                    self.root.after(0, lambda: on_progress(
                        "warn", "沒有可掃描的介面 (無介面有有效 IPv4)"))
                    self.root.after(0, lambda: on_done(None, []))
                    return

                # 預設路由那張排最前面:絕大多數情況遊戲就走這張,先掃到就能提早收工
                preferred = default_route_iface()
                ifs.sort(key=lambda i: i.get("name") != preferred)

                total_time = len(ifs) * per_iface_timeout
                self.root.after(0, lambda: on_progress(
                    "info", f"開始掃描 {len(ifs)} 張介面,每張測 {per_iface_timeout} 秒 (最多約 {total_time} 秒)"))

                hits = []
                for iface in ifs:
                    name = str(iface.get("description") or iface.get("name") or "?")
                    iface_key = iface.get("name")
                    try:
                        pkts = _sniff(iface=iface_key,
                                      filter=f"ip net {IP_FILTER_NET} and tcp",
                                      timeout=per_iface_timeout, store=True)
                        count = len(pkts)
                    except Exception as e:
                        self.root.after(0, lambda n=name, err=e: on_progress(
                            "warn", f"{n}", f"sniff 失敗: {err}"))
                        continue

                    if count > 0:
                        hits.append((iface, count, name))
                        self.root.after(0, lambda n=name, c=count: on_progress(
                            "ok", f"✓ {n}", f"收到 {c} 個目標封包"))
                        # 預設路由那張已經收到流量就不必再試其他張,省下數十秒
                        # (macOS 上虛擬介面動輒十幾張,全掃完使用者早就等到不耐煩)
                        if iface_key == preferred:
                            break
                    else:
                        self.root.after(0, lambda n=name: on_progress(
                            "info", f"  {n}", "沒收到"))

                if not hits:
                    self.root.after(0, lambda: on_done(None, []))
                else:
                    best = max(hits, key=lambda x: x[1])
                    self.root.after(0, lambda b=best: on_done(b[0], hits))
            except Exception as e:
                self.root.after(0, lambda err=e: on_progress(
                    "warn", f"掃描發生錯誤: {err}"))
                self.root.after(0, lambda: on_done(None, []))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_chosen_iface(self, iface_dict):
        """把掃描結果套用到 self.chosen_iface,之後 sniff() 就會綁這張卡。"""
        if iface_dict is None:
            self.chosen_iface = None
            return
        self.chosen_iface = iface_dict.get("name")

    def _auto_detect_iface_on_startup(self):
        """程式開啟時的自動偵測 (背景執行,不阻擋 UI)。
        結果會設到 self.chosen_iface,後續按「開始」時 sniff 會用這張卡。
        """
        self.log("=== 自動偵測收包網卡中... (背景執行,可正常操作) ===")

        def on_progress(status, title, *details):
            # 僅把有意義的訊息推到主日誌 (略過每張介面的細節,避免刷屏)
            if status in ("ok", "warn"):
                self.log(f"  {title}")

        def on_done(best_iface, hits):
            if best_iface is None:
                self.log("=== 未偵測到目標網段封包,將使用 scapy 預設介面 ===")
                self.log("    若監控後仍抓不到,請按「網路檢測 → 掃描收包網卡」重試")
            else:
                self._apply_chosen_iface(best_iface)
                name = str(best_iface.get("description") or best_iface.get("name") or "?")
                self.log(f"=== 已自動選定收包網卡:{name} ===")

        self._scan_ifaces_for_traffic(
            per_iface_timeout=2,
            on_progress=on_progress,
            on_done=on_done,
        )

    def _start_iface_scan(self):
        """網路檢測畫面的「掃描收包網卡」按鈕:掃描並套用結果。"""
        if getattr(self, "_iface_scan_running", False):
            return
        self._iface_scan_running = True
        self._btn_scan_iface.configure(state="disabled", text="🔍 掃描中...")

        def on_progress(status, title, *details):
            self._append_netcheck(status, title, *details)

        def on_done(best_iface, hits):
            if best_iface is None:
                self._append_netcheck(
                    "warn", "掃描結束:所有介面都沒收到目標封包",
                    "可能原因:",
                    "  1. 遊戲未連線 / 未啟動",
                    "  2. 目標伺服器不在監控範圍內",
                    "  3. 沒有以系統管理員身分執行 → sniff 靜默失敗",
                    "  4. 防毒/防火牆阻擋")
            else:
                self._apply_chosen_iface(best_iface)
                name = str(best_iface.get("description") or best_iface.get("name") or "?")
                count = max(h[1] for h in hits)
                self._append_netcheck(
                    "active", f"掃描結束:已套用「{name}」為抓包網卡",
                    f"收到 {count} 個目標封包 (最多)",
                    "下次按「開始」時會綁這張卡進行 sniff")
            self._iface_scan_running = False
            try:
                self._btn_scan_iface.configure(state="normal", text="🔍 掃描收包網卡")
            except Exception:
                pass

        self._scan_ifaces_for_traffic(
            per_iface_timeout=2,
            on_progress=on_progress,
            on_done=on_done,
        )

    def _run_network_checks(self):
        """執行所有網路環境檢測項目並輸出結果。"""
        area = self._netcheck_result
        area.configure(state="normal")
        area.delete("1.0", "end")

        def write(status, title, *details):
            icon = {"ok": "✓", "warn": "⚠", "fail": "✗", "info": "ℹ", "active": "⭐"}.get(status, "•")
            area._textbox.insert("end", f"[{icon}] {title}\n", f"tag_{status}")
            for d in details:
                area._textbox.insert("end", f"    {d}\n")
            area._textbox.insert("end", "\n")

        def section(title):
            area._textbox.insert("end", f"── {title} ──\n\n", "tag_header")

        # === 1. 抓包權限 ===
        section("1. 執行權限")
        perm_ok, perm_detail = check_capture_permission()
        if perm_ok:
            write("ok", "已具備抓包權限", perm_detail)
        else:
            write("fail", "權限不足",
                  "★ 這是抓不到封包最常見的原因 ★",
                  perm_detail)

        # === 2. 抓包驅動 ===
        driver_name = "Npcap 驅動" if IS_WINDOWS else "libpcap / BPF"
        section(f"2. {driver_name}")
        backend_ok, backend_hint = check_capture_backend()
        if backend_ok:
            write("ok", f"{driver_name} 已就緒",
                  *([] if IS_WINDOWS else ["libpcap 為 macOS 內建,無須另外安裝"]))
        else:
            write("fail", f"未偵測到 {driver_name}", backend_hint)

        # ── 共用工具 ──
        def extract_ipv4_list(raw):
            """相容 scapy 各版本的 .ips 型別 → 回傳 IPv4 字串列表。"""
            out = []
            if isinstance(raw, dict):
                for iplist in raw.values():
                    if isinstance(iplist, (list, tuple)):
                        out.extend(iplist)
                    elif iplist:
                        out.append(iplist)
            elif isinstance(raw, (list, tuple)):
                out = list(raw)
            return [str(ip) for ip in out if ":" not in str(ip)]

        def has_usable_ipv4(iface):
            """有沒有真正能用的 IPv4:非空、非 0.0.0.0、非 APIPA (169.254.x.x)。"""
            for ip in extract_ipv4_list(iface.get("ips")):
                if ip and ip != "0.0.0.0" and not ip.startswith("169.254."):
                    return True
            return False

        # ── 先偵測 scapy 目前用哪張卡 (兩處都會用到) ──
        active_iface_str = ""
        active_guid = ""
        active_name = ""
        try:
            from scapy.config import conf
            active_iface = conf.iface
            active_iface_str = str(active_iface)
            v = getattr(active_iface, "guid", None)
            if v:
                active_guid = str(v)
            for attr in ("description", "network_name", "name"):
                v = getattr(active_iface, attr, None)
                if v and not active_name:
                    active_name = str(v)
        except Exception:
            pass

        def is_active_iface(iface):
            guid = str(iface.get("guid") or "")
            name = str(iface.get("name") or "")
            desc = str(iface.get("description") or "")
            if guid and (guid in active_iface_str or guid == active_guid):
                return True
            if name and (name == active_iface_str or name == active_name):
                return True
            if desc and desc == active_name:
                return True
            return False

        # === 3. 網路介面 ===
        section("3. 網路介面偵測 (已過濾無 IPv4 的介面)")
        try:
            ifs = list_network_ifaces()
            if not ifs:
                write("warn", "沒有找到任何網路介面")
            else:
                usable = [i for i in ifs if has_usable_ipv4(i)]
                skipped = len(ifs) - len(usable)
                write("info",
                      f"共 {len(ifs)} 個介面,顯示 {len(usable)} 個有 IPv4 的 (排除 {skipped} 個)")
                for i in usable:
                    name = str(i.get("name", "?"))
                    desc = str(i.get("description", ""))
                    ipv4 = extract_ipv4_list(i.get("ips"))
                    ip_str = ", ".join(ipv4) if ipv4 else "(無 IPv4)"

                    # macOS 的 description 就是 BSD 名稱,所以連 name 一起比對:
                    # utun=VPN, bridge/vmenet=虛擬機橋接, awdl/llw=AirDrop, feth/gif/stf=虛擬
                    lower_desc = (desc + " " + name).lower()
                    tag = ""
                    if any(kw in lower_desc for kw in
                           ["virtual", "vmware", "vbox", "hyper-v", "tap", "tun",
                            "wireguard", "wsl", "loopback",
                            "utun", "bridge", "vmenet", "awdl", "llw", "feth",
                            "gif", "stf", "anpi", "lo0"]):
                        tag = " ⚠虛擬/VPN"

                    if is_active_iface(i):
                        write("active", f"{desc or name}{tag}  ← scapy 目前用這張",
                              f"IPv4: {ip_str}",
                              f"裝置名稱: {name}")
                    else:
                        write("info", f"{desc or name}{tag}",
                              f"IPv4: {ip_str}")
        except Exception as e:
            write("warn", f"無法列出介面: {type(e).__name__}: {e}")

        # === 4. scapy 目前綁定的介面 ===
        section("4. scapy 目前綁定介面")
        try:
            friendly = active_name
            desc = ""
            ipv4 = extract_ipv4_list(getattr(active_iface, "ips", None)) if active_iface_str else []

            # 沒抓到就從介面清單反查
            if active_iface_str and (not friendly or not ipv4):
                for iface in list_network_ifaces():
                    if is_active_iface(iface):
                        if not friendly:
                            friendly = str(iface.get("description") or iface.get("name") or "")
                        if not desc:
                            desc = str(iface.get("description") or "")
                        if not ipv4:
                            ipv4 = extract_ipv4_list(iface.get("ips"))
                        break

            if not active_iface_str:
                write("warn", "無法取得 scapy 預設介面")
            else:
                details = []
                if friendly:
                    details.append(f"友善名稱: {friendly}")
                if desc and desc != friendly:
                    details.append(f"描述: {desc}")
                if ipv4:
                    details.append(f"IPv4: {', '.join(ipv4)}")
                details.append(f"裝置路徑: {active_iface_str}")
                details.append("---")
                details.append("sniff() 若沒特別指定 iface,就是抓這張卡")
                details.append("若這張卡不是你連遊戲用的那張,就永遠抓不到")
                write("active", "scapy 現在綁的網卡:", *details)
        except Exception as e:
            write("warn", f"取得預設介面失敗: {type(e).__name__}: {e}")

        area.configure(state="disabled")

    def show_disclaimer(self):
        """建立一個覆蓋整個視窗的免責聲明畫面。已顯示時不重複建立。"""
        if getattr(self, "_disclaimer_overlay", None) is not None:
            return

        overlay = ctk.CTkFrame(self.root, fg_color="#0a0a0a", corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._disclaimer_overlay = overlay

        # 標題列 + 關閉按鈕
        header = ctk.CTkFrame(overlay, fg_color="transparent", height=44)
        header.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(header, text="⚠ 免責聲明",
                     font=(FONT_UI, 16, "bold"),
                     text_color="#ff9944").pack(side="left", padx=6)
        ctk.CTkButton(header, text="✕", width=32, height=32, corner_radius=16,
                      fg_color="#3a3a3a", hover_color="#c94a4a",
                      font=(FONT_MONO, 14, "bold"),
                      command=self.hide_disclaimer).pack(side="right", padx=6)

        # 內文區
        content = (
            "【 MM Scribe 使用免責聲明 】\n\n"
            "一、本工具由社群個人開發,與任何遊戲廠商、發行商並無合作、\n"
            "    授權或關聯關係,亦非任何官方認可之工具。\n\n"
            "二、本工具僅供個人學習研究與傷害分析用途,\n"
            "    請勿用於任何商業行為或不當競技目的。\n\n"
            "三、透過網路封包擷取遊戲資訊,可能違反相關遊戲之服務條款。\n"
            "    使用者需自行評估風險與後果,包含但不限於\n"
            "    帳號警告、停權或永久封鎖。\n\n"
            "四、本工具僅在本機端解析封包內容,\n"
            "    不會蒐集、儲存或傳送任何個人資料至外部伺服器。\n\n"
            "五、開發者不對使用本工具所產生之任何直接或間接損失\n"
            "    負任何法律或道義責任。\n\n"
            "六、使用本工具即視為您已閱讀並同意上述所有條款。\n"
            "    若不同意,請立即停止使用並刪除本程式。\n"
        )
        textbox = ctk.CTkTextbox(overlay, wrap="word",
                                 font=(FONT_UI, 12),
                                 corner_radius=8, fg_color="#1a1a1a")
        textbox.pack(fill="both", expand=True, padx=16, pady=12)
        textbox.insert("end", content)
        textbox.configure(state="disabled")

    def hide_disclaimer(self):
        overlay = getattr(self, "_disclaimer_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self._disclaimer_overlay = None

    # ---- 設定畫面 ----
    def _scaled_tab_stops(self):
        """LOG_TAB_STOPS 是像素位置,字體縮放時同步放大以維持欄位對齊。"""
        return tuple(str(int(int(x) * self.font_scale)) for x in LOG_TAB_STOPS)

    def show_settings(self):
        """建立覆蓋整個視窗的設定畫面。已顯示時不重複建立。"""
        if getattr(self, "_settings_overlay", None) is not None:
            return

        overlay = ctk.CTkFrame(self.root, fg_color="#0a0a0a", corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._settings_overlay = overlay

        header = ctk.CTkFrame(overlay, fg_color="transparent", height=44)
        header.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(header, text="⚙ 設定",
                     font=(FONT_UI, 16, "bold"),
                     text_color="#88ccff").pack(side="left", padx=6)
        ctk.CTkButton(header, text="✕", width=32, height=32, corner_radius=16,
                      fg_color="#3a3a3a", hover_color="#c94a4a",
                      font=(FONT_MONO, 14, "bold"),
                      command=self.hide_settings).pack(side="right", padx=6)

        # 用 ScrollableFrame,視窗過矮時內容自動可捲 (原本用 CTkFrame 會被截掉)
        body = ctk.CTkScrollableFrame(overlay, fg_color="#1a1a1a", corner_radius=8)
        body.pack(fill="both", expand=True, padx=16, pady=12)

        # ── 「顯示」區塊 ──
        section = ctk.CTkFrame(body, fg_color="transparent")
        section.pack(fill="x", padx=12, pady=(12, 4))
        ctk.CTkLabel(section, text="── 顯示 ──",
                     font=(FONT_UI, 12, "bold"),
                     text_color="#ffffff", anchor="w").pack(fill="x", pady=(0, 8))

        # 字體縮放列
        scale_row = ctk.CTkFrame(section, fg_color="transparent")
        scale_row.pack(fill="x", pady=4)
        ctk.CTkLabel(scale_row, text="字體縮放:", width=90,
                     font=(FONT_UI, 12),
                     anchor="w").pack(side="left", padx=(0, 8))
        # 顯示當前倍率的 Entry (唯讀,只當顯示用) + 右側 ▲▼ 兩顆微型按鈕
        # 每次 ▲ / ▼ 步進 0.1,夾在 FONT_SCALE_MIN ~ FONT_SCALE_MAX 之間
        self._scale_entry = ctk.CTkEntry(
            scale_row, width=64, justify="center",
            font=(FONT_MONO, 13, "bold"), corner_radius=6,
        )
        self._scale_entry.insert(0, f"{self.font_scale:.1f}x")
        self._scale_entry.configure(state="readonly")
        self._scale_entry.pack(side="left", padx=(0, 2))

        step_col = ctk.CTkFrame(scale_row, fg_color="transparent")
        step_col.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            step_col, text="▲", width=22, height=14, corner_radius=3,
            fg_color="#4a4a4a", hover_color="#6a6a6a",
            font=(FONT_MONO, 9),
            command=lambda: self._step_scale(0.1),
        ).pack(pady=(0, 1))
        ctk.CTkButton(
            step_col, text="▼", width=22, height=14, corner_radius=3,
            fg_color="#4a4a4a", hover_color="#6a6a6a",
            font=(FONT_MONO, 9),
            command=lambda: self._step_scale(-0.1),
        ).pack()

        ctk.CTkButton(
            scale_row, text="🔄", width=32, corner_radius=6,
            fg_color="#4a4a4a", hover_color="#6a6a6a",
            font=("Segoe UI Emoji", 13),
            command=self._reset_scale,
        ).pack(side="left", padx=(0, 8))

        # 提示:視窗尺寸不會自動跟著縮放,由使用者手動調整
        ctk.CTkLabel(section,
                     text="※ 縮放後如視窗過小,請手動拖曳邊緣調整尺寸",
                     font=(FONT_UI, 10),
                     text_color="#888888", anchor="w").pack(fill="x", pady=(8, 0))

        # 獨立視窗 (popout) 選項
        popout_row = ctk.CTkFrame(section, fg_color="transparent")
        popout_row.pack(fill="x", pady=(10, 0))
        ctk.CTkLabel(popout_row, text="獨立視窗:", width=90,
                     font=(FONT_UI, 12),
                     anchor="w").pack(side="left", padx=(0, 8))
        ctk.CTkCheckBox(
            popout_row, text="攻擊事件日誌",
            variable=self.popout_log_var,
            command=self._on_popout_log_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(side="left", padx=(0, 12))
        ctk.CTkCheckBox(
            popout_row, text="技能傷害排行",
            variable=self.popout_skill_var,
            command=self._on_popout_skill_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(section,
                     text="※ 勾選後日誌會以獨立視窗開啟;直接關閉獨立視窗會自動收回主視窗",
                     font=(FONT_UI, 10),
                     text_color="#888888", anchor="w").pack(fill="x", pady=(4, 0))

        # ── 「追蹤」區塊 ──
        track_section = ctk.CTkFrame(body, fg_color="transparent")
        track_section.pack(fill="x", padx=12, pady=(16, 4))
        ctk.CTkLabel(track_section, text="── 追蹤 ──",
                     font=(FONT_UI, 12, "bold"),
                     text_color="#ffffff", anchor="w").pack(fill="x", pady=(0, 8))

        ctk.CTkCheckBox(
            track_section,
            text="攻擊數值  (顯示攻擊事件日誌、技能傷害排名、傷害/DPS/覆蓋率)",
            variable=self.track_damage_var,
            command=self._on_track_damage_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(anchor="w", pady=4)

        ctk.CTkCheckBox(
            track_section,
            text="治癒數值 (Beta)  (顯示治癒事件日誌、治癒總量/自身/隊友)",
            variable=self.track_heal_var,
            command=self._on_track_heal_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(anchor="w", pady=4)

        ctk.CTkLabel(track_section,
                     text="※ 兩者可同時勾選;至少留一個開啟以免主畫面空白",
                     font=(FONT_UI, 10),
                     text_color="#888888", anchor="w").pack(fill="x", pady=(8, 0))

        # ── 「診斷」區塊 ──
        diag_section = ctk.CTkFrame(body, fg_color="transparent")
        diag_section.pack(fill="x", padx=12, pady=(16, 4))
        ctk.CTkLabel(diag_section, text="── 診斷 ──",
                     font=(FONT_UI, 12, "bold"),
                     text_color="#ffffff", anchor="w").pack(fill="x", pady=(0, 8))

        diag_row = ctk.CTkFrame(diag_section, fg_color="transparent")
        diag_row.pack(fill="x", pady=4)
        ctk.CTkLabel(diag_row, text="網路環境:", width=90,
                     font=(FONT_UI, 12),
                     anchor="w").pack(side="left", padx=(0, 8))
        ctk.CTkButton(diag_row, text="🌐 網路檢測",
                      width=120, corner_radius=6,
                      fg_color="#3a6a9a", hover_color="#4a7ab0",
                      font=(FONT_UI, 11),
                      command=self.show_network_check).pack(side="left", padx=(0, 8))

    def hide_settings(self):
        overlay = getattr(self, "_settings_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self._settings_overlay = None
        # entry 隨 overlay 一起銷毀,清空參照免得後續誤觸
        self._scale_entry = None

    def _on_scale_change(self, value):
        """套用縮放 → 更新日誌 tab stops → 更新 skill Canvas → 存檔。
        呼叫來源:▲/▼ 步進、還原預設。
        """
        self.font_scale = round(float(value), 2)
        ctk.set_widget_scaling(self.font_scale)
        ctk.set_window_scaling(self.font_scale)
        self.log_area._textbox.configure(tabs=self._scaled_tab_stops())
        # 技能列的 tk.Canvas 不受 CTk widget_scaling 影響,需手動同步
        self._apply_scale_to_skill_rows()
        if getattr(self, "_scale_entry", None) is not None:
            # Entry 是 readonly,更新前要先解鎖
            self._scale_entry.configure(state="normal")
            self._scale_entry.delete(0, "end")
            self._scale_entry.insert(0, f"{self.font_scale:.1f}x")
            self._scale_entry.configure(state="readonly")
        self.settings["font_scale"] = self.font_scale
        save_settings(self.settings)

    def _step_scale(self, delta):
        """▲/▼ 按鈕步進;夾在 FONT_SCALE_MIN..MAX,四捨五入到小數一位避免浮點誤差。"""
        new_val = round(self.font_scale + delta, 1)
        new_val = max(FONT_SCALE_MIN, min(FONT_SCALE_MAX, new_val))
        if new_val != self.font_scale:
            self._on_scale_change(new_val)

    def _reset_scale(self):
        self._on_scale_change(FONT_SCALE_DEFAULT)

    def set_alpha(self, value):
        alpha = float(value) / 100
        self.root.attributes("-alpha", alpha)
        self.lbl_alpha.configure(text=f"{int(float(value))}%")

    def toggle_topmost(self):
        self.is_topmost = self.topmost_var.get()
        self._apply_topmost_all()
        status = "已開啟" if self.is_topmost else "已關閉"
        self.log(f"=== 視窗置頂 {status} ===")

    def _apply_topmost_all(self):
        """對主視窗與所有 popout Toplevel 一併套用 topmost 狀態。
        呼叫時機:toggle_topmost / _popout_log / _popout_skill (新視窗建立時)。
        """
        try:
            self.root.attributes("-topmost", self.is_topmost)
        except Exception:
            pass
        for w in (self._log_popout_win, self._skill_popout_win):
            if w is None:
                continue
            try:
                w.attributes("-topmost", self.is_topmost)
            except Exception:
                pass

    def toggle_log_collapse(self):
        """折疊/展開事件日誌。折疊時 log_area 隱藏但仍持續寫入。
        折疊時該視窗高度縮到剛好容納其餘元件;展開時還原上次記住的高度。

        target = log_pane 當前所在的 Toplevel (dock 時是 root、popout 時是 Toplevel),
        所有 geometry 都對它操作,避免主視窗被 popout 視窗的動作影響。
        prev height 用 attribute 存在 target 上,讓每個 Toplevel 各自記憶。
        """
        scale = self.font_scale
        target = self.log_pane.winfo_toplevel()
        if self.log_collapsed:
            # === 展開 ===
            self.log_area.pack(fill="both", expand=True, padx=6, pady=6)
            self.log_pane.pack_configure(expand=True, fill="both")
            self.btn_log_toggle.configure(text="▼ 即時攻擊事件日誌")
            self.log_collapsed = False
            prev = getattr(target, "_ldm_log_prev_h", None)
            if prev:
                w = target.winfo_width()
                target.geometry(f"{int(w / scale)}x{int(prev / scale)}")
        else:
            # === 折疊 ===
            target._ldm_log_prev_h = target.winfo_height()  # 記住當前高度
            self.log_area.pack_forget()
            self.log_pane.pack_configure(expand=False, fill="x")
            self.btn_log_toggle.configure(text="▶ 即時攻擊事件日誌 (已折疊)")
            self.log_collapsed = True
            target.update_idletasks()
            w = target.winfo_width()
            h = target.winfo_reqheight()
            target.geometry(f"{int(w / scale)}x{int(h / scale)}")

    def toggle_skill_collapse(self):
        """折疊/展開技能傷害排行區塊。折疊時 skill_scroll 隱藏但 self.skill_damage 持續累計。"""
        if self.skill_collapsed:
            self.skill_scroll.pack(fill="both", expand=True, padx=6, pady=6)
            self.skill_pane.pack_configure(expand=True, fill="both")
            self.btn_skill_toggle.configure(text="▼ 技能傷害排行")
            self.skill_collapsed = False
        else:
            self.skill_scroll.pack_forget()
            self.skill_pane.pack_configure(expand=False, fill="x")
            self.btn_skill_toggle.configure(text="▶ 技能傷害排行 (已折疊)")
            self.skill_collapsed = True

    def _skill_area_enter(self, event):
        """滑鼠進入技能排行區,暫時接管 wheel 事件並禁止 CTk 內建 handler 打架。"""
        self.root.bind_all("<MouseWheel>", self._on_skill_wheel_all)

    def _skill_area_leave(self, event):
        """滑鼠離開技能排行區,交還 wheel 事件給其他元件 (log/dev/etc)。
        重要:tkinter 的 Leave 事件在游標「移入子元件」時也會觸發,
        必須用座標檢查游標是否真的離開了 skill_pane 的範圍,否則會誤解綁。
        """
        try:
            x, y = event.x_root, event.y_root
            sx = self.skill_pane.winfo_rootx()
            sy = self.skill_pane.winfo_rooty()
            sw = self.skill_pane.winfo_width()
            sh = self.skill_pane.winfo_height()
            if sx <= x < sx + sw and sy <= y < sy + sh:
                return  # 仍在 skill_pane 內 (只是移入子 widget),不要解綁
            self.root.unbind_all("<MouseWheel>")
        except Exception:
            pass

    def _on_skill_wheel_all(self, event):
        """統一的 wheel handler,直接操作 skill_scroll 內部的 canvas。

        平台差異:Windows 的 event.delta 是 ±120 的倍數,除以 40 換算成捲動格數
        (與 CTk 內建速度一致);macOS Tk 送出的 delta 已經是格數本身 (±1~3),
        再除 40 會被整數截斷成 0,滾輪等同失效,所以直接使用原值。
        """
        SCROLL_SPEED = 3
        try:
            if IS_MACOS:
                step = int(-event.delta) * SCROLL_SPEED
            else:
                step = int(-event.delta / 40) * SCROLL_SPEED
            self.skill_scroll._parent_canvas.yview_scroll(step, "units")
        except Exception:
            pass
        return "break"

    def _create_skill_row(self, display_name):
        """建立單一技能的排行列。
        改用 tk.Canvas 繪製,因為 Canvas 上的 create_text 沒有背景框,
        文字底色天然透明,可讓 fill 橘色直接透過去 (CTkLabel 的 transparent
        只會顯示 parent bg = 深灰,做不到真正透過)。

        結構:
          Container (CTkFrame, 透明)
            ├── Canvas (bar):
            │     - fill_id  : 進度填充矩形 (橘)
            │     - name_id  : 名稱文字 (左貼 10px)
            │     - value_id : 傷害/占比文字 (右貼 10px)
            └── detail_lbl (CTkLabel, 展開時才 pack 於 bar 下方)

        font_scale 變更時需呼叫 _apply_scale_to_skill_rows() 手動重算尺寸
        (tk.Canvas 不受 CTk widget scaling 影響)。
        """
        container = ctk.CTkFrame(self.skill_scroll, fg_color="transparent")
        container.pack(fill="x", padx=0, pady=1)

        canvas_h, name_font, value_font = self._skill_row_metrics()

        bar = tk.Canvas(container, height=canvas_h, bg="#3a3a3a",
                         highlightthickness=0, bd=0, cursor="hand2")
        bar.pack(fill="x")

        # 進度條填充色:暗紅 #a03020 以 60% alpha 疊在 canvas 深灰底 (#3a3a3a) 上。
        # tk.Canvas 不支援真正的 alpha,但在單色底上,預先算出的混色 = 真正透明的視覺結果:
        #   R = 0.6*0xA0 + 0.4*0x3A = 0x77
        #   G = 0.6*0x30 + 0.4*0x3A = 0x34
        #   B = 0.6*0x20 + 0.4*0x3A = 0x2A
        # → #77342A
        # (若之後把 canvas bg 換色,這裡也要重算)
        fill_id = bar.create_rectangle(0, 0, 0, canvas_h,
                                        fill="#77342A", outline="")
        name_id = bar.create_text(10, canvas_h // 2,
                                    text="", anchor="w",
                                    font=name_font, fill="#ffffff")
        value_id = bar.create_text(0, canvas_h // 2,
                                     text="", anchor="e",
                                     font=value_font, fill="#ffffff")

        # 詳細統計:字體與技能列 name 相同 (12pt bold),展開時才 pack
        detail_lbl = ctk.CTkLabel(container, text="", anchor="w",
                                   font=(FONT_UI, 12, "bold"),
                                   text_color="#88ccff")

        row = {
            "container": container, "canvas": bar,
            "fill_id": fill_id, "name_id": name_id, "value_id": value_id,
            "canvas_h": canvas_h,
            "pct": 0.0,        # 記住當前占比,Canvas resize / 縮放時重算 fill 寬
            "detail": detail_lbl,
            "expanded": False,
            "sids": [],
        }

        # Canvas resize:重新調整 fill 寬度與 value_id 位置
        def _on_configure(event, r=row):
            w = event.width
            r["canvas"].coords(r["fill_id"], 0, 0, int(w * r["pct"]), r["canvas_h"])
            r["canvas"].coords(r["value_id"], w - 10, r["canvas_h"] // 2)
        bar.bind("<Configure>", _on_configure)

        # 點擊條上任一處都能展開 (Canvas 是單一 widget,不會被 label 吃掉事件)
        bar.bind("<Button-1>",
                  lambda e, n=display_name: self._toggle_skill_detail(n))

        return row

    def _skill_row_metrics(self):
        """依當前 font_scale 算 canvas 高度與 canvas 上文字用的字體。
        - canvas 高度手動乘 scale (tk.Canvas 本身不受 CTk 的 widget_scaling 影響)
        - 字體用共用的 CTkFont instance;CTk 會自動處理 widget/DPI 縮放
        """
        scale = self.font_scale
        canvas_h = int(30 * scale)
        return canvas_h, self._skill_name_font, self._skill_value_font

    def _apply_scale_to_skill_rows(self):
        """font_scale 變更後同步更新所有既有技能列的 canvas 高度與文字座標。
        字體本身不用重指:CTkFont instance 會自動因應 set_widget_scaling 更新,
        Canvas 只需 itemconfigure 觸發重繪即可 (以確保新尺寸生效)。
        """
        canvas_h, name_font, value_font = self._skill_row_metrics()
        for row in self.skill_rows.values():
            c = row["canvas"]
            c.configure(height=canvas_h)
            row["canvas_h"] = canvas_h
            # 觸發字體 re-apply,讓 Canvas 拿到更新後的 CTkFont 尺寸
            c.itemconfigure(row["name_id"], font=name_font)
            c.itemconfigure(row["value_id"], font=value_font)
            # 重算文字 y 座標 (垂直置中);x 由後續 Configure 事件補
            c.coords(row["name_id"], 10, canvas_h // 2)
            w = c.winfo_width()
            c.coords(row["value_id"], w - 10, canvas_h // 2)
            c.coords(row["fill_id"], 0, 0, int(w * row["pct"]), canvas_h)

    def update_skill_ranking(self):
        """把 self.skill_damage (raw by skill_id) 聚合後重排技能列。
        聚合分兩層:
          A) 依 format_skill_name(sid) 得到的顯示名稱聚合 —— 永遠生效,
             處理同一招在遊戲內產生多個 skill_id 但名稱相同的雜訊。
          B) 勾選「合併同技能」時,再依 MERGE_GROUPS 把成員名稱替換為群組名。
        Resize 進行中會跳過視覺更新 (資料仍會累加,resize 結束後補刷)。
        """
        if self._is_resizing:
            return
        if not self.skill_damage:
            # row 的 top-level widget 是 "container" (改 Canvas 版時從 "frame" 改名),
            # 忘了同步這裡的 destroy → 清除後首次進這分支會 KeyError,
            # 導致 clear_data 中斷、下次 start_monitoring 也在 update_skill_ranking 掛掉
            for row in self.skill_rows.values():
                row["container"].destroy()
            self.skill_rows.clear()
            return

        merge = self.merge_var.get()
        agg = {}       # display_name → damage
        agg_ids = {}   # display_name → [skill_id, ...] (供詳細統計聚合)
        for sid, dmg in self.skill_damage.items():
            name = format_skill_name(sid)
            if merge:
                name = MERGE_GROUPS.get(name, name)
            agg[name] = agg.get(name, 0) + dmg
            agg_ids.setdefault(name, []).append(sid)

        if not agg:
            return
        max_dmg = max(agg.values())
        total = sum(agg.values())
        sorted_names = sorted(agg.keys(), key=lambda k: agg[k], reverse=True)

        seen = set()
        for name in sorted_names:
            dmg = agg[name]
            seen.add(name)
            if name not in self.skill_rows:
                self.skill_rows[name] = self._create_skill_row(name)
            row = self.skill_rows[name]
            row["sids"] = agg_ids[name]  # 存起來供詳細統計 (即使收合時也要保持最新)
            pct = (dmg / max_dmg) if max_dmg else 0
            row["pct"] = pct
            c = row["canvas"]
            w = c.winfo_width()
            # Canvas 剛建立時 winfo_width 可能為 1;此時交給 Configure 事件補畫,
            # 這裡只更新文字內容,fill 座標留空 (Configure 觸發時會依當前寬度重算)
            c.itemconfigure(row["name_id"], text=name)
            c.itemconfigure(row["value_id"],
                             text=f"{dmg:,}  ({dmg * 100 / total:.1f}%)")
            if w > 1:
                c.coords(row["fill_id"], 0, 0, int(w * pct), row["canvas_h"])
            # 展開中的列即時更新詳細統計
            if row["expanded"]:
                row["detail"].configure(
                    text=self._format_skill_detail(row["sids"]))
            # 重新 pack 以強制照排序順序顯示
            row["container"].pack_forget()
            row["container"].pack(fill="x", padx=0, pady=1)

        # 清掉不在 seen 中的舊 row (例如切換合併模式或 clear_data 後又跑新資料)
        for name in list(self.skill_rows.keys()):
            if name not in seen:
                self.skill_rows[name]["container"].destroy()
                del self.skill_rows[name]

    def _toggle_skill_detail(self, display_name):
        """點擊技能列時切換該列的詳細統計 (強擊/連擊/爆擊率) 顯示與否。"""
        row = self.skill_rows.get(display_name)
        if not row:
            return
        if row["expanded"]:
            row["detail"].pack_forget()
            row["expanded"] = False
        else:
            row["detail"].configure(text=self._format_skill_detail(row["sids"]))
            row["detail"].pack(fill="x", padx=10, pady=(2, 4))
            row["expanded"] = True

    def _format_skill_detail(self, sids):
        """把多個 skill_id 的命中次數與各標籤次數合計,格式化為顯示字串。
        沒有命中資料時回傳「(無資料)」。
        """
        hits = 0
        counts = {"爆擊": 0, "強擊": 0, "連擊": 0}
        for sid in sids:
            hits += self.skill_hits.get(sid, 0)
            per = self.skill_tag_counts.get(sid, {})
            for tag_name in counts:
                counts[tag_name] += per.get(tag_name, 0)
        if hits == 0:
            return "  (無資料)"
        parts = [f"強擊率 {counts['強擊'] * 100 / hits:.1f}%",
                 f"連擊率 {counts['連擊'] * 100 / hits:.1f}%",
                 f"爆擊率 {counts['爆擊'] * 100 / hits:.1f}%"]
        return "  " + "  |  ".join(parts) + f"    (共 {hits} 次)"

    def toggle_dev_mode(self):
        """delegate 到 _apply_tracking_mode,讓 dev_pane 與治癒/傷害面板一起重新排序。
        (若只在這裡 pack,dev_pane 會插在 heal_log_pane 之前,順序不對)
        """
        self.is_dev_mode = self.dev_var.get()
        self._apply_tracking_mode()

    def log(self, text):
        self.log_area.configure(state="normal")
        self.log_area.insert("end", text + "\n")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def log_error(self, text):
        """紅字錯誤訊息(共用 highlight tag)。"""
        self.log_area.configure(state="normal")
        self.log_area._textbox.insert("end", text + "\n", "highlight")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def log_damage(self, text, tags):
        """依選定的高亮標籤決定是否套用紅字樣式。"""
        self.log_area.configure(state="normal")
        highlight = self.highlight_var.get()
        if highlight != "無" and highlight in tags:
            self.log_area._textbox.insert("end", text + "\n", "highlight")
        else:
            self.log_area.insert("end", text + "\n")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def dev_log(self, text):
        self.dev_log_area.configure(state="normal")
        self.dev_log_area.insert("end", text + "\n")
        self.dev_log_area.see("end")
        self.dev_log_area.configure(state="disabled")

    def update_coverage(self):
        """更新爆擊/強擊/連擊覆蓋率顯示。樣本不足 COVERAGE_MIN_HITS 時維持「—」。"""
        if self.total_hits < COVERAGE_MIN_HITS:
            for lbl in self.lbl_cov.values():
                lbl.configure(text="—")
            return
        for tag_name, lbl in self.lbl_cov.items():
            pct = self.tag_counts[tag_name] * 100 / self.total_hits
            lbl.configure(text=f"{pct:.1f}%")

    def update_dps(self):
        if self.first_damage_time is None or self.last_damage_time is None:
            self.lbl_dps.configure(text="0")
            return
        elapsed = max(self.last_damage_time - self.first_damage_time, 1.0)
        dps = self.total_damage / elapsed
        self.lbl_dps.configure(text=f"{dps:,.0f}")

    def get_entity_alias(self, entity_id):
        if entity_id not in self.entity_map:
            self.entity_count += 1
            label = chr(64 + self.entity_count) if self.entity_count <= 26 else f"X{self.entity_count}"
            self.entity_map[entity_id] = f"對象_{label}"
        return self.entity_map[entity_id]

    # ================================================
    # 封包解析
    # ================================================
    def find_skill_id_after(self, payload, start):
        """在 start offset 後方(200 bytes 內)尋找 0x4fc5 TLV, 回傳其 skill_id。
        參考 MM_Scribe_PacketNotes.md §5: skill_id 位於該 block payload offset 17..20。
        """
        payload_len = len(payload)
        limit = min(start + 200, payload_len - 8)
        scan = start
        while scan < limit:
            if payload[scan:scan+4] == b'\xc5\x4f\x00\x00':
                try:
                    sz = struct.unpack("<I", payload[scan+4:scan+8])[0]
                    if sz == 35 and scan + 8 + 21 <= payload_len:
                        return struct.unpack("<I", payload[scan+25:scan+29])[0]
                except Exception:
                    pass
                return None
            scan += 1
        return None

    def parse_payload(self, payload):
        offset = 0
        payload_len = len(payload)

        while offset < payload_len - 4:
            if payload[offset:offset+4] == b'\xe9\x51\x00\x00':
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]

                    if offset + 55 <= payload_len:
                        dmg_val = struct.unpack("<I", payload[offset+25:offset+29])[0]

                        # 1. 過濾傷害免疫
                        if dmg_val == 0xFFFFFFFF:
                            msg = "🛡️ [傷害免疫] 數值: 免疫 (0xFFFFFFFF)"
                            self.root.after(0, lambda m=msg: self.log(m))
                            offset += (size + 8) if size > 0 else 35
                            continue

                        # 2. 讀取標籤旗標
                        b41 = payload[offset+41] if offset+41 < payload_len else 0
                        b42 = payload[offset+42] if offset+42 < payload_len else 0
                        b57 = payload[offset+57] if offset+57 < payload_len else 0

                        # 嘗試從後續的 0x4fc5 TLV 抽出 skill_id (可能為 None)
                        skill_id = self.find_skill_id_after(payload, offset + 8 + size)

                        if self.is_dev_mode:
                            skill_txt = f"0x{skill_id:08X}" if skill_id is not None else "(未取得)"
                            dev_msg = (f"[Flag] 數值: {dmg_val} | "
                                       f"b41:{b41:02X} b42:{b42:02X} b57:{b57:02X} | "
                                       f"技能: {skill_txt}")
                            self.root.after(0, lambda m=dev_msg: self.dev_log(m))

                        # 3. 標籤解析
                        #    b41: bit0=爆擊, bit2=無防備(排除破防), bit3=破防
                        #         bit6=非標籤(用途不明,已忽略), bit7=普通攻擊旗標(自動攻擊=1)
                        #    b42: bit0=多重打擊, bit1=強擊, bit2=連擊
                        #    b57: bit0=破防 (備援旗標)
                        KNOWN_MASK_B41 = 0xCD
                        KNOWN_MASK_B42 = 0x07

                        tags = []
                        if b41 & 0x01:
                            tags.append("爆擊")
                        if b42 & 0x02:
                            tags.append("強擊")
                        if (b41 & 0x08) or (b57 & 0x01):
                            tags.append("破防")
                        if (b41 & 0x04) and not (b41 & 0x08):
                            tags.append("無防備")
                        if b42 & 0x04:
                            tags.append("連擊")
                        if b42 & 0x01:
                            tags.append("多重打擊")

                        unknown_b41 = b41 & ~KNOWN_MASK_B41 & 0xFF
                        unknown_b42 = b42 & ~KNOWN_MASK_B42 & 0xFF
                        if unknown_b41 or unknown_b42:
                            parts = []
                            if unknown_b41:
                                parts.append(f"b41.{unknown_b41:02X}")
                            if unknown_b42:
                                parts.append(f"b42.{unknown_b42:02X}")
                            tags.append(f"未知({','.join(parts)})")

                        tag_str = f"[{'+'.join(tags)}]" if tags else "[普通]"

                        # 4. 傷害累加 + DPS 時間戳更新 + 標籤計數
                        self.total_damage += dmg_val
                        now = time.time()
                        if self.first_damage_time is None:
                            self.first_damage_time = now
                        self.last_damage_time = now

                        self.total_hits += 1
                        for name in self.tag_counts:
                            if name in tags:
                                self.tag_counts[name] += 1

                        # 累加該技能的傷害 + 命中次數 + 標籤次數 (skill_id 抓不到就不列入排行)
                        if skill_id is not None:
                            self.skill_damage[skill_id] = self.skill_damage.get(skill_id, 0) + dmg_val
                            self.skill_hits[skill_id] = self.skill_hits.get(skill_id, 0) + 1
                            if skill_id not in self.skill_tag_counts:
                                self.skill_tag_counts[skill_id] = {"爆擊": 0, "強擊": 0, "連擊": 0}
                            for _tn in ("爆擊", "強擊", "連擊"):
                                if _tn in tags:
                                    self.skill_tag_counts[skill_id][_tn] += 1
                            self.root.after(0, self.update_skill_ranking)

                        self.root.after(0, lambda d=self.total_damage: self.lbl_total_dmg.configure(text=f"{d:,}"))
                        self.root.after(0, self.update_dps)
                        self.root.after(0, self.update_coverage)

                        # 技能欄:優先用 skills.ini 對照,skill_id=0 標為符文,否則顯示 hex ID
                        if skill_id is None:
                            skill_display = "?" * 10
                        else:
                            skill_display = format_skill_name(skill_id)
                        # tab 分隔欄位,tab stop 已在初始化時設定於固定像素位置
                        msg = f"{skill_display}\t{dmg_val:>10,}\t{tag_str}"
                        self.root.after(0, lambda m=msg, t=list(tags): self.log_damage(m, t))

                    offset += (size + 8) if size > 0 else 35
                    continue
                except Exception:
                    offset += 1
                    continue
            offset += 1

    # ================================================
    # 治癒 / 護盾 封包解析 (參考 MM_Scribe_PacketNotes_Heal.md)
    #   0x5029 (32B) = 治癒事件 (每個目標一筆)
    #   0x502A (24B) = 本地玩家被治療旗標 (只用於學習本地 ID,不計入)
    #   0x4EED (32B) = 護盾增量事件
    # Skill ID 提取:對每筆 heal/shield 執行 Near scan (見 HEAL_SHIELD_SKILL_ID.md §4)
    # ================================================
    def parse_heal_shield(self, payload):
        """單次掃描 payload,處理 heal + shield + local ID 學習 + Skill ID 關聯。
        - 未學到 local_player_id 前,heal / shield 都用中性標籤 (黃字「治療?」/「護盾?」)
          並不併入 heal_self / heal_ally 分項統計 (但仍計入 heal_total)。
        - Skill ID 走 HEAL_SHIELD_SKILL_ID.md 規格 (±300B 雙向 Near scan,anti-decoy),
          找不到就顯示無技能名。
        """
        offset = 0
        payload_len = len(payload)

        heals = []        # [(tlv_start, target_id, heal_val)]
        shields = []      # [(tlv_start, target_id, shield_amount)]
        flag_heal = None  # 0x502A 帶的 heal 值 (至多一筆)

        while offset < payload_len - 8:
            tag = payload[offset:offset+4]

            if tag == b'\x29\x50\x00\x00':  # 0x5029 heal event (32B TLV)
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]
                    if size == 24 and offset + 32 <= payload_len:
                        target_id = struct.unpack("<Q", payload[offset+9:offset+17])[0]
                        heal_val = struct.unpack("<I", payload[offset+25:offset+29])[0]
                        heals.append((offset, target_id, heal_val))
                        offset += 32
                        continue
                except Exception:
                    pass
                offset += 1
                continue

            if tag == b'\x2a\x50\x00\x00':  # 0x502A local-heal flag (24B TLV)
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]
                    if size == 16 and offset + 24 <= payload_len:
                        flag_heal = struct.unpack("<I", payload[offset+17:offset+21])[0]
                        offset += 24
                        continue
                except Exception:
                    pass
                offset += 1
                continue

            if tag == b'\xed\x4e\x00\x00':  # 0x4EED shield gain (32B TLV)
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]
                    if size == 24 and offset + 32 <= payload_len:
                        target_id = struct.unpack("<Q", payload[offset+9:offset+17])[0]
                        shield_amount = struct.unpack("<Q", payload[offset+17:offset+25])[0]
                        shields.append((offset, target_id, shield_amount))
                        offset += 32
                        continue
                except Exception:
                    pass
                offset += 1
                continue

            offset += 1

        if not (heals or shields):
            return

        # 本地玩家 ID 學習 (見 §5)
        if self.local_player_id is None and flag_heal is not None and heals:
            candidates = {tid for _s, tid, hv in heals if hv == flag_heal}
            if len(candidates) == 1:
                tid = next(iter(candidates))
                self.local_player_id = tid
                self.root.after(0, lambda t=tid: self.log_heal(
                    f"⭐ 已識別本地玩家 ID: 0x{t:X}"))

        # Shield 事件 (統計只寫日誌,不進 banner)
        for tlv_start, target_id, amount in shields:
            skill_id = self._find_heal_shield_skill_id(payload, tlv_start)
            suffix, tag = self._classify_target(target_id)
            prefix = f"護盾{suffix}"
            skill_part = self._skill_label(skill_id)
            detail = "" if tag == "heal_self" else f"  → 0x{target_id:X}"
            msg = f"[{prefix}] {skill_part}+{amount:,}{detail}"
            self.root.after(0, lambda m=msg, t=tag: self.log_heal(m, tag=t))

        # Heal 事件 (banner 累加)
        for tlv_start, target_id, heal_val in heals:
            skill_id = self._find_heal_shield_skill_id(payload, tlv_start)
            suffix, tag = self._classify_target(target_id)
            self.heal_total += heal_val
            if tag == "heal_self":
                self.heal_self += heal_val
            elif tag == "heal_ally":
                self.heal_ally += heal_val
            # heal_unknown → 只累加 heal_total,不分入 self/ally
            prefix = f"治療{suffix}"
            skill_part = self._skill_label(skill_id)
            detail = "" if tag == "heal_self" else f"  → 0x{target_id:X}"
            msg = f"[{prefix}] {skill_part}+{heal_val:,}{detail}"
            self.root.after(0, lambda m=msg, t=tag: self.log_heal(m, tag=t))

        if heals:
            self.root.after(0, self._update_heal_banner)

    def _classify_target(self, target_id):
        """依 local_player_id 判定 target 的分類。
        回傳 (label_suffix, tag_name):
          - 未學到 → ("?", "heal_unknown")  中性黃字
          - target == local → ("自己", "heal_self")  綠字
          - target != local → ("他人", "heal_ally")  藍字
        """
        if self.local_player_id is None:
            return ("?", "heal_unknown")
        if target_id == self.local_player_id:
            return ("自己", "heal_self")
        return ("他人", "heal_ally")

    def _skill_label(self, skill_id):
        """把 skill_id 包裝成日誌顯示用字串;None → 空字串,否則 '[技能名] '。"""
        if skill_id is None:
            return ""
        return f"[{format_skill_name(skill_id)}] "

    # ---- Skill ID Near scan (見 HEAL_SHIELD_SKILL_ID.md §4) ----
    def _find_heal_shield_skill_id(self, payload, tlv_start):
        """對 heal/shield 事件 (TLV size=24,總長 32) 在 ±300B 雙向視窗內
        搜尋伴生 skill TLV;回傳 skill_id 或 None。
        排名規則:min dist;同距離偏好 after 側 (見 §4.3)。
        """
        payload_len = len(payload)
        tlv_end = min(payload_len, tlv_start + 32)
        W = HEAL_SHIELD_SKILL_NEAR_WINDOW

        best_id = None
        best_dist = None      # 用 None 取代 inf,方便判斷
        best_is_after = False

        def consider(magic_off, is_after):
            nonlocal best_id, best_dist, best_is_after
            got = self._try_read_skill_tlv(payload, magic_off)
            if got is None:
                return
            skill_id, is_alt = got
            if is_alt and not self._alt_skill_follows_shield(payload, magic_off):
                return
            dist = abs(magic_off - tlv_start)
            if best_dist is None or dist < best_dist or (
                dist == best_dist and is_after and not best_is_after
            ):
                best_dist = dist
                best_id = skill_id
                best_is_after = is_after

        # After 窗:[tlv_end, tlv_end+W)
        for off in range(tlv_end, min(payload_len, tlv_end + W)):
            consider(off, is_after=True)

        # Before 窗:[max(0, tlv_start-W), tlv_start)
        for off in range(max(0, tlv_start - W), tlv_start):
            consider(off, is_after=False)

        return best_id

    def _try_read_skill_tlv(self, payload, magic_off):
        """檢查 payload[magic_off] 起是否為合法 skill TLV。
        回傳 (skill_id, is_alt) 或 None;is_alt=True 表示 0x1ADE8 (需再過 anti-decoy)。
        size 不符預期時回 None (呼叫方會繼續掃描下一個 offset,不會提前中止 Near)。
        """
        payload_len = len(payload)
        if magic_off + 8 > payload_len:
            return None
        cmd = payload[magic_off:magic_off+4]
        try:
            size = struct.unpack("<I", payload[magic_off+4:magic_off+8])[0]
        except Exception:
            return None
        # 經典型 0x4FC5 size 35 — 無條件接受
        if cmd == b'\xc5\x4f\x00\x00' and size == 35:
            if magic_off + 29 <= payload_len:
                try:
                    return (struct.unpack("<I", payload[magic_off+25:magic_off+29])[0],
                            False)
                except Exception:
                    return None
        # 替代型 0x1ADE8 size 36 — 需 anti-decoy 檢查
        if cmd == b'\xe8\xad\x01\x00' and size == 36:
            if magic_off + 29 <= payload_len:
                try:
                    return (struct.unpack("<I", payload[magic_off+25:magic_off+29])[0],
                            True)
                except Exception:
                    return None
        return None

    def _alt_skill_follows_shield(self, payload, skill_magic_off):
        """anti-decoy:0x1ADE8 只有緊接在某個 0x4EED (size 24) 結束後 0..8 bytes
        才視為真正的 skill TLV,否則為 decoy 要拒絕。
        往前 64 bytes 搜 0x4EED 候選。
        """
        payload_len = len(payload)
        lo = max(0, skill_magic_off - ALT_SKILL_BACKSCAN)
        for o in range(lo, skill_magic_off):
            if o + 8 > payload_len:
                continue
            if payload[o:o+4] != b'\xed\x4e\x00\x00':
                continue
            try:
                size = struct.unpack("<I", payload[o+4:o+8])[0]
            except Exception:
                continue
            if size != 24:
                continue
            shield_end = o + 8 + 24
            gap = skill_magic_off - shield_end
            if 0 <= gap <= ALT_SKILL_MAX_GAP:
                return True
        return False

    def log_heal(self, text, tag=None):
        """寫入治癒日誌。tag 對應 heal_log_area 上定義的 tag 顏色:
          - "heal_self"    → 綠字 (自己)
          - "heal_ally"    → 藍字 (他人)
          - "heal_unknown" → 黃字 (尚未識別本地 ID)
          - None           → 一般白字 (系統/學習訊息)
        """
        self.heal_log_area.configure(state="normal")
        if tag:
            self.heal_log_area._textbox.insert("end", text + "\n", tag)
        else:
            self.heal_log_area.insert("end", text + "\n")
        self.heal_log_area.see("end")
        self.heal_log_area.configure(state="disabled")

    def _update_heal_banner(self):
        self.lbl_heal_total.configure(text=f"{self.heal_total:,}")
        self.lbl_heal_self.configure(text=f"{self.heal_self:,}")
        self.lbl_heal_ally.configure(text=f"{self.heal_ally:,}")

    def packet_callback(self, packet):
        if not (self.is_monitoring and packet.haslayer(TCP) and packet.haslayer(IP)):
            return
        raw_payload = bytes(packet[TCP].payload)
        if not raw_payload:
            return
        if self.track_damage:
            self.parse_payload(raw_payload)
        if self.track_heal:
            self.parse_heal_shield(raw_payload)

    def sniff_packets(self):
        bpf_filter = f"ip net {IP_FILTER_NET} and tcp"
        try:
            self.log("=== 已啟動監控 ===")
            sniff_kwargs = {
                "filter": bpf_filter,
                "prn": self.packet_callback,
                "store": 0,
                "stop_filter": lambda _: not self.is_monitoring,
            }
            # 若已由開機自動偵測 or 手動掃描選定網卡,就綁在那張;否則交給 scapy 自選
            if self.chosen_iface:
                sniff_kwargs["iface"] = self.chosen_iface
            sniff(**sniff_kwargs)
        except Exception as e:
            self.root.after(0, lambda err=e: self.log(f"❌ 攔截錯誤: {err}"))

    def start_monitoring(self):
        self.is_monitoring = True
        self.btn_start.configure(state="disabled")
        # 監控中把停止按鈕改成醒目的紅色
        self.btn_stop.configure(state="normal", fg_color="#d63031", hover_color="#b02a2c")

        # 每次按下開始都重新讀取 skills.ini,讓使用者修改後不用重啟程式
        global SKILL_NAMES, MERGE_GROUPS
        SKILL_NAMES, MERGE_GROUPS, conflicts, ini_errors = load_skill_config()
        if ini_errors:
            self.log_error(f"❌ 載入 {SKILL_CFG_NAME} 時發生錯誤:")
            for err in ini_errors:
                self.log_error(f"    • {err}")
        if SKILL_NAMES:
            self.log(f"=== 已載入 {len(SKILL_NAMES)} 個技能名稱 ({SKILL_CFG_NAME}) ===")
        else:
            self.log(f"=== 未載入 {SKILL_CFG_NAME},技能欄將顯示 hex ID ===")
        if MERGE_GROUPS:
            group_count = len(set(MERGE_GROUPS.values()))
            self.log(f"=== 已載入 {group_count} 個合併群組,涵蓋 {len(MERGE_GROUPS)} 個技能名稱 ===")
        for member, first, ignored in conflicts:
            self.log(f"⚠ 群組衝突:「{member}」已屬於「{first}」,忽略「{ignored}」的宣告")
        # 已顯示中的技能排行列即時套用新名稱
        self.update_skill_ranking()

        self.log("=== 已啟動即時監控 ===")
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

    def start_timer(self):
        """讀取分/秒輸入 → 清資料 → 啟動監控 → 開始倒數。
        0:00 或非數字輸入直接忽略;若已有計時進行中,舊計時會被取消再重啟。
        """
        try:
            m = int((self.timer_min_var.get() or "0").strip())
            s = int((self.timer_sec_var.get() or "0").strip())
        except ValueError:
            self.log("⚠ 計時輸入非數字,已忽略")
            return
        if m < 0 or s < 0:
            return
        total = m * 60 + s
        if total <= 0:
            return

        self._cancel_timer()  # 保險起見,先取消可能仍在跑的舊計時
        self.clear_data()
        if not self.is_monitoring:
            self.start_monitoring()

        self.timer_end_time = time.time() + total
        self._set_timer_button_running()
        self.log(f"=== 計時開始:{m:02d}:{s:02d} ===")
        self._tick_timer()

    def _tick_timer(self):
        """每 500ms 更新剩餘時間;歸零時自動停止監控。"""
        if self.timer_end_time is None:
            return
        remaining = self.timer_end_time - time.time()
        if remaining <= 0:
            # 先清狀態,再呼叫 stop_monitoring,避免 stop_monitoring 誤判為手動取消
            self.timer_end_time = None
            self.timer_after_id = None
            self.lbl_timer_remaining.configure(text="已結束", text_color="#ff9944")
            self._set_timer_button_idle()
            if self.is_monitoring:
                self.stop_monitoring()
            self.log("=== 計時結束,已自動停止監控 ===")
            return
        m = int(remaining) // 60
        s = int(remaining) % 60
        self.lbl_timer_remaining.configure(text=f"剩餘 {m:02d}:{s:02d}",
                                            text_color="#88ccff")
        self.timer_after_id = self.root.after(500, self._tick_timer)

    def _cancel_timer(self):
        """取消計時 (清 after callback + 清狀態 + 清顯示 + 按鈕還原閒置樣式)。"""
        if self.timer_after_id is not None:
            try:
                self.root.after_cancel(self.timer_after_id)
            except Exception:
                pass
            self.timer_after_id = None
        self.timer_end_time = None
        self.lbl_timer_remaining.configure(text="")
        self._set_timer_button_idle()

    def _set_timer_button_running(self):
        """切成「計時停止」紅色樣式,command 指向手動停止 handler。"""
        self.btn_timer.configure(text="⏱ 計時停止",
                                 fg_color="#d63031", hover_color="#b02a2c",
                                 command=self._stop_timer_button)

    def _set_timer_button_idle(self):
        """還原為「計時開始」預設綠色樣式。"""
        self.btn_timer.configure(text="⏱ 計時開始",
                                 fg_color=self._btn_timer_idle_fg,
                                 hover_color=self._btn_timer_idle_hover,
                                 command=self.start_timer)

    def _stop_timer_button(self):
        """使用者按下「計時停止」:取消計時並停止監控 (與計時歸零的行為一致)。"""
        was_running = self.timer_end_time is not None
        self._cancel_timer()
        if self.is_monitoring:
            self.stop_monitoring()
        if was_running:
            self.log("=== 計時已手動停止 ===")

    def stop_monitoring(self):
        self.is_monitoring = False
        self.btn_start.configure(state="normal")
        # 停止後把停止按鈕還原為預設樣式
        self.btn_stop.configure(state="disabled",
                                fg_color=self._btn_stop_default_fg,
                                hover_color=self._btn_stop_default_hover)
        # 若在計時中被手動停止,一併取消計時 (計時自然結束時 timer_end_time 已被清 None,
        # 這個分支不會被誤觸)
        if self.timer_end_time is not None:
            self._cancel_timer()
            self.log("=== 計時已隨監控停止取消 ===")
        self.log("=== 已停止監控 ===")

    def clear_data(self):
        # === 傷害端 ===
        self.total_damage = 0
        self.entity_map.clear()
        self.entity_count = 0
        self.first_damage_time = None
        self.last_damage_time = None

        self.total_hits = 0
        for name in self.tag_counts:
            self.tag_counts[name] = 0

        self.skill_damage.clear()
        self.skill_hits.clear()
        self.skill_tag_counts.clear()
        self.update_skill_ranking()

        self.lbl_total_dmg.configure(text="0")
        self.lbl_dps.configure(text="0")
        self.update_coverage()

        # === 治癒端 ===
        # 注意:local_player_id 不清零 — 一旦學到就整個 session 沿用,
        # 避免使用者手動清資料後又要重新等一次 502A 才能區分自己/隊友
        self.heal_total = 0
        self.heal_self = 0
        self.heal_ally = 0
        self._update_heal_banner()

        # 解鎖 → 清空 → 鎖回
        self.log_area.configure(state="normal")
        self.log_area.delete("1.0", "end")
        self.log_area.configure(state="disabled")

        self.heal_log_area.configure(state="normal")
        self.heal_log_area.delete("1.0", "end")
        self.heal_log_area.configure(state="disabled")

        self.dev_log_area.configure(state="normal")
        self.dev_log_area.delete("1.0", "end")
        self.dev_log_area.configure(state="disabled")

        self.log("=== 數據已歸零 ===")


if __name__ == "__main__":
    root = ctk.CTk()
    app = LiveDamageMonitor(root)
    root.mainloop()
