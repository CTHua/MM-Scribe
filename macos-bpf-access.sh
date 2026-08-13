#!/usr/bin/env bash
# ============================================================
#  MM Scribe — macOS BPF 存取權限設定
#
#  用途:讓抓封包不必每次都 sudo。
#
#  原理與 Wireshark 的 ChmodBPF 完全相同,也刻意沿用同一個群組名稱
#  (access_bpf),兩者可以並存、不會互相干擾:
#    1. 建立 access_bpf 群組,並把你的帳號加進去
#    2. 安裝一個開機執行的 LaunchDaemon,把 /dev/bpf* 的群組改成
#       access_bpf 並給予讀寫權限
#
#  ⚠ 安全性取捨:設定完成後,access_bpf 群組的成員不需要密碼就能
#    監聽這台電腦上的所有網路流量。這正是 Wireshark 的做法,但請
#    確認你接受這個取捨。不想長期開著就用 uninstall 還原。
#
#  用法:
#    ./macos-bpf-access.sh status      查看目前狀態(不需 sudo)
#    ./macos-bpf-access.sh install     設定免 sudo 抓包
#    ./macos-bpf-access.sh uninstall   還原
# ============================================================
set -euo pipefail

LABEL="com.github.mmscribe.ChmodBPF"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
HELPER_DIR="/Library/Application Support/MM Scribe"
HELPER="${HELPER_DIR}/ChmodBPF"
GROUP="access_bpf"
WIRESHARK_PLIST="/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist"

# 要拿的是「真正在用這台電腦的人」,不是提權後的 root:
#   - 透過 sudo 執行     → SUDO_USER
#   - 從 GUI 提權執行     → SUDO_USER 不存在,改看 /dev/console 的擁有者,
#                          也就是當前登入圖形介面的使用者
#   - --user 可明確指定,優先於上面兩者
TARGET_USER="${SUDO_USER:-$(stat -f %Su /dev/console 2>/dev/null || echo "$USER")}"
for ((_i = 1; _i <= $#; _i++)); do
    if [[ "${!_i}" == "--user" ]]; then
        _j=$((_i + 1))
        [[ -n "${!_j:-}" ]] && TARGET_USER="${!_j}"
    fi
done

need_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "需要管理員權限,將以 sudo 重新執行..."
        exec sudo "$0" "$@"
    fi
}

# 是否真的能用 — 用 O_RDWR 測,因為 scapy 的 get_dev_bpf() 就是這樣開的
can_open_bpf() {
    /usr/bin/python3 - <<'PY' 2>/dev/null
import os, sys
for i in range(8):
    p = f"/dev/bpf{i}"
    if not os.path.exists(p):
        continue
    try:
        os.close(os.open(p, os.O_RDWR))
        sys.exit(0)
    except PermissionError:
        sys.exit(1)
    except OSError:
        continue
sys.exit(1)
PY
}

cmd_status() {
    echo "── BPF 存取狀態 ──"
    echo

    if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
        echo "  [✓] 群組 $GROUP 存在"
    else
        echo "  [✗] 群組 $GROUP 不存在"
    fi

    if dseditgroup -o checkmember -m "$TARGET_USER" "$GROUP" >/dev/null 2>&1; then
        echo "  [✓] $TARGET_USER 是 $GROUP 的成員"
    else
        echo "  [✗] $TARGET_USER 不是 $GROUP 的成員"
    fi

    if [[ -f "$WIRESHARK_PLIST" ]]; then
        echo "  [i] 偵測到 Wireshark 的 ChmodBPF,已足夠,不需要再安裝本腳本"
    fi
    if [[ -f "$PLIST" ]]; then
        echo "  [✓] LaunchDaemon 已安裝($PLIST)"
    else
        echo "  [✗] LaunchDaemon 未安裝"
    fi

    echo
    echo "  /dev/bpf* 權限:"
    ls -l /dev/bpf0 /dev/bpf1 2>/dev/null | sed 's/^/    /' || echo "    (找不到 BPF 裝置)"

    echo
    if can_open_bpf; then
        echo "  ⇒ 目前可以免 sudo 抓封包"
    else
        echo "  ⇒ 目前需要 sudo 才能抓封包"
    fi
}

cmd_install() {
    need_root "$@"

    # --yes:跳過互動確認。給程式內部呼叫用 — 那時同意已經在 GUI 上取得過了,
    # 不該在看不到的 shell 裡再問一次(使用者根本看不到那個提示)。
    local assume_yes=0
    for arg in "$@"; do
        [[ "$arg" == "--yes" || "$arg" == "-y" ]] && assume_yes=1
    done

    if [[ -f "$WIRESHARK_PLIST" ]]; then
        echo "偵測到 Wireshark 的 ChmodBPF 已安裝,功能相同,不需要重複安裝。"
        echo "若仍要安裝本腳本的版本,請先移除 Wireshark 的版本。"
        exit 0
    fi

    if [[ $assume_yes -eq 0 ]]; then
        echo "即將進行以下變更:"
        echo "  1. 建立群組 $GROUP(若不存在),並將 $TARGET_USER 加入"
        echo "  2. 安裝 $HELPER"
        echo "  3. 安裝並啟用 LaunchDaemon $PLIST"
        echo
        echo "完成後 $GROUP 的成員不需密碼即可監聽本機所有網路流量。"
        read -r -p "確定要繼續嗎? [y/N] " reply
        [[ "$reply" =~ ^[Yy]$ ]] || { echo "已取消。"; exit 0; }
    fi

    if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
        echo "建立群組 $GROUP..."
        dseditgroup -q -o create -r "BPF device access for packet capture" "$GROUP"
    fi

    if ! dseditgroup -o checkmember -m "$TARGET_USER" "$GROUP" >/dev/null 2>&1; then
        echo "將 $TARGET_USER 加入 $GROUP..."
        dseditgroup -q -o edit -a "$TARGET_USER" -t user "$GROUP"
    fi

    echo "安裝 helper..."
    mkdir -p "$HELPER_DIR"
    cat > "$HELPER" <<'HELPER_EOF'
#!/bin/sh
# 開機時把 BPF 裝置交給 access_bpf 群組,讓群組成員免 sudo 抓封包。
# 權限必須是 rw:libpcap 與 scapy 都以 O_RDWR 開啟 /dev/bpf*。
GROUP=access_bpf
if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    chgrp "$GROUP" /dev/bpf* 2>/dev/null || exit 0
    chmod g+rw /dev/bpf* 2>/dev/null || exit 0
fi
HELPER_EOF
    chown root:wheel "$HELPER"
    chmod 755 "$HELPER"

    echo "安裝 LaunchDaemon..."
    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>${HELPER}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
PLIST_EOF
    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"

    # 先卸載舊的(如果有),再載入
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
    launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load "$PLIST"

    # LaunchDaemon 只在開機時跑,這裡先手動套用一次,免得還要重開機
    "$HELPER"

    echo
    echo "完成。"
    ls -l /dev/bpf0 2>/dev/null | sed 's/^/  /'
    echo
    echo "如果剛剛才被加入群組,現有的終端機視窗可能還沒吃到新的群組身分,"
    echo "開一個新的終端機視窗(或登出再登入)即可。"
}

cmd_uninstall() {
    need_root "$@"

    echo "即將移除 LaunchDaemon 與 helper,並把 /dev/bpf* 權限收回 root。"
    echo "群組 $GROUP 與成員資格會保留(Wireshark 也可能在用)。"
    read -r -p "確定要繼續嗎? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { echo "已取消。"; exit 0; }

    launchctl bootout "system/${LABEL}" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST" "$HELPER"
    rmdir "$HELPER_DIR" 2>/dev/null || true

    # 收回權限,不必等重開機
    chgrp wheel /dev/bpf* 2>/dev/null || true
    chmod g-rw /dev/bpf* 2>/dev/null || true

    echo
    echo "已移除。之後抓封包會再度需要 sudo。"
    echo "若想連群組成員資格一併移除:"
    echo "  sudo dseditgroup -o edit -d $TARGET_USER -t user $GROUP"
}

case "${1:-status}" in
    status) cmd_status ;;
    install) cmd_install "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    *)
        echo "用法: $0 {status|install|uninstall}" >&2
        exit 1
        ;;
esac
