#!/usr/bin/env bash
#
# enhanced_system_forensics.sh
#
# Cross-distro digital forensics collection tool for Linux (Debian/Ubuntu, RHEL/CentOS/OEL).
#
# Usage:
#   sudo ./enhanced_system_forensics.sh [-r] [-m months] [-s]
#
# Options:
#   -r          Run rkhunter (installs temporarily if not present)
#   -m <months> Look back this many months in user login history (default: 1)
#   -s          Silent mode (minimal output to console; report still generated)

REPORT_FILE="forensics-report-$(date +'%Y-%m-%d_%H-%M-%S').log"
SUSPICIOUS_FINDINGS=()
LOOKBACK_MONTHS="1"
RKHUNTER_ENABLED=false
SILENT_MODE=false
RKHUNTER_INSTALLED_TEMP=false

# Parse arguments
while getopts ":rm:s" opt; do
  case $opt in
    r)
      RKHUNTER_ENABLED=true
      ;;
    m)
      LOOKBACK_MONTHS="$OPTARG"
      ;;
    s)
      SILENT_MODE=true
      ;;
    \?)
      echo "[ERROR] Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "[ERROR] Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

# Detect OS family
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID=$ID
  OS_LIKE=$ID_LIKE
else
  echo "[ERROR] Cannot determine OS." >&2
  exit 1
fi

# Determine if Debian or RedHat based
if echo "$OS_ID $OS_LIKE" | grep -qE 'debian|ubuntu'; then
  OS_FAMILY="debian"
  PKG_INSTALL="apt-get install -y"
  PKG_REMOVE="apt-get remove --purge -y"
  LIST_PACKAGES="dpkg -l"
  INSTALL_RKHUNTER="apt-get update && $PKG_INSTALL rkhunter"
  REMOVE_RKHUNTER="$PKG_REMOVE rkhunter && apt-get autoremove -y"
  CRON_DIR="/var/spool/cron/crontabs"
elif echo "$OS_ID $OS_LIKE" | grep -qE 'rhel|fedora|centos|ol'; then
  OS_FAMILY="redhat"
  PKG_INSTALL="yum install -y"
  PKG_REMOVE="yum remove -y"
  LIST_PACKAGES="rpm -qa"
  INSTALL_RKHUNTER="yum install -y epel-release && $PKG_INSTALL rkhunter"
  REMOVE_RKHUNTER="$PKG_REMOVE rkhunter"
  CRON_DIR="/var/spool/cron"
else
  echo "[ERROR] Unsupported OS: $OS_ID" >&2
  exit 1
fi

log_info() {
  $SILENT_MODE && return || echo "[INFO] $1" | tee -a "$REPORT_FILE"
}

log_warn() {
  $SILENT_MODE && return || echo "[WARNING] $1" | tee -a "$REPORT_FILE"
}

report_suspicious() {
  local message="$1"
  SUSPICIOUS_FINDINGS+=("$message")
  echo -e "[SUSPICIOUS] $message" | tee -a "$REPORT_FILE"
}

header() {
  echo "========================================" | tee -a "$REPORT_FILE"
  echo " $1 - $(date)" | tee -a "$REPORT_FILE"
  echo "========================================" | tee -a "$REPORT_FILE"
}

collect_system_info() {
  header "System Info"
  log_info "Hostname: $(hostname)"
  log_info "Date: $(date)"
  log_info "Uptime: $(uptime -p)"
  log_info "Kernel Version: $(uname -r)"
  cat /etc/os-release | tee -a "$REPORT_FILE"
}

collect_installed_packages() {
  header "Installed Packages"
  eval "$LIST_PACKAGES" | tee -a "$REPORT_FILE"
}

collect_users_and_groups() {
  header "Users and Groups"
  head -n 10 /etc/passwd | tee -a "$REPORT_FILE"
}

collect_login_history() {
  header "Login History"
  who | tee -a "$REPORT_FILE"
  last -F -n 50 | tee -a "$REPORT_FILE"
}

collect_process_info() {
  header "Running Processes"
  ps auxww --sort=-%mem | head -n 15 | tee -a "$REPORT_FILE"
  ps aux | grep -E 'crypto|mining|/tmp|/dev/shm|\.py|\.pl|base64|eval|curl|wget|nc|bash' | grep -v "grep" | while read -r line; do
    report_suspicious "Suspicious process: $line"
  done
}

collect_network_info() {
  header "Network Connections and Listening Ports"
  netstat -tulpn 2>/dev/null | tee -a "$REPORT_FILE"
  netstat -natp 2>/dev/null | grep 'ESTABLISHED' | tee -a "$REPORT_FILE"

  header "Suspicious Network Connections"
  netstat -natp 2>/dev/null | grep 'ESTABLISHED' | while read -r line; do
    if echo "$line" | grep -E ':22 ' | grep -vqE '127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])|::1'; then
      report_suspicious "External SSH connection: $line"
    elif echo "$line" | grep -vqE '127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])|::1'; then
      report_suspicious "External non-SSH connection: $line"
    fi
  done
}

collect_autoruns() {
  header "Startup Scripts and Scheduled Jobs"
  ls -l /etc/cron.* /etc/cron.d/ 2>/dev/null | tee -a "$REPORT_FILE"
  atq 2>/dev/null | tee -a "$REPORT_FILE"
  grep '^[^#]' /etc/passwd | cut -d':' -f1 | while read user; do
    cronfile="$CRON_DIR/$user"
    if [[ -f "$cronfile" ]]; then
      echo "--- Cron for $user ---" | tee -a "$REPORT_FILE"
      cat "$cronfile" | tee -a "$REPORT_FILE"
    fi
  done
  systemctl list-units --type=service --all | head -n 10 | tee -a "$REPORT_FILE"
}

collect_file_integrity() {
  header "Critical File Integrity"
  for bin in /bin/bash /usr/bin/ssh /usr/bin/sudo /sbin/init; do
    [[ -f "$bin" ]] && sha256sum "$bin" | tee -a "$REPORT_FILE"
  done
}

collect_recent_changes() {
  header "Recently Modified Files (3 days)"
  find / -type f -mtime -3 2>/dev/null | tee -a "$REPORT_FILE"
}

collect_hidden_world_writable_files() {
  header "Hidden and World-Writable Files"
  find / -type f -name ".*" 2>/dev/null | tee -a "$REPORT_FILE"
  find / -type f -perm -0002 2>/dev/null | tee -a "$REPORT_FILE"
}

collect_unusual_binary_paths() {
  header "Processes with Unusual Binary Paths"
  ps -eo pid,comm,args | grep -vE '^(PID|root)' | grep -E '/tmp/|/dev/shm|/var/tmp' | tee -a "$REPORT_FILE"
}

collect_kernel_modules() {
  header "Loaded Kernel Modules"
  lsmod | tee -a "$REPORT_FILE"
  lsmod | grep -vE "^(Module|usb|nf|ipv|ext|fat|xfs|overlay)" | tee -a "$REPORT_FILE"
}

collect_suid_sgid_files() {
  header "SUID/SGID Files"
  find / -perm /6000 -type f 2>/dev/null | tee -a "$REPORT_FILE"
}

collect_bash_history() {
  header "Bash Histories"
  for home in /home/* /root; do
    [[ -f "$home/.bash_history" ]] && {
      echo "--- History for $home ---" | tee -a "$REPORT_FILE"
      tail -n 20 "$home/.bash_history" | tee -a "$REPORT_FILE"
      grep -Ei 'nc -e|/dev/tcp|bash -i|sudo su|curl http|wget http|scp .*@|history -c|chmod \+s|/etc/shadow|rm -rf|python -c' "$home/.bash_history" | \
        while read -r cmd; do
          report_suspicious "Suspicious command in $home/.bash_history: $cmd"
        done
    }
  done
}

collect_persistence_mechanisms() {
  header "User-Level Persistence"
  for home in /home/* /root; do
    find "$home" -maxdepth 2 -type f \( -name ".bashrc" -o -name ".profile" \) \
      -exec grep -H 'curl\|wget\|nc\|bash\|python' {} \; 2>/dev/null | tee -a "$REPORT_FILE"
    find "$home/.config/autostart" -type f 2>/dev/null | tee -a "$REPORT_FILE"
  done
}

collect_open_files() {
  header "Open Files by All Processes"
  lsof -nP -u $(cut -f1 -d: /etc/passwd) 2>/dev/null | grep -vE 'lib|locale|font|icon|cache' | tee -a "$REPORT_FILE"
}

collect_ssh_keys_and_hosts() {
  header "/etc/hosts and SSH Keys"
  cat /etc/hosts | tee -a "$REPORT_FILE"
  find /home /root -name "authorized_keys" -exec cat {} \; 2>/dev/null | tee -a "$REPORT_FILE"
}

run_rootkit_scanner() {
  if [ "$RKHUNTER_ENABLED" = false ]; then
    log_info "Skipping rkhunter scan (use -r to enable it)."
    return
  fi

  header "Rootkit Scan (rkhunter)"
  if ! command -v rkhunter &>/dev/null; then
    log_info "Installing rkhunter temporarily..."
    eval "$INSTALL_RKHUNTER"
    RKHUNTER_INSTALLED_TEMP=true
  fi
  rkhunter --update
  rkhunter --check --sk 2>&1 | tee -a "$REPORT_FILE"
}

cleanup() {
  if [ "$RKHUNTER_INSTALLED_TEMP" = true ]; then
    log_info "Removing temporarily installed rkhunter..."
    eval "$REMOVE_RKHUNTER"
  fi
  tar czf "forensics-archive-$(date +'%Y%m%d-%H%M').tar.gz" "$REPORT_FILE"
  echo "[INFO] Report archived. Forensics complete."
}

main() {
  log_info "Forensics scan started..."
  collect_system_info
  collect_installed_packages
  collect_users_and_groups
  collect_login_history
  collect_process_info
  collect_network_info
  collect_autoruns
  collect_file_integrity
  collect_recent_changes
  collect_hidden_world_writable_files
  collect_unusual_binary_paths
  collect_kernel_modules
  collect_suid_sgid_files
  collect_bash_history
  collect_persistence_mechanisms
  collect_open_files
  collect_ssh_keys_and_hosts
  run_rootkit_scanner

  header "Suspicious Findings Summary"
  if [ ${#SUSPICIOUS_FINDINGS[@]} -eq 0 ]; then
    echo "No obvious signs of compromise detected." | tee -a "$REPORT_FILE"
  else
    echo "Potential issues found:" | tee -a "$REPORT_FILE"
    for finding in "${SUSPICIOUS_FINDINGS[@]}"; do
      echo "- $finding" | tee -a "$REPORT_FILE"
    done
  fi

  header "Final Assessment Summary"
  if [ ${#SUSPICIOUS_FINDINGS[@]} -eq 0 ]; then
    echo "✅ System appears clean. No signs of compromise were detected during this scan." | tee -a "$REPORT_FILE"
  else
    echo "⚠️  Warning: One or more suspicious items were detected." | tee -a "$REPORT_FILE"
    echo "❗ This may indicate a compromised host. Further investigation is strongly recommended." | tee -a "$REPORT_FILE"
  fi

  cleanup
}

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] This script must be run as root." >&2
  exit 1
fi

main
