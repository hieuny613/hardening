#!/bin/bash

# Định nghĩa biến log file
LOG_FILE="/var/log/script.log"

FILE_USER_IT="users.txt"
NTP_SERVER="pool.ntp.org"

# Định nghĩa các hàm hiển thị màu sắc
function echo_red() {
  echo -e "\033[1;31m$1\033[0m"
}

function echo_green() {
  echo -e "\033[1;32m$1\033[0m"
}

function echo_yellow() {
  echo -e "\033[1;33m$1\033[0m"
}

# Định nghĩa các hàm log
function log_success() {
  echo_green "[SUCCESS] $1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$LOG_FILE"
}

function log_warning() {
  echo_yellow "[WARNING] $1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$LOG_FILE"
}

function log_error() {
  echo_red "[ERROR] $1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE"
}

# Kiểm tra quyền root
function check_root_user() {
  if [[ "$(id -u)" != "0" ]]; then
    log_error "Vui lòng chạy script bằng quyền root."
    exit 1
  else
    log_success "Đã xác nhận quyền root."
  fi
}

# Xác minh phiên bản hệ điều hành
function verify_os_version() {
  os_name=$(lsb_release -si)
  os_version=$(lsb_release -sr)
  if [[ "$os_name" == "Ubuntu" && "$os_version" == "22.04" ]]; then
    log_success "Hệ điều hành là Ubuntu 22.04. Tiếp tục chạy script."
  else
    log_error "Script này chỉ chạy trên Ubuntu 22.04. Bạn đang sử dụng $os_name $os_version."
    exit 1
  fi
}

# Cập nhật hệ thống
function update_system_packages() {
  echo_yellow "Đang cập nhật hệ thống..."
  apt update -y >/dev/null 2>&1 && apt upgrade -y >/dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    log_success "Cập nhật hệ thống thành công."
  else
    log_error "Cập nhật hệ thống thất bại."
  fi
}

# Vô hiệu hóa đăng nhập root qua SSH
function disable_root_ssh_login() {
  echo_yellow "Vô hiệu hóa đăng nhập root qua SSH..."
  sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  systemctl restart sshd
  if [[ $? -eq 0 ]]; then
    log_success "Đã vô hiệu hóa đăng nhập root qua SSH."
  else
    log_error "Vô hiệu hóa đăng nhập root qua SSH thất bại."
  fi
}

# Cấu hình sudo và nhóm sugroup
function configure_sudo_permissions() {
  groupadd sugroup >/dev/null 2>&1
  chgrp sugroup /bin/su
  chmod 750 /bin/su
  echo "%sugroup   ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
  log_success "Cấu hình sudo và nhóm sugroup thành công."
}

# Cấu hình bảo mật cho các tệp tin
function configure_file_security() {
  echo_yellow "Cấu hình bảo mật cho các tệp tin..."
  chmod 644 /etc/passwd
  chmod 751 /var/log/
  chmod 640 /var/log/*log
  chmod 640 /etc/logrotate.conf
  chmod 751 /etc/logrotate.d
  chmod 640 /etc/logrotate.d/*
  chmod 640 /etc/rsyslog.conf
  chmod 751 /etc/rsyslog.d
  chmod 640 /etc/rsyslog.d/*
  chmod 700 /etc/init.d
  log_success "Cấu hình bảo mật tệp tin thành công."
}

# Kiểm tra các user có UID 0
function check_users_with_uid_zero() {
  echo_yellow "Kiểm tra các user có UID 0:"
  awk -F: '($3 == "0") {print $1}' /etc/passwd | tee -a "$LOG_FILE"
}

# Đồng bộ thời gian hệ thống
function synchronize_system_time() {
  local server="$1"
  if [ -z "$server" ]; then
    log_error "Vui lòng cung cấp tên hoặc địa chỉ IP của server NTP."
    return 1
  fi

  if ! command -v ntpdate &> /dev/null; then
    echo_yellow "Đang cài đặt ntpdate..."
    apt update -y >/dev/null 2>&1 && apt install -y ntpdate >/dev/null 2>&1
  fi

  echo_yellow "Đang đồng bộ thời gian từ server $server..."
  ntpdate "$server" >/dev/null 2>&1

  if [ $? -eq 0 ]; then
    log_success "Đồng bộ thời gian thành công từ $server."
  else
    log_error "Đồng bộ thời gian thất bại."
  fi
}

# Cấu hình sysctl để tăng cường bảo mật
function configure_sysctl_security() {
  echo_yellow "Cấu hình sysctl để tăng cường bảo mật..."
  echo "
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
  " >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1
  log_success "Cấu hình sysctl bảo mật thành công."
}

# Cấu hình chính sách mật khẩu
function configure_password_policy() {
  echo_yellow "Cấu hình chính sách mật khẩu..."
  apt install libpam-pwquality -y >/dev/null 2>&1
  echo "password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" >> /etc/pam.d/common-password
  sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   60' /etc/login.defs
  sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   3' /etc/login.defs
  sed -i '/^PASS_MIN_LEN/ c\PASS_MIN_LEN    8' /etc/login.defs
  sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   10' /etc/login.defs
  log_success "Cấu hình chính sách mật khẩu thành công."
}

# Xóa các user không cần thiết
function delete_unnecessary_users() {
  local users=("Guest" "lp" "uucp" "gopher" "games" "news")

  echo_yellow "Xóa các user không cần thiết..."
  for user in "${users[@]}"; do
    if id "$user" &>/dev/null; then
      userdel -r "$user" >/dev/null 2>&1
      echo "Đã xóa user: $user" | tee -a "$LOG_FILE"
    else
      echo "User $user không tồn tại" | tee -a "$LOG_FILE"
    fi
  done
  log_success "Hoàn thành việc xóa user không cần thiết."
}

# Liệt kê các user không có mật khẩu
function list_users_without_password() {
  echo_yellow "Các user không có mật khẩu trên hệ thống:"
  awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow | tee -a "$LOG_FILE"
}

# Tạo user từ file
function create_users_from_file() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    log_error "File $file không tồn tại."
    return 1
  fi

  echo_yellow "Tạo user từ file $file..."
  while IFS=: read -r username password ssh_key; do
    if id "$username" &>/dev/null; then
      echo "User $username đã tồn tại." | tee -a "$LOG_FILE"
    else
      useradd -m -s /bin/bash -G sugroup,sudo "$username"
      echo "$username:$password" | chpasswd
      echo "Đã tạo user: $username và thêm vào nhóm 'sugroup' và 'sudo'." | tee -a "$LOG_FILE"

      user_ssh_dir="/home/$username/.ssh"
      mkdir -p "$user_ssh_dir"
      echo "$ssh_key" > "$user_ssh_dir/authorized_keys"
      chmod 700 "$user_ssh_dir"
      chmod 600 "$user_ssh_dir/authorized_keys"
      chown -R "$username:$username" "$user_ssh_dir"
      echo "Đã thêm SSH key cho user: $username." | tee -a "$LOG_FILE"
    fi
  done < "$file"
  log_success "Hoàn thành việc tạo user từ file."
}

# Cấu hình SSH
function configure_ssh() {
  echo_yellow "Cấu hình SSH..."
  echo "banner /etc/ssh/banner" >> /etc/ssh/sshd_config
  echo "
*************************WARNING***********************************************************
This computer system is the property of the Prajwal Organization. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Organization's Acceptable Use of Information Technology Resources Policy. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the policy. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this warning.
*******************************************************************************************
  " > /etc/ssh/banner
  echo "
PermitUserEnvironment no
ClientAliveInterval 900
ClientAliveCountMax 0
" >> /etc/ssh/sshd_config
  systemctl restart sshd
  log_success "Cấu hình SSH thành công."
}

# Vô hiệu hóa Ctrl+Alt+Del
function disable_ctrl_alt_del() {
  echo_yellow "Vô hiệu hóa tổ hợp phím Ctrl+Alt+Del..."
  systemctl mask ctrl-alt-del.target
  systemctl daemon-reload
  log_success "Đã vô hiệu hóa Ctrl+Alt+Del."
}

# Cấu hình chính sách đăng nhập thất bại
function configure_login_failures() {
  echo_yellow "Cấu hình chính sách đăng nhập thất bại..."
  echo "auth required pam_tally2.so deny=5 unlock_time=1800" >> /etc/pam.d/sshd
  echo "auth required pam_tally2.so deny=5 unlock_time=1800" >> /etc/pam.d/login
  log_success "Cấu hình chính sách đăng nhập thất bại thành công."
}

# Cài đặt và cấu hình auditd
function setup_auditd_rules() {
  echo_yellow "Cài đặt và cấu hình auditd..."
  apt install auditd audispd-plugins -y >/dev/null 2>&1
  echo "
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /etc/sudoers -p wa -k actions
" >> /etc/audit/audit.rules
  sed -i 's/^active.*/active = yes/' /etc/audit/plugins.d/syslog.conf
  service auditd restart
  log_success "Cấu hình auditd thành công."
}

# Hàm main
function main() {
  check_root_user
  verify_os_version
  update_system_packages
  configure_file_security
  synchronize_system_time "$NTP_SERVER"
  configure_sysctl_security
  setup_auditd_rules
  disable_root_ssh_login
  configure_login_failures
  disable_ctrl_alt_del
  configure_ssh
  configure_password_policy
  configure_sudo_permissions
  check_users_with_uid_zero
  delete_unnecessary_users
  list_users_without_password
  create_users_from_file "$FILE_USER_IT"
}

# Chạy hàm main
main
