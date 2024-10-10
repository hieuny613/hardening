#!/bin/bash

# Define log file variable
LOG_FILE="/var/log/script.log"

FILE_USER_IT="users.txt"
NTP_SERVER="pool.ntp.org"
# Services to disable
unnecessary_services=("avahi-daemon.service" "cups.service")

# Define color display functions
function echo_red() {
  echo -e "\033[1;31m$1\033[0m"
}

function echo_green() {
  echo -e "\033[1;32m$1\033[0m"
}

function echo_yellow() {
  echo -e "\033[1;33m$1\033[0m"
}

# Define logging functions
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

# Check if running as root
function check_root_user() {
  if [[ "$(id -u)" != "0" ]]; then
    log_error "Please run the script as root."
    exit 1
  else
    log_success "Confirmed running as root."
  fi
}

# Verify operating system version
function verify_os_version() {
  os_name=$(lsb_release -si)
  os_version=$(lsb_release -sr)
  if [[ "$os_name" == "Ubuntu" && "$os_version" == "22.04" ]]; then
    log_success "Operating system is Ubuntu 22.04. Continuing with the script."
  else
    log_error "This script only runs on Ubuntu 22.04. You are using $os_name $os_version."
    exit 1
  fi
}

# Update system packages
function update_system_packages() {
  echo_yellow "Updating system packages..."
  apt update -y >/dev/null 2>&1 && apt upgrade -y >/dev/null 2>&1 && apt autoremove -y >/dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    log_success "System packages updated successfully."
  else
    log_error "Failed to update system packages."
  fi
}

# Disable root SSH login
function disable_root_ssh_login() {
  echo_yellow "Disabling root SSH login..."
  sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
  systemctl restart sshd
  if [[ $? -eq 0 ]]; then
    log_success "Disabled root SSH login."
  else
    log_error "Failed to disable root SSH login."
  fi
}

# Configure sudo permissions and sugroup
function configure_sudo_permissions() {
  groupadd sugroup >/dev/null 2>&1
  chgrp sugroup /bin/su
  chmod 750 /bin/su
  echo "%sugroup ALL=NOPASSWD:ALL" >> /etc/sudoers
  log_success "Configured sudo permissions and sugroup."
}

# Configure file security settings
function configure_file_security() {
  echo_yellow "Configuring file security settings..."
  chmod 644 /etc/passwd
  chmod 751 /var/log/
  chmod 640 /var/log/*log
  chmod 640 /etc/logrotate.conf
  chmod 751 /etc/logrotate.d
  chmod 640 /etc/logrotate.d/*
  chmod 640 /etc/rsyslog.conf
  chmod 751 /etc/rsyslog.d
  chmod 640 /etc/rsyslog.d/*
  chmod 755 /etc/init.d
  log_success "File security settings configured successfully."
}

# Check users with UID 0
function check_users_with_uid_zero() {
  echo_yellow "Checking users with UID 0..."
  UID_ZERO_LOG="/var/log/uid_zero_users.log"
  > "$UID_ZERO_LOG"
  users_with_uid_zero=$(awk -F: '($3 == "0") {print $1}' /etc/passwd)
  for user in $users_with_uid_zero; do
    user_info=$(getent passwd "$user")
    echo "User with UID 0: $user" | tee -a "$UID_ZERO_LOG"
    echo "Details: $user_info" | tee -a "$UID_ZERO_LOG"
    if [[ "$user" != "root" ]]; then
      log_warning "User $user has UID 0. This may be a security risk."
    fi
  done
  log_success "UID 0 user check completed. Details saved to $UID_ZERO_LOG."
}

# Synchronize system time with Chrony
function install_and_configure_chrony() {
  echo_yellow "Installing and configuring Chrony..."
  apt install chrony -y >/dev/null 2>&1
  sed -i "s|^pool .*|pool $NTP_SERVER iburst|" /etc/chrony/chrony.conf
  systemctl restart chrony
  if [[ $? -eq 0 ]]; then
    log_success "Chrony installed and configured successfully."
  else
    log_error "Failed to configure Chrony."
  fi
}

# Configure sysctl for security enhancements
function configure_sysctl_security() {
  echo_yellow "Configuring sysctl for security enhancements..."
  sysctl_params=(
    "net.ipv4.ip_forward=0"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
  )

  for param in "${sysctl_params[@]}"; do
    key=$(echo "$param" | cut -d= -f1)
    sed -i "s|^$key.*|$param|" /etc/sysctl.conf
    if ! grep -q "^$key" /etc/sysctl.conf; then
      echo "$param" >> /etc/sysctl.conf
    fi
  done
  sysctl -p >/dev/null 2>&1
  log_success "Sysctl security settings configured successfully."
}

# Configure password policy
function configure_password_policy() {
  echo_yellow "Configuring password policy..."
  # Backup configuration file
  cp /etc/pam.d/common-password /etc/pam.d/common-password.bak.$(date +%F-%T)
  apt install libpam-pwquality -y >/dev/null 2>&1

  # Configure pam_pwquality in /etc/pam.d/common-password
  if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sed -i '/^password\s\+requisite\s\+pam_deny.so/a password requisite pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1' /etc/pam.d/common-password
  else
    sed -i 's/^password\s\+requisite\s\+pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
  fi

  # Update /etc/login.defs
  sed -i 's/^#\?\s*\(PASS_MAX_DAYS\s*\).*/\1   60/' /etc/login.defs
  sed -i 's/^#\?\s*\(PASS_MIN_DAYS\s*\).*/\1   3/' /etc/login.defs
  sed -i 's/^#\?\s*\(PASS_MIN_LEN\s*\).*/\1   8/' /etc/login.defs
  sed -i 's/^#\?\s*\(PASS_WARN_AGE\s*\).*/\1   10/' /etc/login.defs
  log_success "Password policy configured successfully."
}

# Function to check if password complies with policy
function is_password_compliant() {
  local password="$1"

  # Check password length
  if [[ ${#password} -lt 8 ]]; then
    return 1
  fi

  # Check for at least one uppercase letter
  if ! [[ "$password" =~ [A-Z] ]]; then
    return 1
  fi

  # Check for at least two lowercase letters
  if ! [[ "$(echo "$password" | grep -o '[a-z]' | wc -l)" -ge 2 ]]; then
    return 1
  fi

  # Check for at least one digit
  if ! [[ "$password" =~ [0-9] ]]; then
    return 1
  fi

  # Check for at least one special character
  if ! [[ "$password" =~ [\@\#\$\%\^\&\*\(\)\_\+\!\~\`\-\=] ]]; then
    return 1
  fi

  return 0
}

# Disable unnecessary user accounts
function disable_unnecessary_users() {
  local users=("Guest" "lp" "uucp" "gopher" "games" "news")

  echo_yellow "Disabling unnecessary user accounts..."
  for user in "${users[@]}"; do
    if id "$user" &>/dev/null; then
      usermod -s /usr/sbin/nologin "$user"
      passwd -l "$user"
      echo "Locked user account: $user" | tee -a "$LOG_FILE"
    else
      echo "User $user does not exist" | tee -a "$LOG_FILE"
    fi
  done
  log_success "Completed disabling unnecessary user accounts."
}

# List users without passwords
function list_users_without_password() {
  echo_yellow "Listing users without passwords..."
  awk -F: '($2 == "" && $7 !~ /(\/usr\/sbin\/nologin|\/bin\/false)/) {print $1}' /etc/shadow | tee -a "$LOG_FILE"
}

# Create users from file
function create_users_from_file() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    log_error "File $file does not exist."
    return 1
  fi

  echo_yellow "Creating users from file $file..."
  while IFS=: read -r username password ssh_key; do
    if id "$username" &>/dev/null; then
      echo "User $username already exists." | tee -a "$LOG_FILE"
    else
      # Check if password complies with policy
      if is_password_compliant "$password"; then
        useradd -m -s /bin/bash -G sugroup,sudo "$username"
        echo "$username:$password" | chpasswd
        echo "Created user: $username and added to groups 'sugroup' and 'sudo'." | tee -a "$LOG_FILE"
        user_dir="/home/$username/"
        user_ssh_dir="/home/$username/.ssh"
        mkdir -p "$user_ssh_dir"
        cp /etc/skel/.* "$user_dir"
        echo "$ssh_key" > "$user_ssh_dir/authorized_keys"
        chmod 700 "$user_ssh_dir"
        chmod 600 "$user_ssh_dir/authorized_keys"
        chown -R "$username:$username" "$user_dir"
        echo "Added SSH key for user: $username." | tee -a "$LOG_FILE"
      else
        log_warning "Password for user $username does not comply with the policy. Skipping user creation."
      fi
    fi
  done < "$file"
  log_success "Completed creating users from file."
}

# Configure user session timeout
function configure_session_timeout() {
  echo_yellow "Configuring user session timeout..."
  SESSION_TIMEOUT=600
  echo "TMOUT=$SESSION_TIMEOUT" >> /etc/profile
  echo "readonly TMOUT" >> /etc/profile
  echo "export TMOUT" >> /etc/profile
  log_success "User session timeout configured."
}

# Audit and disable unnecessary services
function audit_and_disable_services() {
  echo_yellow "Auditing and disabling unnecessary services..."
  for service in "${unnecessary_services[@]}"; do
    if systemctl is-enabled "$service" >/dev/null 2>&1; then
      systemctl disable "$service" >/dev/null 2>&1
      systemctl stop "$service"
      echo "Disabled service: $service" | tee -a "$LOG_FILE"
    fi
  done

  log_success "Completed auditing and disabling services."
}

# Configure SSH
function configure_ssh() {
  echo_yellow "Configuring SSH..."

  # Backup configuration file
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F-%T)

  # Configure banner
  if ! grep -q "^Banner /etc/ssh/banner" /etc/ssh/sshd_config; then
    echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
  else
    sed -i 's|^Banner.*|Banner /etc/ssh/banner|' /etc/ssh/sshd_config
  fi

  # Create banner file
  cat <<EOL > /etc/ssh/banner
*************************WARNING***********************************************************
This computer system is the property of the Prajwal Organization. It is for authorized use only.
By using this system, all users acknowledge notice of, and agree to comply with,
the Organization's Acceptable Use of Information Technology Resources Policy.
Unauthorized or improper use of this system may result in administrative disciplinary action,
civil charges/criminal penalties, and/or other sanctions as set forth in the policy.
By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.
LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this warning.
*******************************************************************************************
EOL

  # Update parameters in sshd_config
  sed -i '/^#\?PermitUserEnvironment /c\PermitUserEnvironment no' /etc/ssh/sshd_config
  sed -i '/^#\?ClientAliveInterval /c\ClientAliveInterval 900' /etc/ssh/sshd_config
  sed -i '/^#\?ClientAliveCountMax /c\ClientAliveCountMax 0' /etc/ssh/sshd_config

  systemctl restart sshd
  if [[ $? -eq 0 ]]; then
    log_success "SSH configured successfully."
  else
    log_error "Failed to configure SSH."
  fi
}

# Disable Ctrl+Alt+Del
function disable_ctrl_alt_del() {
  echo_yellow "Disabling Ctrl+Alt+Del key sequence..."
  systemctl mask ctrl-alt-del.target
  systemctl daemon-reload
  log_success "Ctrl+Alt+Del key sequence disabled."
}

# Install and configure auditd
function setup_auditd_rules() {
  echo_yellow "Installing and configuring auditd..."
  apt install auditd audispd-plugins -y >/dev/null 2>&1

  # Create auditd rules file
  cat <<EOL > /etc/audit/rules.d/audit.rules
# Custom audit rules
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
EOL

  augenrules --load
  service auditd restart
  if [[ $? -eq 0 ]]; then
    log_success "auditd configured successfully."
  else
    log_error "Failed to configure auditd."
  fi
}

# Main function
function main() {
  check_root_user
  verify_os_version
  update_system_packages
  configure_file_security
  install_and_configure_chrony
  configure_sysctl_security
  setup_auditd_rules
  disable_root_ssh_login
  disable_ctrl_alt_del
  configure_ssh
  configure_password_policy
  configure_sudo_permissions
  check_users_with_uid_zero
  disable_unnecessary_users
  list_users_without_password
  configure_session_timeout
  audit_and_disable_services
  create_users_from_file "$FILE_USER_IT"
}

# Run main function
main
