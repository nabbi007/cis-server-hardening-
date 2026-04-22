# Server Hardening Runbook
## Ubuntu 24.04 LTS — CIS Level 1

**Author:** Nabbi (Illiasu)  
**Date:** April 2026  
**Environment:** AWS EC2 t2.micro, Ubuntu 24.04.4 LTS  
**Purpose:** Production-grade server hardening from scratch

---

## Prerequisites
- Ubuntu 24.04 EC2 instance running
- SSH access via key pair
- Non-root user with sudo privileges

---

## 1. Baseline Setup

### Update the system
```bash
sudo apt update && sudo apt upgrade -y
```
**Why:** Never harden a stale system. Patch first, harden second.

### Set hostname
```bash
sudo hostnamectl set-hostname app-01
```
**Why:** Every log entry references the hostname. Named servers
make forensic investigation and log analysis readable.

### Create named admin user
```bash
sudo adduser nabbi
sudo usermod -aG sudo nabbi
```
**Why:** Never work as the default ubuntu user. Named users
mean every action in logs and audit records is traceable
to a specific person.

---

## 2. CIS Level 1 Hardening

### Lock root account
```bash
sudo passwd -l root
```
**Verify:**
```bash
sudo passwd -S root
# Expected: root L ...
```
**Why:** Eliminates root as an authentication target.
Root still exists for processes but cannot be logged into directly.

### Disable root SSH login
Edit /etc/ssh/sshd_config:
```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
```
```bash
sudo systemctl restart sshd
```
**Verify:**
```bash
sudo sshd -T | grep -E "permitrootlogin|passwordauthentication"
```
**Why:** Two independent layers blocking root access.
passwd -l blocks at OS level, PermitRootLogin no blocks at SSH level.

### Restrict su to wheel group
```bash
sudo groupadd wheel
sudo usermod -aG wheel nabbi
sudo nano /etc/pam.d/su
# Uncomment: auth required pam_wheel.so use_uid
```
**Why:** Without this any compromised user account can attempt
su - root. Restricting su to wheel limits blast radius of
a compromised account.

### Lock down /tmp
Add to /etc/fstab:
```
tmpfs   /tmp   tmpfs   defaults,noexec,nosuid,nodev   0 0
```
```bash
sudo mount -o remount /tmp
```
**Verify:**
```bash
mount | grep /tmp
# Expected: noexec, nosuid, nodev
```
**Why:** /tmp is world-writable. noexec prevents attackers
from writing and executing malicious binaries there.

---

## 3. UFW Firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
```
**Verify:**
```bash
sudo ufw status verbose
```
**Why:** Default deny means your attack surface is exactly
your ruleset — nothing more. Every open port is a conscious
decision not a default.

---

## 4. Fail2ban

```bash
sudo apt install fail2ban -y
sudo nano /etc/fail2ban/jail.local
```
Config:
```ini
[DEFAULT]
bantime  = 86400
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400
```
**Verify:**
```bash
sudo fail2ban-client status sshd
```
**Why:** Automated IP banning after 3 failed SSH attempts
within 10 minutes. Makes brute force attacks impractical.

---

## 5. Auditd

```bash
sudo apt install auditd audispd-plugins -y
```
Rules in /etc/audit/rules.d/hardening.rules — 19 rules covering:
- Identity changes (passwd, shadow, group)
- Privilege escalation (sudo, su)
- Sudoers modifications
- SSH config changes
- User management commands
- Cron modifications
- Login events

**Verify:**
```bash
sudo auditctl -l
# Expected: 19 rules listed
```
**Why:** Kernel-level tamper-resistant audit trail. Records
who did what, when, from which session. Essential for
forensic investigation and compliance.

---

## 6. Unattended Upgrades

```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
```
Config in /etc/apt/apt.conf.d/50unattended-upgrades:
- Security patches only
- No automatic reboots
- Email on change
- Remove unused dependencies

**Why:** Security patches applied automatically overnight.
Eliminates the window between patch release and manual application.

---

## 7. Sudoers Hardening

```bash
sudo groupadd admingroup
sudo usermod -aG admingroup nabbi
sudo visudo
```
Settings applied:
- Named admingroup instead of default sudo group
- Full session logging to /var/log/sudo.log
- I/O recording in /var/log/sudo-io
- requiretty — no background sudo execution
- 5 minute credential cache timeout
- 1 minute password timeout

**Verify:**
```bash
sudo cat /var/log/sudo.log
```
**Why:** Every sudo command logged in three independent places —
sudo.log, sudo-io session recordings, and auditd kernel records.
Complete traceability of all privileged actions.

---

## Verification Checklist

Run these after full hardening to confirm everything is in place:

```bash
sudo passwd -S root                          # root locked
sudo sshd -T | grep permitrootlogin         # root SSH disabled
sudo ufw status verbose                      # firewall active
sudo fail2ban-client status sshd            # fail2ban watching
sudo auditctl -l                            # 19 audit rules loaded
cat /var/run/reboot-required 2>/dev/null    # check reboot needed
sudo cat /var/log/sudo.log                  # sudo logging works
```