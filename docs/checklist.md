# Server Hardening Checklist
## Ubuntu 24.04 LTS — CIS Level 1

Use this to verify hardening on any new server.

### Baseline
- [ ] System fully patched (apt update && apt upgrade)
- [ ] Hostname set and in /etc/hosts
- [ ] Named admin user created
- [ ] SSH access verified for named user before hardening

### CIS Level 1
- [ ] Root account locked (passwd -S root shows L)
- [ ] Root SSH login disabled
- [ ] Password authentication disabled
- [ ] su restricted to wheel group
- [ ] /tmp mounted noexec,nosuid,nodev
- [ ] Password complexity policy set (pwquality)
- [ ] Password aging set (login.defs)

### Firewall
- [ ] UFW enabled
- [ ] Default deny incoming
- [ ] Only required ports open
- [ ] No unused ports in ruleset

### Fail2ban
- [ ] Installed and running
- [ ] jail.local created (not jail.conf)
- [ ] sshd jail enabled
- [ ] bantime 86400 (24 hours)
- [ ] maxretry 3

### Auditd
- [ ] Installed and running
- [ ] 19 rules loaded (auditctl -l)
- [ ] identity_change rules active
- [ ] privilege_escalation rules active
- [ ] sudoers_change rules active
- [ ] user_mgmt rules active

### Unattended Upgrades
- [ ] Installed and enabled
- [ ] Security patches only (not all updates)
- [ ] Automatic reboot disabled
- [ ] Email notifications configured

### Sudoers
- [ ] admingroup created
- [ ] Named user in admingroup not sudo group
- [ ] sudo.log enabled
- [ ] I/O logging enabled
- [ ] requiretty set
- [ ] timestamp_timeout 5 minutes