# Ubuntu 24.04 Server Hardening — CIS Level 1

A documented, step-by-step implementation of production-grade 
security hardening on Ubuntu 24.04 LTS running on AWS EC2.

## Overview
This project covers manual CIS Level 1 hardening of a fresh 
Ubuntu 24.04 EC2 instance, simulating how a sysadmin would 
lock down a production server from scratch.

## Environment
- OS: Ubuntu 24.04.4 LTS
- Platform: AWS EC2 t2.micro
- Kernel: Linux 6.17.0 AWS

## What Was Implemented
- CIS Level 1 hardening (root lockdown, /tmp restrictions, sysctl)
- SSH hardening (key-only auth, root disabled, MaxAuthTries)
- UFW firewall (default deny, explicit allow rules)
- Fail2ban (SSH brute force protection, 24hr bans)
- Auditd (kernel-level audit logging, 19 custom rules)
- Unattended upgrades (automatic security patching)
- Sudoers hardening (admin groups, full session logging)

## Structure
- docs/hardening-runbook.md — full step by step implementation guide
- docs/checklist.md — quick reference hardening checklist
- scripts/harden.sh — automation script (Phase 3)

## Skills Demonstrated
- Linux security internals
- Access control and privilege management  
- Kernel-level audit logging
- Host-based firewall configuration
- Intrusion prevention
- Technical runbook writing# Ubuntu 24.04 Server Hardening — CIS Level 1

A documented, step-by-step implementation of production-grade 
security hardening on Ubuntu 24.04 LTS running on AWS EC2.

## Overview
This project covers manual CIS Level 1 hardening of a fresh 
Ubuntu 24.04 EC2 instance, simulating how a sysadmin would 
lock down a production server from scratch.

## Environment
- OS: Ubuntu 24.04.4 LTS
- Platform: AWS EC2 t2.micro
- Kernel: Linux 6.17.0 AWS

## What Was Implemented
- CIS Level 1 hardening (root lockdown, /tmp restrictions, sysctl)
- SSH hardening (key-only auth, root disabled, MaxAuthTries)
- UFW firewall (default deny, explicit allow rules)
- Fail2ban (SSH brute force protection, 24hr bans)
- Auditd (kernel-level audit logging, 19 custom rules)
- Unattended upgrades (automatic security patching)
- Sudoers hardening (admin groups, full session logging)

## Structure
- docs/hardening-runbook.md — full step by step implementation guide
- docs/checklist.md — quick reference hardening checklist
- scripts/harden.sh — automation script (Phase 3)

## Skills Demonstrated
- Linux security internals
- Access control and privilege management  
- Kernel-level audit logging
- Host-based firewall configuration
- Intrusion prevention
- Technical runbook writing