"""
Linux Threat Hunt (Python Enhanced)
Author: Charles G. | Auroch Security
Purpose: Enumerate suspicious processes, users, files, and persistence indicators on a Linux host
"""

import os
import pwd
import subprocess
from datetime import datetime

def banner():
    print("=" * 50)
    print("🐍  LINUX THREAT HUNT SCRIPT (Python Enhanced)")
    print("Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("Hostname:", os.uname().nodename)
    print("=" * 50)

def suspicious_processes():
    print("
[+] Suspicious Processes (/tmp, /dev, /var):")
    result = subprocess.getoutput("ps aux | grep -E '/tmp|/dev|/var' | grep -v grep")
    print(result if result else "None found.")

def cron_jobs():
    print("
[+] Cron Jobs (user and system):")
    for user in pwd.getpwall():
        try:
            crons = subprocess.getoutput(f"crontab -u {user.pw_name} -l")
            if crons and "no crontab" not in crons.lower():
                print(f"-- {user.pw_name} --
{crons}")
        except Exception:
            continue
    print("
[System Cron Directories:]")
    print(subprocess.getoutput("ls -al /etc/cron* /var/spool/cron/crontabs 2>/dev/null"))

def hidden_files():
    print("
[+] Hidden Files (/, /home, /tmp):")
    result = subprocess.getoutput("find / /home /tmp -type f -name '.*' 2>/dev/null | head -n 20")
    print(result if result else "None found.")

def outbound_connections():
    print("
[+] Outbound Established Connections:")
    result = subprocess.getoutput("ss -tupna | grep ESTAB")
    print(result if result else "None found.")

def persistence_checks():
    print("
[+] Persistence Mechanisms:")
    if os.path.isfile("/etc/rc.local"):
        print("[rc.local]")
        print(open("/etc/rc.local").read())
    print("
[init.d services:]")
    print(subprocess.getoutput("ls -al /etc/init.d/"))
    print("
[systemd timers:]")
    print(subprocess.getoutput("systemctl list-timers --all 2>/dev/null"))

def uid0_users():
    print("
[+] Non-root UID 0 Users:")
    with open("/etc/passwd") as f:
        for line in f:
            parts = line.split(":")
            if parts[2] == "0" and parts[0] != "root":
                print(f"{parts[0]} has UID 0")

def suid_sgid_files():
    print("
[+] SUID/SGID Files:")
    print(subprocess.getoutput("find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -n 20"))

def recent_changes():
    print("
[+] Recently Modified Files in /etc /var /tmp (last 2 days):")
    print(subprocess.getoutput("find /etc /var /tmp -type f -mtime -2 -ls 2>/dev/null | head -n 20"))

if __name__ == "__main__":
    banner()
    suspicious_processes()
    cron_jobs()
    hidden_files()
    outbound_connections()
    persistence_checks()
    uid0_users()
    suid_sgid_files()
    recent_changes()
    print("
✅ Threat Hunt Complete. Review results manually.")
