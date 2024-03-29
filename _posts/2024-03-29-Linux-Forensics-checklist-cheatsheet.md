---
title:  "Checklist and Cheatsheet: Linux Forensics Analysis"
tags: DFIR
---

Linux can be hack as large numbers of web and DB servers run under Linux OS. In this Checklist and Cheatsheet, I'll list all possible approach to response against Linux machine that have been compromised.

# Live Response
Oftenly review for anomalous behaviour and to verify compromised.

## General
```
date
uname -a
hostname
ifconfig -a
cat /etc/lsb-release
cat /var/log/kern.log | grep -i "Linux version"
```

## Logon activities
```
w
lastlog
last -f /var/log/wtmp
last -f /var/log/btmp
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i user
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i Accepted
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i failed
grep -v cron /var/log/auth.log* | grep -v sudo | grep i "login:session"
cat /var/log/secure
last -Faiwx
```
 
## Review processes
```
htop
ps -aux
lsof -p <PID>
ls /proc/<PID>
cat /proc/<PID>
```

## Review network
```
netstat -antup
netstat -rn
route
cat /etc/hosts
cat /
```

## Review activities
```
history
cat /home/$USER/.history
cat /root/.history
grep -v cron /var/log/auth.log* | grep -i -e "command=" -e "su:" -e "groupadd" -e "useradd" -e "passwd"
```

## Hunting unusual files
```
find / -type f -mtime -5 | less
find / -type f -mtime -5 | grep "php"
find / -size +10000k –print
ls -lai /usr/bin | sort -n
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"
find / -type f -mtime -1 -print
```

## Persistent
### Review account
```
cat /etc/passwd | grep bash
sort -nk3 -t: /etc/passwd
find / -nouser -print
cat /etc/shadow
cat /etc/groups
cat /etc/sudoers
cat /etc/sudoers.d/
cat /home/$USER/authorized_keys
```

### Webshell
```
find /var/www/html -type f -name "*.php" -printf "%T@ %f\n" | sort -n | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1), $2}'
tail -f /etc/apache2/*/*
tail -f /etc/nginx/*/*
```

### Cron tasks
```
cat /lib/systemd/system/cron.service
crontab –u <user> -l
cat /etc/crontab
tail -f /etc/cron.*/*
ls /var/spool/cron/crontabs/*
cat /var/spool/cron/atjobs
```

### Services and systemd
```
for service in $(systemctl list-unit-files --type=service | grep enabled | awk '{print $1}'); do echo "Service: $service"; systemctl cat $service | grep ExecStart= | sed 's/^/Command: /'; echo "--------------------------------------------------"; done
ls /etc/systemd/system/
ls /lib/systemd/system/
ls /lib/systemd/system-generators/*
more -f /etc/init.d/*
ls /lib/systemd/user/*
ls /etc/systemd/user/*
ls /etc/systemd/user-generators/*
ls /usr/local/lib/systemd/user-generators/*
ls /usr/lib/systemd/user-generators/*
```

### SSH Daemon
```
cat /lib/systemd/system/ssh.service
cat /etc/ssh/sshd_config
ls ~/.ssh/rc
ls /etc/ssh/sshrc
```

### Login Shell
```
cat /etc/bash.bashrc
cat /home/$USER/.bashrc
cat /home/$USER/.bash_profile
cat /etc/profile
cat /etc/profile.d/*
cat /home/$USER/.profile
cat /home/$USER/.bash_login
cat /home/$USER/.bash_logout
cat /etc/.bash_logout
```

### rc scripts
```
/etc/rc*
```

### Infected binaries
```
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"
ls /usr/lib/python3*
```

### PAM
```
cat /etc/pam.conf
cat /etc/pam.d
```

### MOTD
```
cat /etc/update-motd.d/*
```

## Unusual system resources
```
uptime
free
df
```

# Triage collection
```
git clone https://github.com/WithSecureLabs/LinuxCatScale.git
cd LinuxCatScale
./Cat-Scale.sh
./Extract-Cat-Scale.sh
```

# Scanner
```
apt install chkrootkit && chkrootkit

# Download Thor Lite and the license from Nextron website
cd thorlite/
./thor-lite-util update
./thor-lite-linux-64
```

# Disk acquisition
```
lsblk
fdisk -l
dd if=/dev/<DISK DEVICE> of=/media/sf_tmp/linux_forensic.img
```

# Memory acquisition
TODO

# Log analysis
### System
```
/var/log/syslog
/var/log/kern.log
/var/log/dmesg
```

### Web
```
/var/logs/apache2/access.log*
/var/log/httpd/
```

### SQL
```
/var/log/mysqld.log
/var/log/mysql.log
/root/.mysql_history
```

### Cron
```
/var/log/cron
```

### Services
```
/var/log/daemon.log
```

### Authentication
```
/var/log/auth.log
/var/log/secure
```

### Mail
```
/var/log/mail*
```

### FTP
```
/var/log/xferlog
```
