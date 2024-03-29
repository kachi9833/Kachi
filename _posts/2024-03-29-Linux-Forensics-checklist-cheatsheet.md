---
title:  "Checklist and Cheatsheet: Linux Forensics Analysis"
tags: DFIR
---

In this Checklist and Cheatsheet, I'll list all possible approach to response against Linux machine that have been compromised by an attacker.

# Disk acquisition and analysis
Analyst collect digital disk image of the Linux system to perform disk analysis offline. This activity is required to find any suspicious files and folders, recover files and to extract artifacts (triage) from the disk

## Disk imaging
```
# Verify which disk device that we want to perform the disk imaging
lsblk
fdisk -l

# Perform disk imaging into the external disk or shared folder
# Change "sdb" to your disk device letter
dd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img
# OR
dcfldd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img hash=sha256 hashwindow=1M hashlog=/media/sf_tmp/linux_forensic.hash
```

## Disk analysis
Analyst can perform disk analyst using:
1. Autopsy
2. FTK Imager
3. Linux distro such as Tsurugi, SIFT or REMNUX (Need to mount the disk image first)

# Memory acquisition and analysis
Memory acquisition and memory analysis is quite bit rare in Linux forensics as most of the analyst rely on live response actions and commands. To perform memory acquisition, we going to use LIME.

## Memory acquisition using LIME
```
# In the target machine, run this command to verify the kernel version
uname -r

# Using other machine with the same kernel version, git clone, and compile the source. It will generate .ko file.
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src; sudo make

# Copy the .ko file into the target machine using SCP or Netcat

# In the target machine, run this command to generate memory dump
sudo insmod lime-$(uname -r).ko "path=/media/sf_tmp/mem.lime format=lime"
```

## Memory analysis with Volatility
```
# Install volatility
sudo git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
apt install python3-pip
pip3 install -r requirements-minimal.txt
python3 vol.py -f /media/sf_tmp/mem.lime banners

# Build Linux profile
TODO
```

# Triage collection
Collect important triage files for quick investigation
```
git clone https://github.com/WithSecureLabs/LinuxCatScale.git
cd LinuxCatScale
./Cat-Scale.sh
./Extract-Cat-Scale.sh
```

# Live response commands
These commands oftenly used to review for anomalous behaviour and to verify compromised.

## General information
The first thing we are going to do is collect important information regarding the server that we will analyze.
```
# Display current date and time. Verify the timezone.
date

# System information
uname -a

# Network information
ifconfig

# Display distro version
cat /etc/*-release

# Date of installation of the OS
ls -ld /var/log/installer
```

## Logon activities
Then, we proceed to review the logon activities of the compromised host.
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
Review all running processes and its command could identify malicious process
```
htop
ps -aux
lsof -p <PID>
ls /proc/<PID>
cat /proc/<PID>

# Recover deleted process's binary
cd /proc/1234/
head -1 maps
dd if=mem bs=1 skip=ADDRESS count=1000 of=/tmp/recovered_proc_file
```

## Review network
Investigate any malicious connection and unexpected IP address
```
netstat -antup
netstat -rn
route
cat /etc/hosts
cat /
```

## Review activities
Investigate the executed command by the attacker and user could give nice context about the incident
```
history
cat /home/$USER/.*_history
cat /home/$USER/.bash_history
cat /root/.bash_history
grep -v cron /var/log/auth.log* | grep -i -e "command=" -e "su:" -e "groupadd" -e "useradd" -e "passwd"
cat /root/.mysql_history
ls /home/$USER/.mozilla/firefox 
ls /home/$USER/.config/google-chrome
cat /home/$USER/.viminfo
cat /home/$USER/.ftp_history
cat /home/$USER/.sftp_history
cat /home/$USER/.lesshst
cat /home/$USER/.gitconfig
ls /home/$USER/.git/logs
```

## Hunting unusual files
```
find / -type f -mtime -5 | less
find / -type f -mtime -5 | grep "php"
find / -size +10000k –print
ls -lai /usr/bin | sort -n
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"
find / -type f -mtime -1 -print
ls -laR --sort=time /bin
find / -user root -perm -04000 -print
ls /dev
```

## Installed programs
```
cat /var/log/apt/history.log | grep "Commandline"
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
ls /usr/sbin /usr/bin /bin /sbin
ls /var/cache/apt/archives
```

## File investigation
```
stat <filename>
file <filename>
strings <filename>
md5sum <filename> # submit to VT
```

## Persistent mechanisms
### Review account
```
cat /etc/passwd | grep bash
sort -nk3 -t: /etc/passwd
find / -nouser -print
cat /etc/shadow
cat /etc/groups
cat /etc/sudoers
cat /etc/sudoers.d/
cat /home/$USER/.ssh/authorized_keys
cat /home/$USER/.ssh/known_hosts
cat /home/$USER/.recently-used.xbel 
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

# Compromised assestment scanning
```
# Download Thor Lite and the license from Nextron website
cd thorlite/
./thor-lite-util update
./thor-lite-linux-64
```

# Log analysis
Tool such as SIEM, or CA scanner could speed up analysis of the log analysis
```
# System log
/var/log/syslog
/var/log/kern.log
/var/log/dmesg

# Web
# Analyze the web based on attack, CVE, exploit context
/var/logs/apache2/access.log* # Try using goaccess
/var/log/httpd/

# SQL
/var/log/mysqld.log
/var/log/mysql.log

# Cron
/var/log/cron

# Services
/var/log/daemon.log

# Authentication
/var/log/auth.log
/var/log/secure

#Mail
/var/log/mail*

# FTP
/var/log/xferlog
```

# File recovery
TODO

# Hunting rootkit
TODO
```
apt install chkrootkit && chkrootkit
```

# Timeline analysis
TODO
