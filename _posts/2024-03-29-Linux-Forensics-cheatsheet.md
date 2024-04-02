---
title:  "Cheatsheet: Linux Forensics Analysis"
tags: 
- DFIR
- Cheatsheet
---

Linux Forensic in a nutshell:
1. Validate compromised
      - Interviewing client/user/administrator (what, why, how, when, where, who?)
      - Live response commands / Run triage scripts
2. Collect evidence
      - Live response triage script collection
      - Disk image
      - Memory dump
3. Investigation and analysis
      - Live response analysis
      - Disk analysis
      - Timeline analysis
      - Log analysis
      - Memory analysis
4. Reporting

# Validate compromised
To validate compromise, we often will collect as much information as we can from the client. Then we proceed with the investigation to validate the compromised. I will often run a few commands or execute a triage script to collect live response command results using a single script.

Validation sometimes easy:
- Defaced web pages
- IDS/EDR/AV/SIEM captures
- Ransomware file encrypted

## Interviewing client/user/administrator
Understanding the incident with questions like this:
- What happened?
- What seemed unusual?
- When did you notice it?
- Which host involved
- What's the purpose of the system
- Who has access to them?
- How are these systems set up?
- What have you done to fix it?

## Linux-CatScale: Live response and triage script
For more information about what the script collects, please refer to https://labs.withsecure.com/tools/cat-scale-linux-incident-response-collection.
```
git clone https://github.com/WithSecureLabs/LinuxCatScale.git
cd LinuxCatScale
./Cat-Scale.sh
./Extract-Cat-Scale.sh
```
After running the script and extract the collected evidence, we can proceed investigate the triage data in text editor such as VS Code. Figure below shows the result of command `lastlog` collect by Linux-CatScale.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/8669bd9a-9971-4213-b06a-fb40a8f2e89a)

## Live response commands
These commands can be used to review anomalous behavior and verify compromise in real-time action. Some of the commands, such as `cat /var/www/html/webshell.php`, can also be used to perform post-compromise disk analysis, where we only need to supply the full path of the mounted compromised disk, for example, `cat /media/compromised_disk/var/www/html/webshell.php`.

### General information
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

# Date of installation of the OS. Check the date
ls -ld /var/log/installer
```

### Logon activities
Then, we proceed to review the logon activities of the compromised host.
```
# Check users who are currently logged in
w

# Last login information for all users. It reads the /var/log/lastlog file
lastlog
cat /var/log/lastlog

# List of last logged in users and their login times
last -f /var/log/wtmp

# Failed login attempts
last -f /var/log/btmp

# Searching for login activities in auth.log with specific keyword
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i user
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i Accepted
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i failed
grep -v cron /var/log/auth.log* | grep -v sudo | grep i "login:session"

# CentOS, Red Hat Enterprise Linux (RHEL) of auth.log
cat /var/log/secure
```
 
### Review processes
Review all running processes and its command could identify malicious process
```
# Interactive process viewer
htop

# Currently running processes and its command
ps -aux

# List all open files associated with a specific process
lsof -p <PID>

# Directories that contains information about a specific process
ls /proc/<PID>
cat /proc/<PID>
```

| File/Directory in /proc/PID | Description |
|----------------|-----------------------------------------------------------|
| cmdline        | Command-line arguments passed to the process              |
| cwd            | Symbolic link to the current working directory of the process |
| exe            | Symbolic link to the executable file of the process       |
| fd             | Directory containing symbolic links to open file descriptors used by the process |
| status         | Various status information about the process               |
| mem            | Represents the process's memory space                      |
| cpuinfo        | CPU-related information for the process                    |
| maps           | Memory maps of the process                                 |
| limits         | Resource limits imposed on the process                     |
| io             | I/O statistics for the process                             |
| stat           | Various statistics about the process                       |
| sched          | Scheduling information for the process                     |
| syscall        | Information about system calls made by the process         |
| oom_score      | OOM (Out-Of-Memory) score of the process                   |


### Recover deleted process's binary
This method attempts to recover the binary executable from the process's memory by extracting a portion of the memory associated with the process. 
```
cd /proc/1234/

# maps contains memory maps of the process, showing the memory regions used by the process
head -1 maps

# Extract memory content (1000 bytes) at specified ADDRESS to tmp directory
dd if=mem bs=1 skip=ADDRESS count=1000 of=/tmp/recovered_proc_file
```

### Review network
Investigate any malicious connection and unexpected IP address
```
#  List all TCP and UDP connections on your system along with their respective listening and non-listening sockets
netstat -antup

# kernel routing table
netstat -rn
route

# Maps IP addresses to hostnames
cat /etc/hosts
```

### Review activities
Investigate the executed command by the attacker and user could give nice context about the incident
```
# Check command history 
history

# Check all files with "history" in their name in the user's home directory
cat /home/$USER/.*_history

# Check the command history  (specific to bash shell)
cat /home/$USER/.bash_history

# Check the command history for the root user (specific to bash shell)
cat /root/.bash_history

# Check the MySQL command history for the root user
cat /root/.mysql_history

# Check the FTP command history 
cat /home/$USER/.ftp_history

# Check the SFTP command history 
cat /home/$USER/.sftp_history

# Check the VIM editor history 
cat /home/$USER/.viminfo

# Check the history of commands entered in the 'less' pager 
cat /home/$USER/.lesshst

# Check the Git configuration 
cat /home/$USER/.gitconfig

# List recent Git activity logs 
ls /home/$USER/.git/logs

# List Mozilla Firefox profiles, check history and downloads
ls /home/$USER/.mozilla/firefox

# List Google Chrome profiles, check history and downloads
ls /home/$USER/.config/google-chrome

# Search for relevant commands in the authentication logs excluding cron jobs
grep -v cron /var/log/auth.log* | grep -i -e "command=" -e "su:" -e "groupadd" -e "useradd" -e "passwd"
```

### Hunting unusual files
```
# Search for files modified within the last 5 days and Check them for further inspection, change 5 if needed
find / -type f -mtime -5 | less

# Search for files modified within the last 5 days with "php" in their name and Check them for further inspection
find / -type f -mtime -5 | grep "php"

# Find files modified in the last 10 days in specified directories and Check them
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"

# Find files modified within the last day and print their paths
find / -type f -mtime -1 -print

# Search for files larger than 10,000 kilobytes and print their paths
find / -size +10000k -print

# List files in /usr/bin directory with their inode numbers and sort them numerically
ls -lai /usr/bin | sort -n

# List files in /bin directory recursively, sorted by modification time
ls -laR --sort=time /bin

# Find files owned by root with the setuid or setgid permissions and print their paths
find / -user root -perm -04000 -print

# List all devices in the /dev directory
ls /dev
```

### Installed programs
```
# Examine commands used for package installations from the APT history log for tracking software changes
cat /var/log/apt/history.log | grep "Commandline"

# Retrieve package names and their statuses from the dpkg status file for software inventory analysis
cat /var/lib/dpkg/status | grep -E "Package:|Status:"

# Review entries from the dpkg log file indicating installed packages for change analysis
cat /var/log/dpkg.log | grep installed

# Identify executables in the /sbin directory and determine their package ownership using dpkg for attribution
find /sbin/ -exec dpkg -S {} \; | grep "no path found"

# List executables in standard system directories for anomaly detection
ls /usr/sbin /usr/bin /bin /sbin

# List files in the APT package cache directory for investigating downloaded packages
ls /var/cache/apt/archives

```

### File investigation
```
# Collect detailed metadata about the file for forensic analysis
stat <filename>

# Identify the file type and format to understand its nature
file <filename>

# Extract human-readable strings from the file for potential clues or analysis
strings <filename>

# Generate an MD5 checksum of the file to verify integrity and check against known malware signatures
md5sum <filename> # submit to VT
```

### Persistent mechanisms
Persistent mechanism is a methods used by attackers to maintain access to a compromised system across reboots or to ensure their malicious activities persist over time. Below is the potential list of the places attacker might add or modify to deploy their persistent access.

#### Review account
Review user account information and activity on the system to iidentify potentially active user accounts, detect anomalies in user account configurations, find files belonging to non-existent users, extract password hashes for analysis, examine group information for privilege analysis, review sudo configurations for potential privilege escalation, investigate SSH authentication keys and known hosts for unauthorized access, and analyze recently used files for user activity.

```
# Identify potentially active user accounts
cat /etc/passwd | grep bash

# Sort user accounts by their UID to detect anomalies
sort -nk3 -t: /etc/passwd

# Find files belonging to non-existent users (indicators of unauthorized access)
find / -nouser -print

# Extract password hashes for forensic analysis
cat /etc/shadow

# Examine group information for user privilege analysis
cat /etc/group

# Review sudo configuration for potential privilege escalation
cat /etc/sudoers

# Check for additional sudo configurations for backdoors
cat /etc/sudoers.d/*

# Investigate SSH authentication keys for potential unauthorized access
cat /home/$USER/.ssh/authorized_keys

# Analyze SSH known hosts for suspicious connections
cat /home/$USER/.ssh/known_hosts

# Review recently used files for user activity
cat /home/$USER/.recently-used.xbel
```

#### Webshell
Identifying potential webshell installations or modifications
```
# Search for PHP files in the /var/www/html directory and print their modification timestamps
find /var/www/html -type f -name "*.php" -printf "%T@ %f\n" | sort -n | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1), $2}'

# Monitor Apache configuration files
tail -f /etc/apache2/*/*

# Monitor Nginx configuration files
tail -f /etc/nginx/*/*
```

#### Cron tasks
Identify any scheduled tasks or suspicious activities that may have been configured to execute at specific times
```
# View the configuration of the cron service managed by systemd
cat /lib/systemd/system/cron.service

# View the cron tasks scheduled for a specific user
crontab –u <user> -l

# View the system-wide crontab file containing system cron tasks
cat /etc/crontab

# Check all files in /etc/cron
tail -f /etc/cron.*/*

# List all user-specific cron files in the cron spool directory
ls /var/spool/cron/crontabs/*

# View the contents of the atjobs file, which contains at jobs scheduled by the at command
cat /var/spool/cron/atjobs
```

#### Services and systemd
Examine systemd configurations and unit files on the system to identify any modifications or suspicious configurations that may have been made to services or startup processes.
```
# List enabled services and Check their associated start commands
for service in $(systemctl list-unit-files --type=service | grep enabled | awk '{print $1}'); do echo "Service: $service"; systemctl cat $service | grep ExecStart= | sed 's/^/Command: /'; echo "--------------------------------------------------"; done

# List custom systemd unit files in /etc/systemd/system/
ls /etc/systemd/system/

# List systemd unit files in /lib/systemd/system/
ls /lib/systemd/system/

# List systemd system generators
ls /lib/systemd/system-generators/*

# View contents of init.d scripts
more -f /etc/init.d/*

# List systemd user units in /lib/systemd/user/
ls /lib/systemd/user/*

# List custom systemd user units in /etc/systemd/user/
ls /etc/systemd/user/*

# List user systemd generators in /etc/systemd/user-generators/
ls /etc/systemd/user-generators/*

# List user systemd generators in /usr/local/lib/systemd/user-generators/
ls /usr/local/lib/systemd/user-generators/*

# List user systemd generators in /usr/lib/systemd/user-generators/
ls /usr/lib/systemd/user-generators/*
```

#### SSH Daemon
Examine the configuration of the SSH daemon and related resource files
```
# View the SSH service configuration managed by systemd
cat /lib/systemd/system/ssh.service

# View the SSH daemon configuration file
cat /etc/ssh/sshd_config

# List any user-specific SSH resource files in the ~/.ssh directory
ls ~/.ssh/rc

# List system-wide SSH resource files in the /etc/ssh directory
ls /etc/ssh/sshrc
```

#### Login Shell
Examine login shell configurations and scripts responsible for system initialization and startup processes.
```
# Check system-wide Bash initialization file
cat /etc/bash.bashrc

# Check user-specific Bash initialization file
cat /home/$USER/.bashrc

# Check user-specific Bash profile file
cat /home/$USER/.bash_profile

# Check system-wide profile file
cat /etc/profile

# Check scripts in the /etc/profile.d directory
cat /etc/profile.d/*

# Check user-specific profile file
cat /home/$USER/.profile

# Check user-specific Bash login file
cat /home/$USER/.bash_login

# Check user-specific Bash logout file
cat /home/$USER/.bash_logout

# Check system-wide Bash logout file
cat /etc/.bash_logout
```

#### rc scripts
RC scripts responsible for system initialization and startup processes.
```
# Review rc scripts
cat /etc/rc*
```

#### Infected binaries
Uncover recently modified files that may indicate unauthorized activity or compromise.
```
# Find binaries modified within the last 10 days in specified directories
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"

# List Python 3 related libraries and modules in /usr/lib directory
ls /usr/lib/python3*
```

#### PAM
```
# Display contents of the PAM configuration file
cat /etc/pam.conf

# Check contents of the PAM directory
cat /etc/pam.d
```

#### MOTD
"motd" stands for "message of the day". These scripts may contain important system status updates, notifications, or potentially malicious content inserted by attackers. 
```
# Examine the scripts responsible for generating dynamic messages displayed to users upon login
cat /etc/update-motd.d/*
```

### Unusual system resources
These commands provide information about system uptime, memory usage, and disk space usage, which can help identify abnormal behavior such as high resource consumption, potential denial of service attacks, or disk space exhaustion. 
```
# Display system uptime and load average
uptime

# Display memory usage statistics
free

# Display disk space usage statistics
df
```

## Compromised assestment scanning
Using a CA scanner with the capability of YARA and SIGMA detection significantly speeds up our hunt for malicious and suspicious files in compromised systems. Running this scanner can save a considerable amount of time and proves to be invaluable during DFIR investigations.

### THOR Lite
THOR is a portable scanner to detect attacker tools and activity on suspicious or compromised server systems. We can use this free tool to scan our compromised hosts.

Download: https://www.nextron-systems.com/thor-lite/
![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/d8f13e66-351f-450a-a5d6-774423a5045c)

Extract the zip files and copy the license file into the extracted folder.

```
# Download Thor Lite and the license from Nextron website
cd thorlite/
./thor-lite-util update
./thor-lite-linux-64
```

## Hunting rootkit
### To hunt via 3rd party software
```
# Detect rootkits on Linux systems
chkrootkit

# Detect rootkits on Linux systems
rkhunter --check

# Comprehensive security auditing tool that includes checks for rootkits among other security issues:
lynis audit system

# Antivirus scanner for malware
clamscan -r /
```

### Hunting and check files, processes
```
# Inspect dir and files
find /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec ls -la {} \;

# Check running process with root priv
ps aux | grep -i root

# Check unusual network connections
netstat -antup

# Compare checksums or file hashes against known good values
sha256sum /bin/* /sbin/* /usr/bin/* /usr/sbin/* /lib/* /lib64/* /etc/* | sort > current_checksums.txt
```

### Investigate loaded kernel modules
```
user@training:~$ lsmod
Module                  Size  Used by
tls                   114688  0
lime                   16384  0
cpuid                  16384  0
vboxsf                 36864  1
binfmt_misc            24576  1
intel_rapl_msr         20480  0
intel_rapl_common      40960  1 intel_rapl_msr
intel_powerclamp       24576  0
rapl                   20480  0
snd_intel8x0           45056  0
input_leds             16384  0
serio_raw              20480  0
joydev                 32768  0
snd_ac97_codec        180224  1 snd_intel8x0
ac97_bus               16384  1 snd_ac97_codec
snd_pcm               143360  2 snd_intel8x0,snd_ac97_codec
snd_timer              40960  1 snd_pcm
```
1. The first column lists the module names (tls, lime, etc.).
2. The second column shows the size of each module.
3. The third column (Used by) indicates which other modules are using the listed module.

To identify whether a loaded kernel module or its dependencies are part of a rootkit or not, we may want to try this methods:
- Compare the list of loaded kernel modules (lsmod output) against a known good baseline.
- Look for modules that have suspicious names, sizes, or descriptions.
- Investigate the modules listed under the "Used by" column.
- Research any unfamiliar or suspicious modules online.

To get detailed information about a specific module:
```
modinfo <name of module>
```

Review configuration files that control module loading.
```
tail -f /etc/modprobe.d/*
```

# Collect evidences
We have completed the collection of live response data and triage scripts, saving all results for further analysis alongside disk and memory analysis. At this stage, it's imperative to gather disk and memory dumps to conduct a comprehensive and in-depth investigation. These disk and memory dumps will provide critical insights into the state of the system, allowing us to identify any anomalies or malicious activity that may have occurred.

## Disk imaging using dd
Collecting digital disk image of the Linux system is essential to perform disk analysis offline. This activity is required to find any suspicious files and folders, recover files and to extract artifacts (triage) from the disk.
```
# List all devices to identify the disk device for disk imaging
lsblk

# List partition tables for disk devices
fdisk -l

# Perform disk imaging to an external disk or shared folder
# Replace "sdb" with the appropriate disk device identifier
dd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img

# Alternatively, use dcfldd to perform hashing while imaging
dcfldd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img hash=sha256 hashwindow=1M hashlog=/media/sf_tmp/linux_forensic.hash
```

## Memory acquisition
Memory acquisition and memory analysis is quite bit rare in Linux forensics as most of the analyst rely on live response actions and commands. To perform memory acquisition, we going to use LIME.
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

# Investigation and analysis
After we have collected all the crucial evidence, we then can proceed with the investigation and analysis of the triage evidence.

## Live response and triage script analysis
Based on the scripts and live command results, proceed with the investigation using a text editor such as VS Code. If the data is in CSV format, consider using tools like Timeline Explorer for better visualization and analysis.

## Memory analysis with Volatility
First, install volatility first in your forensic lab.
```
sudo git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
apt install python3-pip
pip3 install -r requirements-minimal.txt
python3 vol.py -f /media/sf_tmp/mem.lime banners
```

Then we need to build Linux volatility profile in order to use Volatility for memory forensic.
```
TODO
```

## Disk analysis
Analyst can perform disk analyst using:
1. Autopsy
2. FTK Imager
3. Linux distro such as Tsurugi, SIFT or REMNUX (Need to mount the disk image first)

### Directories and Files Analysis
```
TODO
```
### Log analysis
Tool such as SIEM, or CA scanner could speed up analysis of the log analysis. Tool named `goaccess` can be use against access.log

| Log File                  | Purpose of Analysis                                      |
|---------------------------|----------------------------------------------------------|
| /var/log/syslog           | Analyze system events, errors, and warnings              |
| /var/log/kern.log         | Investigate kernel-level events and errors               |
| /var/log/dmesg            | Examine kernel ring buffer for boot-time messages        |
| /var/logs/apache2/access.log* | Analyze web server access logs for activity and requests |
| /var/log/httpd/           | Investigate HTTP server logs for web activity            |
| /var/log/mysqld.log       | Review MySQL server logs for database activity           |
| /var/log/mysql.log        | Examine MySQL logs for queries and errors                |
| /var/log/cron             | Analyze cron job execution and scheduling                |
| /var/log/daemon.log       | Investigate daemon-related events and errors             |
| /var/log/auth.log         | Review authentication events and login attempts          |
| /var/log/secure           | Examine secure authentication logs (usually for SSH)     |
| /var/log/mail*            | Analyze mail server logs for email activity              |
| /var/log/xferlog          | Investigate FTP server logs for file transfer activity   |


### File recovery
Using sleauth kit
```
tsk_recover -h
tsk_recover -i raw -e image.dd <location>
```

Using debugfs
```
TODO
```

Using ext4magic
```
TODO
```

### Timeline analysis
```
TODO
```
