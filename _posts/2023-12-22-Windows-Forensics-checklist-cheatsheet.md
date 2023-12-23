---
title:  "Checklist and Cheatsheet: Windows Forensics Analysis"
tags: DFIR
---

During a Windows Forensics engagement, I occasionally find myself forgetting essential tasks or unintentionally skipping analyzing importants artifacts. Therefore, this checklist (along with cheatsheet) could help myself (or readers) and ensure that I adhere to a systematic workflow when conducting Windows Forensics.

# Tools
## Acquire artifact's Tools

| Tools | Description |
| --- | --- |
| FTK Imager | Disk Imaging |
| Magnet RAM Capturer | Generate memory dump |
| KAPE | Triage only selected important artifacts instead of the whole disk image |
| Inquisitor / FastIR | Live analysis triage |
| Mandiant Redline | Collect live and file's data and produce analysis |
| External Hard disk | To store the artifact acquisition |
| Velociraptor's agent and server | Remote forensics framework |
| EDD | Check disk encryption |

## Forensic analysis tools

| Tools | Description |
| --- | --- |
| Arsenal Image Mounter | Mounting image |
| Autopsy / FTK Imager | Disk forensics |
| KAPE | Triage artifact |
| Eric Zimmerman tools | Artifact parser and viewer |
| Regripper | Registry parser |
| Volatility / MemProcFS | Memory analysis tools |
| Event log explorer | Event log viewer |
| Other open/close source tools | - |

## OS / Linux Distros
1. Windows
2. SIFT Linux
3. Tsurugi Linux
4. REMnux

# Acquire artifacts
1. Check disk encryption using EDD
2. Perform disk imaging using FTK Imager
3. Run live analysis collection script such as Inquisitor
4. Perform memory dump activity
5. Execute RedLine script to perform endpoint analysis
6. Save all files in the external harddisk

# Analysis
## Live Forensics
1. Check all the results of the script collection

## Memory analysis
1. Tool used: Volatility, MemProcFS, MemProcFS-Analyzer
2. Check network connection (netstat, netscan)
3. Check process list (pslist, pstree, psscan, cmdline)
4. Check injected process, dll injection (malfind, dlllist)
5. Dump malicious process (dumpfiles --pid PID)
6. Volatilit3 command: `python3 vol.py -f <memdump> <plugin name>`

## Disk analysis
### Mount image
1. Perform KAPE execution on the mounted drive using "KAPE triage" module to extract important artifacts
2. Run malware scanner on the mounted drive (Loki scanner, THOR scanner, AV scanner, Densityscout)
3. Perform data recovery on the mounted drive using Photorec
4. Check any shadow copy, view it in Shadow Explorer

### Autopsy
1. Attach disk in Autopsy
2. Run ingest module "Recent activity" and "Keyword search"
3. Check Data artifacts in Autopsy, record all interesting findings
4. Check file and folder (Access time, and created time)
5. View Timeline Analysis in Autopsy
6. Search any interesting keywords

## Windows event logs analysis
1. Located at `C:\Windows\System32\winevt\Logs`
2. Perform event log scanner
3. Manually view in Event Log Explorer

### Interesting log sources

| Log sources | Context |
| --- | --- |
| Security.evtx | Security-related events |
| System.evtx | Tracks system component events |
| Application.evtx | Logs application-specific events |
| Microsoft-Windows-Sysmon/Operational.evtx | Enhanced process, network, and file monitoring |
| Microsoft-Windows-PowerShell/4Operational.evtx | Records PowerShell activity |
| Microsoft-Windows-Windows Defender/Operational.evtx | Logs Windows Defender events |
| Microsoft-Windows-WMI-Activity/4Operational.evtx | Logs WMI events  |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx | Logs RDP session events |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx | Logs RDP session events |
| Microsoft-Windows-TaskScheduler/Operational.evtx | Logs Task Scheduler events |
| Microsoft-Windows-DNS-Server%4Operational.evtx | Active Directory Server Logs |
| Directory Service.evtx | Active Directory Server Logs |
| File Replication Service.evtx | Active Directory Server Logs |
| %SystemDrive%\inetpub\logs\LogFiles | IIS log |
| %SystemRoot%\System32\LogFiles\HTTPERR | IIS log  |
| %ProgramFiles%\Microsoft\Exchange Server\V15\Logging | Exchange log |
| Panther*.log | Windows setup details |
| RPC Client Access*.log | Exchange Server, if applicable |
| Third party antivirus log | AV logs |

### Event log scanner

| Tools | Commands |
| --- | --- |
| Hayabusa | `hayabusa.exe update-rules` and `hayabusa.exe csv-timeline -d ..\Logs -p verbose -o results.csv` |
| DeepBlueCLI | `.\DeepBlue.ps1 -log security` |
| Chainsaw | `chainsaw.exe hunt evtx_logs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output results` |
| Zircolite | `zircolite_win10.exe --evtx ../Logs` |
| APT-Hunter | `APT-Hunter.exe -p ..\Logs -o Foldername -allreport` |
| EVTXHussar | `EvtxHussar.exe C:\evtx_compromised_machine -o C:\evtxhussar_results` |
| Rhaegal | `rhaegal.exe -lp ..\Logs -rp rules -n 100 -o output.csv` |
    

### Important Security Event IDs

| IDs | Event log | Context |
| --- | --- | --- |
| 4624 | Security | Successful Login |
| 4625 | Security | Failed Login |
| 4634/4647 | Security| User Initiated Logoff/An Account was Logged Off |
| 4648 | Security | A Logon was Attempted Using Explicit Credentials |
| 4662 | Security | An Operation was Performed on an Object |
| 4663 | Security | An Attempt was Made to Access an Object |
| 4672 | Security | Special Logon |
| 4688 | Security | Process Creation |
| 4689 | Security | Process Termination |
| 4697 | Security | Service Installed |
| 4698/4702/4700 | Security | Scheduled Task Created or Updated |
| 4699 | Security | Scheduled Task Deleted |
| 4701 | Security | Scheduled Task Enabled |
| 4702 | Security | Service Removed |
| 4720 | Security | A User Account was Created |
| 4722 | Security | A User Account was Enabled |
| 4723 | Security | An Attempt was Made to Change an Account's Password |
| 4724 | Security | An Attempt was Made to Reset an Account's Password |
| 4725 | Security | A User Account was Disabled |
| 4726 | Security | A User Account was Deleted |
| 4728 | Security | A Member was Added to a Security-Enabled Global Group |
| 4729 | Security | A Member was Removed from a Security-Enabled Global Group |
| 4732 | Security | A Security-Enabled Local Group was Created |
| 4733 | Security | A Security-Enabled Local Group was Changed |
| 4734 | Security | A Security-Enabled Local Group was Deleted |
| 4741 | Security | A Computer Account was Created |
| 4742 | Security | A Computer Account was Changed |
| 4768 | Security | Kerberos Authentication Service Ticket Request |
| 4769 | Security | Kerberos Service Ticket Renewal |
| 4776 | Security | Credential Validation |
| 4778 | Security | Session Reconnected |
| 4779 | Security | Session Disconnected by User |
| 4794 | Security | An Attempt was Made to Set the Directory Services Restore Mode Administrator Password |
| 5136 | Security | Directory Service Changes |
| 5140 | Security | A Network Share Object was Accessed |
| 5141 | Security | A Directory Service Object was Deleted |
| 5145 | Security | Network Share Object was Checked |
| 5376 | Security | Credential Manager Credentials Submitted |
| 5377 | Security | Credential Manager Credentials Auto-Logon |
| 1102 | Security | Event Log Cleared |
| 1100 | Security | Event Log Service Shutdown |

### Logon type corresponding to Succesfull (4624) or Failed logins (4625)

| Logon Type | Explanation |
|---|---|
| 2 | Logon via console |
| 3 | Network Logon. A user or computer logged on to this computer from the network |
| 4 | Batch Logon |
| 5 | Windows Service Logon  |
| 7 | Credentials used to unlock screen  |
| 8 | Network logon sending credentials (cleartext)    |
| 9 | Different credentials used than logon user |
| 10 | Remote Interactive logon (RDP)  |
| 11 | Cached credentials used to logon|
| 12 | Cached remote interactive |
| 13 | Cached Unlock (Similar to logon type 7)  |

### Other's log important Event IDs

| IDs | Event log | Context |
| --- | --- | --- |
| 7045 | System | Service installed |
| 7035 | System | Service Control Manager |
| 7036 | System | Service State Change |
| 7001 | System | Service Start Failed |
| 1001 | System | BSOD |
| 6005 | System | Start-up time of the machine	|
| 6006 | System | Shutdown time of the machine |
| 59 | MicrosoftWindows Bits Client/operational | Bits Jobs |
| 2004 | Microsoft-Windows-Windows Firewall with Advanced Security | Rule has been added to the Window Firewall exception list |
| 2006 | Microsoft-Windows-Windows Firewall with Advanced Security | Deleted firewall rule |
| 1116  | Microsoft Windows Windows Defender/Operational | Defender Antivirus has detected malware |
| 1117 | Microsoft Windows Windows Defender/Operational | Action taken |
| 1006 | Microsoft Windows Windows Defender/Operational | Scan result |
| 4103 | Microsoft Windows PowerShell/Operational | Module logging |
| 4104 | Microsoft Windows PowerShell/Operational | Script Block Logging |
| 4105 | Microsoft Windows PowerShell/Operational | Transcription Logging |
| 4688 | Microsoft Windows PowerShell/Operational | Process Creation (including PowerShell processes) |
| 400 | Windows PowerShell | Start of a PowerShell activity, whether local or remote.  |
| 403 | Windows PowerShell | Completion of a PowerShell activity |
| 800 | Windows PowerShell | Pipeline execution |
| 1000 | Application | Application Error/crash |
| 1001 | Application | Application Error reporting |
| 1024 | Application | Software Installation |
| 1040 | Application | User Initiated Software Installation |
| 1 | Microsoft-Windows-Sysmon/Operational | Process Creation |
| 2 | Microsoft-Windows-Sysmon/Operational | A process changed a file creation time |
| 3 | Microsoft-Windows-Sysmon/Operational | Network connection detected |
| 6 | Microsoft-Windows-Sysmon/Operational | Driver Loaded |
| 7 | Microsoft-Windows-Sysmon/Operational | Image Loaded |
| 8 | Microsoft-Windows-Sysmon/Operational | CreateRemoteThread |
| 10 | Microsoft-Windows-Sysmon/Operational | ProcessAccess |
| 11 | Microsoft-Windows-Sysmon/Operational | FileCreate |
| 12 | Microsoft-Windows-Sysmon/Operational | RegistryEvent (Object create and delete) |

Event ID KB: https://system32.eventsentry.com/ and https://www.myeventlog.com/search/browse

## Triage artifacts parsing and analysis

### File Records

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| MFT | `C:\` | `MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out" --csvf MyOutputFile.csv` or NTFS Log Tracker |
| UsnJrnl | `C:\$Extend` | `MFTECmd.exe -f "C:\Temp\SomeJ" --csv "c:\temp\out" --csvf MyOutputFile.csv` or NTFS Log Tracker |

Follow Windows Time Rules below:

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/70270442-6316-420a-b183-971624a141f9)
Credit: SANS Windows Forensic Analysis Poster (digital-forensics.sans.org)

### System and user Information (via Registry)

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| Operating System Version | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Registry Explorer |
| System Boot & Autostart Programs | Run registries | Registry Explorer |
| Computer Name | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | Registry Explorer |
| System Last Shutdown Time | `SYSTEM\CurrentControlSet\Control\Windows` | Registry Explorer |
| Cloud Account Details | `SAM\Domains\Account\Users\<RID>\InternetUserName` | Registry Explorer |
| User Accounts | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` | Registry Explorer |
| Last Login and Password Change | `SAM\Domains\Account\Users` | Registry Explorer |

### Application Execution

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| Shimcache | `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache` | RegRipper |
| Amcache.hve | `C:\Windows\AppCompat\Programs\Amcache.hve` | Registry Explorer |
| UserAssist | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` | Registry Explorer |
| Win10 Timeline | `C:\%USERPROFILE%\AppData\Local\ConnectedDevicesPlatform\L.Administrator\ActivitiesCache.db` | `WxTCmd.exe -f "ActivitiesCache.db" --csv D:\Hands-On` |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | srum-dump |
| BAM / DAM | `SYSTEM\ControlSet001\Services\bam\State\UserSettings\` | Registry Explorer |
| Prefetch | `C:\Windows\prefetch` | `PECmd.exe -d D:\Windows\prefetch --csv "D:\Hands-On" --csvf prefetch.csv` or WinPrefetch |
| Task Bar Feature Usage | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` | Registry Explorer |
| Jumplist | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` | Jumplist Explorer |
| Last Visited MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | RegRipper |
| CapabilityAccessManager | `NTUSER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore` | Registry Explorer |
| Commands Executed in the Run Dialog | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Registry Explorer |
| Services | `System\CurrentControlSet\Services` | Registry Explorer |

### File and Folder Opening

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| Shellbag | `NTUSER.dat\Software\Microsoft\Windows\Shell\Bags` | Shellbags Explorer |
| Open/Save MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU` | Registry Explorer |
| Shortcut (LNK) Files | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows|Office\Recent\` | Autopsy |
| Jumplist | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` | Jumplist Explorer |
| Recent Files | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Registry Explorer |
| Office Recent Files | `NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>` | Registry Explorer |
| Office Trust Records | `NTUSER\Software\Microsoft\Offi ce\<Version>\<AppName>\Security\Trusted Documents\TrustRecords` | Registry Explorer |
| MS Word Reading Locations | `NTUSER\Software\Microsoft\Offi ce\<Version>\Word\Reading Locations` | Registry Explorer |
| Office OAlerts | OAlerts.evtx | Event log explorer |
| Last Visited MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Registry Explorer |
| Internet Explorer file:/// | `%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat` | Text Editor |


### Deleted Items and File Existence

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| Recycle Bin | `C:\$Recycle.Bin` | Recbin |
| Thumbcache | `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` | Thumbcache Viewer |
| User Typed Paths | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | Registry Explorer |
| Search – WordWheelQuery | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | Registry Explorer |
| Internet Explorer file:/// | `%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat` | Text Editor |
| Windows Search Database | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` | LostPassword's Search Index Examiner |


### Browser activity

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| Browser activity | `C:\Users\%user%\AppData\Local\\Roaming\BrowserName` | DBBrowser | 

### Network Usage

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| Network History | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Network*` | Registry Explorer |
| Timezone | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Registry Explorer |
| WLAN Event Log | `Microsoft-Windows-WLAN-AutoConfig Operational.evtx` | Event log viewer |
| Network Interfaces | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` | Registry Explorer |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | srum-dump |

### USB Usage

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| USB Device Identification | `SYSTEM\CurrentControlSet\Enum\*` | Registry Explorer |
| Drive Letter and Volume Name | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` and `SYSTEM\MountedDevices` | Registry Explorer |
| User Information | `SYSTEM\MountedDevices` and `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Registry Explorer |
| Connection Timestamps | `SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_&Prod_\USBSerial` | Registry Explorer |
| Volume Serial Number (VSN) | `SOFTWARE\Microsoft\WindowsNT\CurrentVersion\EMDMgmt` | Registry Explorer |
| Shortcut (LNK) Files | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\\Office\Recent\` | Autopsy |
| Event Logs | `System.evtx` | Event log viewer |


### AntiVirus logs

| Artifact | Location |
| --- | --- |
| Avast | `C:\ProgramData\Avast Software\` |
| AVG | `C:\ProgramData\AVG\Antivirus\` |
| Avira | `C:\ProgramData\Avira\Antivirus\LOGFILES\` | 
| Bitdefender | `C:\Program Files*\Bitdefender*\` | 
| ESET | `C:\ProgramData\ESET\ESET NOD32 Antivirus\Logs\` | 
| F-Secure | `C:\ProgramData\F-Secure\Log\` or `C:\Users\%user%\AppData\Local\F-Secure\Log\`   | 
| McAfee |` C:\ProgramData\McAfee\*`  | 
| Sophos | `C:\ProgramData\Sophos\Sophos *\Logs\` | 
| Trend Micro | `C:\ProgramData\Trend Micro\` or `C:\Program Files*\Trend Micro\` |
| Symantec | `C:\ProgramData\Symantec\` or `C:\Users\%user%\AppData\Local\Symantec\` |
| WinDefender | `C:\ProgramData\Microsoft\Windows Defender\*` or `C:\ProgramData\Microsoft\Microsoft AntiMalware\Support\` or MpCmdRun.log |

## Other Artifacts

| Artifact | Location | Tools or Commands |
| --- | --- | --- |
| Task Scheduler | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` | Registry Explorer |
| Startup folder | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | Autopsy |
| Startup folder user | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` | Autopsy |
| Shadow copy | - | Shadow Explorer |
| hiberfil.sys | `C:\` | Hibernation Recon |
| pagefile.sys | `C:\` | strings |
| Unalloc file | - | Autopsy |
| Anydesk | `C:\Users\%user%\AppData\Roaming\AnyDesk\*` or `C:\ProgramData\AnyDesk\*` | Autopsy |
| WMI persistence | `C:\WINDOWS\system32\wbem\Repository\OBJECTS.DATA` | WMI_Forensics |
| WMI persistence | `C:\WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA` | WMI_Forensics |
| RDP Cache | `C:\%USERPROFILE%\AppData/Local/Microsoft/Terminal Server Client/Cache` | BMC-Tools |


## Other notes

- Command to parse all registry in a folder using Regripper
```
cd folder_containing_all_registries
for /r %i in (*) do (C:\RegRipper3.0\rip.exe -r %i -a > %i.txt)
```
- USB usage also can be investigate using "USB Detective Community Edition"
- Nirsoft software might have a good tool for viewing your artifacts
