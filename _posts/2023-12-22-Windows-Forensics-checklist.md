---
title:  "Checklist: Windows Forensics"
tags: DFIR
---

During a Windows Forensics engagement, I occasionally find myself forgetting essential tasks or unintentionally skipping analyzing importants artifacts. Therefore, this checklist (along with cheatsheet) could help myself and ensure that I adhere to a systematic workflow when conducting Windows Forensics.

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

### Windows event logs analysis
1. Located at `C:\Windows\System32\winevt\Logs`
2. Perform event log scanner:

    | Tools | Commands |
    | --- | --- |
    | Hayabusa | `hayabusa.exe update-rules` and `hayabusa.exe csv-timeline -d ..\Logs -p verbose -o results.csv` |
    | DeepBlueCLI | `.\DeepBlue.ps1 -log security` |
    | Chainsaw | `chainsaw.exe hunt evtx_logs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output results` |
    | Zircolite | `zircolite_win10.exe --evtx ../Logs` |
    | APT-Hunter | `APT-Hunter.exe -p ..\Logs -o Foldername -allreport` |
    | EVTXHussar | `EvtxHussar.exe C:\evtx_compromised_machine -o C:\evtxhussar_results` |
    | Rhaegal | `rhaegal.exe -lp ..\Logs -rp rules -n 100 -o output.csv` |

3. Manually view in Event Log Explorer

    | No. | Interesting logs |
    | --- | --- |
    | 1 | Security.evtx |
    | 2 | System.evtx |
    | 3 | Application.evtx |
    | 4 | Microsoft-Windows-Sysmon/Operational.evtx |
    | 5 | Microsoft-Windows-PowerShell/4Operational.evtx |
    | 6 | Microsoft-Windows-Windows Defender/Operational.evtx |
    | 7 | Microsoft-Windows-WMI-Activity/4Operational.evtx |
    | 8 | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx |
    | 9 | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx |
    | 10 | Microsoft-Windows-TaskScheduler/Operational.evtx |
    | 11 | Microsoft-Windows-DNS-Server%4Operational.evtx |
    | 12 | Directory Service.evtx |
    | 13 | File Replication Service.evtx | 
    | 14 | %SystemDrive%\inetpub\logs\LogFiles |
    | 15 | %SystemRoot%\System32\LogFiles\HTTPERR |
    | 16 | %ProgramFiles%\Microsoft\Exchange Server\V15\Logging |
    | 17 | Panther*.log |
    | 18 | RPC Client Access*.log |
    | 19 | Third party antivirus log |

### Triage artifacts parsing and analysis
| To do | Tools or Commands |
| --- | --- |
| MFT | `MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out" --csvf MyOutputFile.csv` |
| UsnJrnl | `MFTECmd.exe -f "C:\Temp\SomeJ" --csv "c:\temp\out" --csvf MyOutputFile.csv` |
| Registry | `for /r %i in (*) do (C:\RegRipper3.0\rip.exe -r %i -a > %i.txt)` |
| Jumplist | Jumplist Explorer - `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` |
| Prefetch | `PECmd.exe -d D:\Windows\prefetch --csv "D:\Hands-On" --csvf prefetch.csv` |
| UserAssist | Registry Explorer - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` |
| Shimcache | RegRipper - `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache` |
| Win10 Timeline | `WxTCmd.exe -f "D:\Users\Administrator\AppData\Local\ConnectedDevicesPlatform\L.Administrator\ActivitiesCache.db" --csv D:\Hands-On` |
| SRUM | srum-dump - `C:\Windows\System32\sru\SRUDB.dat` |
| BAM / DAM | Registry Explorer - `SYSTEM\ControlSet001\Services\bam\State\UserSettings\` |
| MRU | Registry Explorer - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` |
| Shellbag | Shellbags Explorer - `NTUSER.dat\Software\Microsoft\Windows\Shell\Bags` |
| Registry persistent | Registry Explorer |
| Services | Registry Explorer - `System\CurrentControlSet\Services` |
| Task Scheduler | Registry Explorer - `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` |
| Startup folder | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` |
| Startup folder user | `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` |
| Shadow copy | Shadow Explorer |
| hiberfil.sys | Hibernation Recon |
| pagefile.sys | strings |
| Unalloc file | Autopsy |
| Browser activity | DBBrowser | 

