# OSDA 

## ToDo
- Import Import Get-WDLog.psm1 in C:\Sysmon and write the function (AV module)
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/windows-server-side-attacks/web-application-attacks/extra-mile
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/windows-client-side-attacks/monitoring-windows-powershell/extra-mile
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/linux-server-side-attacks/credential-abuse/extra-mile-i
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/linux-server-side-attacks/credential-abuse/extra-mile-ii
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/linux-server-side-attacks/web-application-attacks/extra-mile-iii
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/linux-server-side-attacks/web-application-attacks/extra-mile-iv
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/linux-privilege-escalation/attacking-the-system/extra-mile-i
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/linux-privilege-escalation/attacking-the-system/extra-mile-ii
- Grab all ps1 script

## Example of .bat file
```
@ECHO OFF
TITLE Example Batch File
ECHO This batchfile will show Windows 10 Operating System information
systeminfo | findstr /C:"Host Name"
systeminfo | findstr /C:"OS Name"
systeminfo | findstr /C:"OS Version"
systeminfo | findstr /C:"System Type"
systeminfo | findstr /C:"Registered Owner"
PAUSE
```

## Example of vb script
```
' List Operating System and Service Pack Information

strComputer = "."
Set objWMIService = GetObject("winmgmts:" _
 & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
 
Set colOSes = objWMIService.ExecQuery("Select * from Win32_OperatingSystem")
For Each objOS in colOSes
  Wscript.Echo "Computer Name: " & objOS.CSName
  Wscript.Echo "Caption: " & objOS.Caption 'Name
  Wscript.Echo "Version: " & objOS.Version 'Version & build
  Wscript.Echo "Build Number: " & objOS.BuildNumber 'Build
  Wscript.Echo "Build Type: " & objOS.BuildType
  Wscript.Echo "OS Type: " & objOS.OSType
  Wscript.Echo "Other Type Description: " & objOS.OtherTypeDescription
  WScript.Echo "Service Pack: " & objOS.ServicePackMajorVersion & "." & _
   objOS.ServicePackMinorVersion
Next
```
In order to run; `cscript osinfo.vbs`

## Example of powershell
```
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property CSName, Caption, Version,BuildNumber, BuildType, OSType, RegisteredUser, OSArchitecture, ServicePackMajorVersion, ServicePackMinorVersion
```

## Event viewer
Log dir at `C:\Windows\System32\winevt\Logs` and process name `eventvwr.exe`

### PowerShell and Event Logs
List individual event log entries
```
Get-WinEvent -ListLog Application, Security, Setup, System
Get-WinEvent -LogName Security | Select-Object -first 10
Get-WinEvent -LogName 'Security' | Where-Object { $_.Id -eq "4624" } | Select-Object -Property TimeCreated,Message -first 10
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="4/23/2021 14:00:00"; EndTime="4/23/2021 14:30:00"; ID=4624} | Select-Object -Property TimeCreated,Message
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="4/23/2021 19:00:00"; EndTime="4/26/2021 07:00:00"; ID=4624} | Select-Object -Property TimeCreated,Message
```
Below is a mapping of the first nine array indices for the tags and values of EventData in Logon events.

| Index  | Description  |  
|---|---|
| Index 0  | SubjectUserSid  |  
| Index 1  | SubjectUserName  |  
| Index 2  | SubjectDomainName  |  
| Index 3  | SubjectLogonId  |  
| Index 4  | TargetUserSid  |  
| Index 5  | TargetUserName  |  
| Index 6  | TargetDomainName  |  
| Index 7  | TargetLogonId  |  
| Index 8  | LogonType  |  

**LogonType**
03 => Network-Level Authentication (NLA)
10 => Remote Desktop Services (RDP)
09 => NewCredentials (when a new session is established with the same local identity as the initiator, but uses a different identity for network connections)
```
Get-WinEvent -FilterHashTable @{LogName='Security'; StartTime="4/23/2021 00:00:00"; EndTime="4/26/2021 07:00:00"; ID=4624 } | Where-Object { $_.properties[8].value -eq 10 } | Format-List
```

## Sysmon
The open-source configuration we'll be using is located C:\Sysmon\sysmonconfig-export.xml and designed by SwiftOnSecurity.
`.\Sysmon64.exe -c | Select-Object -first 10` `.\Sysmon64.exe -s`. Sysmon events are stored in Applications and Services Logs/Microsoft/Windows/Sysmon/Operational

### Sysmon module && Powershell module
```
function Get-SysmonEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-Sysmon/Operational"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    Get-WinEvent -FilterHashtable $filters
}

function Get-SecurityEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Security"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    Get-WinEvent -FilterHashtable $filters
}

function Get-PSLogEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-PowerShell/Operational"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }

    Get-WinEvent -FilterHashtable $filters
}

```
For EventData, RuleName is element 0; UtcTime is element 1; ProcessGuid is element 2; ProcessId is element 3, and so on. We'll focus on the ProcessId tag.
```
Get-SysmonEvent $null "04/28/2021 13:55:00" "04/28/2021 14:00:00"
Get-SysmonEvent 11 "4/28/2021 13:48:00" "4/28/2021 13:49:00" | Format-List
# Checking the process that creates the file (the process is extracted from the previous command output)
Get-SysmonEvent 1 $null "7/28/2021 13:48:42" | Where-Object { $_.properties[3].value -eq 2032 } | Format-List
```

```
Import-Module C:\Sysmon\Get-Sysmon.psm1
Get-Module
```

## Remote Access with PowerShell Core
On kali 
```
pwsh
Enter-PSSession 192.168.51.10 -Credential offsec -Authentication Negotiate
Import-Module C:\Sysmon\Get-Sysmon.psm1
Get-Module
``` 

## Event ID 
4624 => Successful Logon
4625 => Fail Logon 
4634 => Log OFF
4697 => Service was installed
7045 => A new service was created on the local Windows machine
7036 => A service starts successfully
4104 => PowerShell script block
1116 => MALWAREPROTECTION_STATE_MALWARE_DETECTED
1117 => MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN
4662 => An operation was performed on an object
4740 => A lockout is triggered
4625 => Failled operation due to lockout 
4768 => KDC issues TGT
4769 => KDC issues TG4728 => A member was added to a security-enabled global group
#Account management
4729 => A member was removed from a security-enabled global group
4732 => A member was added to a security-enabled local group
4733 => A member was removed from a security-enabled local group
4756 => A member was added to a security-enabled universal group
4757 => A member was removed from a security-enabled universal group

## Status & SubStatus code
C000006D (Status) => bad username or authentication information
C000006A (SubStatus) => bad username or authentication information

## Sysmon ID 
1 => Process created
3 =>  Network connection
11 => File created
13 => RegistryEvent 
10 => ProcessAccess

## Brute Force detection
```
#Get successful login
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="4/30/2021 19:00:00"; EndTime="5/3/2021 07:00:00"; ID=4624 }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="5/1/2021 03:21:26"; EndTime="5/1/2021 03:21:27"; ID=4624 } | Format-List

#Get the Login ID and check for logoff for this account during the same time 
Get-SecurityEvent 4634 "5/1/2021 03:21:26" "5/3/2021 07:00:00" | Where-Object { $_.properties[3].value -eq 0x323466 } | Format-List

#Failed logon of a day
Get-SecurityEvent 4625 "5/6/2021 00:00:00" "5/7/2021 00:00:00"

Get-SecurityEvent 4625 "5/6/2021 00:00:00" "5/7/2021 00:00:00" | Format-List TimeCreated, @{Label = "Logon Type"; Expression = {$_.properties[10].value}}, @{Label = "Status"; Expression = {'{0:X8}' -f $_.properties[7].value}}, @{Label = "Substatus"; Expression = {'{0:X8}' -f $_.properties[9].value}}, @{Label = "Target User Name"; Expression = {$_.properties[5].value}}, @{Label = "Workstation Name"; Expression = {$_.properties[13].value}}, @{Label = "IP Address"; Expression = {$_.properties[19].value}}

#Cross check with successful login from IP 
Get-SecurityEvent 4624 "5/6/2021 09:36:44" "5/6/2021 09:37:44" | Where-Object { $_.properties[18].value -eq "192.168.51.50" }
```

## Web Application Attacks
### Local File Inclusion
Grep '..\..\..\..\..\..\..\..\..\..\..\..\..\..', '../../../../../../../../../' or 'Python' in C:\inetpub\logs\LogFiles 

### Command Injection
```
# Check for Process create 
Get-SysmonEvent $null "05/10/2021 16:02:00" "5/10/2021 16:03:00"

#Get-SysmonEvent 1 "05/10/2021 16:02:33" "5/10/2021 16:02:35" | Format-List TimeCreated, @{Label = "CommandLine"; Expression = {$_.properties[10].value}}, @{Label = "User"; Expression = {$_.properties[12].value}}, @{Label = "ParentImage"; Expression = {$_.properties[20].value}}

# Check where ParentImage is C:\Windows\SysWOW64\cmd.exe or ends with cmd.exe
```

### File upload
Extract from Sysmon (File create) the name of the Rule (index 0), the Image (index 4) and Process ID (index 3) of the process that performed the creation, and the destination of the newly-created file (index 5):
```
Get-SysmonEvent 11 "05/12/2021 12:48:50" "05/12/2021 12:48:52" | Format-List @{Label = "Rule"; Expression = {$_.properties[0].value}}, @{Label = "PID"; Expression = {$_.properties[3].value}},@{Label = "Image"; Expression = {$_.properties[4].value}}, @{Label = "TargetFile"; Expression = {$_.properties[5].value}}
```
Extract from Sysmon (ProcessCreate events), the Process ID (PID) and the Parent Process ID (PPID).
```
Get-SysmonEvent 1 "5/13/2021 14:26:17" "5/13/2021 14:26:19" | Format-List TimeCreated, @{Label = "PID"; Expression = {$_.properties[3].value}}, @{Label = "PPID"; Expression = {$_.properties[19].value}}, @{Label = "CommandLine"; Expression = {$_.properties[10].value}}, @{Label = "User"; Expression = {$_.properties[12].value}}, @{Label = "ParentImage"; Expression = {$_.properties[20].value}}
```
Extract from Sysmon, NetworkConnect with PID, Image, User, Source and Destination IPs, along with the Source and Destination Ports of our network traffic.
```
Get-SysmonEvent 3 "5/13/2021 2:26:18" "5/13/2021 2:26:20" | Format-List @{Label = "PID"; Expression = {$_.properties[3].value}}, @{Label = "Image"; Expression = {$_.properties[4].value}}, @{Label = "User"; Expression = {$_.properties[5].value}}, @{Label = "Source IP"; Expression = {$_.properties[9].value}}, @{Label = "Source Port"; Expression = {$_.properties[11].value}}, @{Label = "Destination IP"; Expression = {$_.properties[14].value}}, @{Label = "Destination Port"; Expression = {$_.properties[16].value}}
```

## Binary exploitation
Within 10 sec of the exploit
```
Get-SysmonEvent $null "05/21/2021 14:50:34" "05/21/2021 14:50:44"

#Process create
Get-SysmonEvent 1 "05/21/2021 14:50:39" "05/21/2021 14:50:41" | Format-List TimeCreated, @{Label = "PID"; Expression = {$_.properties[3].value}}, @{Label = "PPID"; Expression = {$_.properties[19].value}}, @{Label = "CommandLine"; Expression = {$_.properties[10].value}}, @{Label = "User"; Expression = {$_.properties[12].value}}, @{Label = "ParentImage"; Expression = {$_.properties[20].value}}

#Network
Get-SysmonEvent 3 "05/21/2021 14:50:38" "5/21/2021 14:50:44" | Format-List TimeCreated, @{Label = "Image"; Expression = {$_.properties[4].value}}, @{Label = "Source IP"; Expression = {$_.properties[9].value}}, @{Label = "Source Port"; Expression = {$_.properties[11].value}}, @{Label = "Destination IP"; Expression = {$_.properties[14].value}}, @{Label = "Destination Port"; Expression = {$_.properties[16].value}}
```

### Windows Defender Exploit Guard (WDEG)
Event regarding blocking due to WDEG
```
Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-Security-Mitigations/UserMode'; StartTime = '5/25/2021 13:42:28'; EndTime = '5/25/2021 13:42:30'} | Format-List -Property Id, TimeCreated, LevelDisplayName, Message

#Remove remove SyncBreeze configuration
Remove-Item -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\syncbrs.exe'
```

## Windows client-side attacks
to be implemented 
- Get-SysmonEvent 1 where Image contains powershell.exe; CommandLine contains powershell.exe; ParentImage contains Microsoft Office (or office365)
- process where CommandLine: starts with "powershell.exe"

for IOC
- FileCreate (11) event that follows the ProcessCreate event using the same timeframe where TargetFilename is like C:\Users\*\AppData\Local\Temp\*.ps1

DNS (Event ID "22") 
- filter on QueryName, QueryResults # QueryName: kali ;  QueryResults: ::ffff:192.168.*.*;

Next filter on IP found in the DNS event above
```
Get-SysmonEvent 3 "6/17/2021 15:10:41" "6/17/2021 15:11:00" | Where-Object { $_.properties[14].value -eq "192.168.51.50" } | Format-List
```

## Monitoring Windows PowerShell
To configure different parts of PowerShell logging, launch the Local Group Policy Editor, gpedit.msc, and navigate to Local Computer Policy > Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell.

### PowerShell Module Logging
```
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-PowerShell/Operational'; StartTime="6/14/2021 13:25:52"; EndTime="6/14/2021 13:25:54"; ID=4103}

Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-PowerShell/Operational'; StartTime="6/14/2021 13:25:52"; EndTime="6/14/2021 13:25:54"; ID=4103} | Format-List
```

### PowerShell Script Block Logging
```
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-PowerShell/Operational'; StartTime="06/15/2021 14:49:42"; EndTime="06/15/2021 14:49:44"; ID=4104} | Format-List
```

### PowerShell Transcription
```
Get-CimInstance Win32_ComputerSystem | Select-Object -Property Name, PrimaryOwnerName, Domain, TotalPhysicalMemory, Model, Manufacturer
```
Log are stored in C:\Users\offsec\Documents\YYYYMMDD using PowerShell_transcript.HOSTNAME.UNIQUEID.YYYYMMDDHHMMSS.txt format

### Case study
```
Get-PSLogEvent 4104 "6/15/2021 15:44:00" "6/15/2021 15:45:00" | Format-Table Timecreated, LevelDisplayName, Message
Get-PSLogEvent 4103 "6/15/2021 15:44:00" "6/15/2021 15:45:00" | Format-List
Get-PSLogEvent 4103 "6/15/2021 15:44:00" "6/15/2021 15:44:59" | Format-List TimeCreated, @{Label = "Payload"; Expression = {$_.properties[2].value}}
```

## Deobfuscating
```
wevtutil export-log Microsoft-Windows-PowerShell/Operational C:\users\offsec\Desktop\pwsh_export.evtx # Exporting
Get-RvoScriptBlock -Path 'C:\Users\offsec\Desktop\pwsh_export.evtx' -Verbose #Attempting to deobfuscate using Revoke-Obfuscation
```

## Privilege escalation detection
### UAC bypass (with fodhelper)
```
## Register update where TargetObject contains ms-settings\Shell\Open\command
## Process create where ParentCommandLine is C:\Windows\system32\fodhelper.exe or CommandLine is C:\Windows\system32\fodhelper.exe
## All process where IntegrityLevel is High or System and CommandLine is custom one (cf winprivesc.ps1)
Get-SysmonEvent 13 "06/28/2021 13:41:35" "06/28/2021 13:41:37" | Format-List
#Process create in the same time range
Get-SysmonEvent 1 "06/28/2021 13:41:35" "06/28/2021 13:41:37" | Format-List
#-PSLogEvent 4103 in the timeframe 
Get-PSLogEvent 4103 "6/28/2021 13:41:35" "6/28/2021 13:41:45"
Get-PSLogEvent 4103 "6/28/2021 13:41:35" "6/28/2021 13:41:45" | Format-List
#Above command will reveal C:\tools\windows_privilege_escalation\fodshell_443.exe as value in Message
Get-SysmonEvent 1 "06/28/2021 13:41:00" "06/28/2021 13:42:00" | Where-Object { $_.properties[4].value -like "*fodshell*" } | Format-List
```

### Service Creation
```
Get-SecurityEvent $null "6/30/2021 12:49:00" "6/30/2021 12:50:00"
Get-SecurityEvent 4697 "6/30/2021 12:49:31" "6/30/2021 12:49:33" | Format-List
Get-SysmonEvent $null "06/30/2021 12:49:31" "06/30/2021 12:50:00"
Get-SysmonEvent 13 "06/30/2021 12:49:31" "06/30/2021 12:49:33" | Format-List
```

### Attacking Service Permissions
```
Get-SysmonEvent $null "7/1/2021 10:42:00" "7/1/2021 10:43:00"
Get-SysmonEvent 1 "7/1/2021 10:42:00" "7/1/2021 10:42:59" | Format-List
Get-SysmonEvent 13 "7/1/2021 10:42:00" "7/1/2021 10:42:59" | Format-List
Get-SysmonEvent $null "7/1/2021 10:56:00" "7/1/2021 10:56:20"

Get-SysmonEvent 1 "7/1/2021 10:56:09" "7/1/2021 10:56:11" | Format-List @{ Label = 'UtcTime'; Expression = { $_.properties[1].value }}, @{ Label = 'Image'; Expression = { $_.properties[4].value }}, @{ Label = 'ProcessId'; Expression = { $_.properties[3].value }}, @{ Label = 'CommandLine'; Expression = { $_.properties[10].value }}, @{Label = 'User'; Expression = { $_.properties[12].value }}, @{ Label = 'ParentImage'; Expression = { $_.properties[20].value }}, @{ Label = 'ParentProcessId'; Expression = { $_.properties[19].value }}
```

### Leveraging Unquoted Service Paths
```
Import-Module .\PowerUp.ps1
Get-UnquotedService
Get-SysmonEvent 11 "7/8/2021 10:49:33" "7/8/2021 10:49:35" | Format-List # where TargetFilename is IOBit.exe
Get-SysmonEvent 1 | Where-Object { $_.properties[4].value -like "*IOBit.exe*" } | Format-List
```

### Persisting via Windows Service

### Persisting via Scheduled Tasks
```
schtasks /query /fo LIST /v
schtasks /query /tn MicrosoftEdgeUpdateTaskMachineCore

Get-SecurityEvent 4698 "11/12/2021 7:26:00" "11/12/2021 7:27:00" | Format-List
Get-SysmonEvent 1 "11/12/2021 7:26:02" "11/12/2021 7:26:04" | Format-List 
## List process where User: NT AUTHORITY\SYSTEM  IntegrityLevel: System 
## All network connection perform by User: NT AUTHORITY\SYSTEM
```

### Persisting by DLL-Sideloading/Hijacking
Get-SysmonEvent 11 (create file) where TargetFilename ends with .dll

### Persistence Using Run Keys
The Run and RunOnce registry keys are commonly used for persistence

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

```
## Get-SysmonEvent 1 (Process) where CommandLine contains one of the Reg and User is NT AUTHORITY\SYSTEM
## Get-SysmonEvent 13 (reg) where TargetObject contains one of the Reg 

Get-SysmonEvent 1 "11/15/2021 8:49:11" "11/15/2021 8:49:13" | Format-List
Get-SysmonEvent 13 "11/15/2021 8:49:11" "11/15/2021 8:49:13" | Format-List
Get-SecurityEvent 4624 | Where-Object { $_.properties[8].value -eq 10 -and $_.properties[5].value -eq "Administrator" }
```

### Using Winlogon Helper
```
## Get-SysmonEvent 1 (process) where CommandLine contains HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
## Get-SysmonEvent 13 (reg) where TargetObject contains HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
```

## Windows Persistence 
```
sc.exe create VindowsUpdate start= auto error= ignore binpath= C:\tools\windows_persistence\prst_servshell443.exe

## List scheduled task
schtasks /query /tn MicrosoftEdgeUpdateTaskMachineCore
```

## Logging
### log_parser.py
```
import re
import os.path

centos_ssh_log_file_path = "/var/log/secure"
ubuntu_shh_log_file_path = "/var/log/auth.log"

centos_apache_log_file_path = "/var/log/httpd/access_log"
ubuntu_apache_log_file_path = "/var/log/apache2/access.log"

ssh_log_files = [centos_ssh_log_file_path,ubuntu_shh_log_file_path]
apache_log_files = [centos_apache_log_file_path,ubuntu_apache_log_file_path]

regex_pattern = 'sshd\[.*\]'   
regex = '([(\d\.)]+) - - \[(.*?)\] \"(.*?)\" (\d+) (\d+) \"(.*?)\" \"(.*?)\"'

for log_file in ssh_log_files:
    if os.path.isfile(log_file) :
 	    with open(log_file, "r") as file:
 	        for line in file:
 	            for match in re.finditer(regex_pattern, line, re.S):
 		            print(line,end = '')
```

## Linux Web application attacks
```
### command injection 
shellshock_regex = '\(\)\s*\t*\{.*;\s*\}\s*;'

web_log_regex_cookie = '([(\d\.)]+) - - \[(.*?)\] \"(.*?)\" (\d+) (\d+) \"(.*?)\" \"(.*?)\" \"(.*?)\"'

### sudo privesc attempt 
regex_sudo_privesc_attempt = 'sudo:.*command not allowed'

### audit
regex_audit = "^type=TTY.*"+" uid=" + uid +".*data=.*"

regex_audit     = ".*key=\"" + keyarg +"\".*"

### Audit decoder
for match in re.finditer(regex_audit, line, re.S):
   ...
   encoded_commands = ((line.split("data=")[1])).strip()
   decoded_commands = (binascii.a2b_hex(encoded_commands))
   print(decoded_commands)
```
### Backdooring a User
```
echo 'echo "hello from bob .bashrc"' >> /home/bob/.bashrc
ssh bob@192.168.51.12

#auditctl command to watch 
sudo auditctl -w /home/bob/.bashrc  -p wa -k privesc
sudo auditctl -w /home/bob/.profile -p wa -k privesc

#verify that the rules are validated
sudo auditctl -l

#aureport tool along with the -k option to filter based on key value
sudo aureport -k
```

### Detecting suid attack and weak permission
```
#logging rule (suid)
sudo auditctl -a exit,always -F arch=b64 -F euid=0 -S execve -k root_cmds 
sudo auditctl -a exit,always -F arch=b32 -F euid=0 -S execve -k root_cmds

#detect rule
sudo ausearch -k root_cmds -i -x bash

#logging weak permission
sudo auditctl -w /home/offsec/SOC-200/Linux_Privilege_Escalation/cron_scripts/ -p wa -k cron_scripts
sudo ausearch -k cron_scripts -i

sudo auditctl -w /etc/shadow -p  war -k etc_shadow
sudo ausearch -k etc_shadow -c cat -i
```

## Antivirus Alerts and Evasion
- Signature-Based Detection (Not logged in Windows Event Log)
```
MpCmdRun -Scan -ScanType 3 -File C:\tools\av_alerts_evasion\signature_detect_nonstage.exe -DisableRemediation
```
MpCmdRun => run manual scans 
ScanType 3 => performing a custom file and directory
File => specify the directory or file to be scanned 
DisableRemediation => do not perform any remediation after detection
- Logging them in Windows Event Log
```
Start-MpScan -ScanPath C:\tools\av_alerts_evasion\signature_detect_nonstage.exe -ScanType CustomScan; Get-Date
```
- Getting the log details
Import Get-WDLog.psm1 in C:\Sysmon
- Detection
```
Get-WDLogEvent $null "12/2/2021 10:59:00" "12/2/2021 11:00:00"
Get-WDLogEvent 1116 "12/2/2021 10:59:20" "12/2/2021 11:59:22" | Format-List
```
- List of all threats currently awaiting mitigation
```
Get-MpThreat
```
- Clear the queue of threats to remediate and remove the file from the computer
```
Remove-MpThreat
```
- View list of taken actions
```
Get-WDLogEvent 1117 "12/2/2021 11:08:07" "12/2/2021 11:08:09" | Format-List
```

- Activating real-time protection via gpedit.msc
Local Computer Policy > Computer Configuration then Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection

Disable *Turn off real-time protection* setting
**This will generate a configuration change with Event ID 5007. The HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection key in the Windows Registry will change from 0x0 to 0x1.**

- Detect AMSI byspass
```
Get-PSLogEvent 4104 "12/22/2021 8:41:24" "12/22/2021 8:41:26" | Where-Object { $_.LevelDisplayName -eq "Warning" } | Format-List
```

## Port forwarding 
```
netsh interface portproxy add v4tov4 listenport=21 listenaddress=172.16.50.11 connectport=3306 connectaddress=172.16.50.12
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=172.16.50.11 localport=21 action=allow

netsh interface portproxy show v4tov4

#Get WinEvent
Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'} -MaxEvents 20
Get-NetFirewallRule -Direction Inbound | Select-Object -Property DisplayName,Profile,Enabled | Where { $_.Enabled -eq 'True'}
Get-NetFirewallRule -DisplayName "forward_port_rule"
Get-NetFirewallRule -DisplayName "forward_port_rule" | Get-NetFirewallPortFilter

echo y | plink.exe -ssh -N -l kali -pw toor -R 192.168.48.2:1234:127.0.0.1:445 192.168.48.2 
Get-SysmonEvent | Where-Object { $_.Message -like "*plink*" }
Get-SysmonEvent 1 "1/31/2022 11:46:12" "2/1/2022 12:02:39" | Where-Object { $_.Message -like "*plink*" } | Format-List
```

## Active Directory Enumeration 
- Interacting with LDAP
```
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.Filter = '(distinguishedName=CN=DC-2,OU=Domain Controllers,DC=corp,DC=com)'
$Searcher.FindOne()

$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.Filter = '(distinguishedName=CN=DC-2,OU=Domain Controllers,DC=corp,DC=com)'
$Searcher.FindAll()

$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=corp,DC=com", 'corp\jdoe','Qwerty09!')
$Searcher.Filter = '(&(objectClass=computer)(cn=*dc*))'
$Searcher.FindAll()
```
- Detecting Active Directory Enumeration
```
auditpol /list /category
auditpol /list /subcategory:*
auditpol /get /category:"Logon/Logoff"
auditpol /get /subcategory:"Directory Service Access"
```
- Configure the audit settings for individual objects:
Open Active Directory Users and Computers (ADUC) with `dsa.msc`, expand the domain root, navigate to Domain Controllers and right click DC-2 to select Properties.
With the Properties window open, select Security and click Advanced on the bottom left.
Finally, with the Advanced Security Settings window open, click on the Auditing tab.

Click on Add to create a new auditing policy
Use the Everyone security principal, which is all encompassing. Clicking Select a principal and entering "Everyone".

Event related to this ("An operation was performed on an object") will be accessible via event ID 4662 under the security log.

### Baseline Monitoring with XPath filters
If we want to enumerate access to Domain Admins group performed by offsec user:
```
Function Get-GuidName ($Guid) {
    Begin {
        $ObjectTable = @{
            '%{0ca1d341-b9ee-4d46-ab3b-3a2732aa4b51}' = 'Domain Admins'
        }
    }
    Process {
        $Value = $ObjectTable[$Guid]
        If (!$Value) {
            $Value = $Guid
        }
    }
    End {
        return $Value
    }
}

Function Get-AccessName ($AccessMask) {
    Begin {
        $AccessTable = @{
            '0x10' = 'Read Property'
            '0x20000' = 'READ_CONTROL'
        }
    }
    Process {
        $Value = $AccessTable[$AccessMask]
        If (!$Value) {
            $Value = $AccessMask
        }
    }
    End {
        return $Value
    }
}

$FilterXML = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
     *[System[(EventID=4662)]] and *[EventData[(Data[@Name='SubjectUserSid']='S-1-5-21-2154860315-1826001137-329834519-1107')]] and *[EventData[(Data[@Name='ObjectName']='%{0ca1d341-b9ee-4d46-ab3b-3a2732aa4b51}')]] and *[EventData[(Data[@Name='OperationType']='Object Access')]]
   </Select>
  </Query>
</QueryList>
'@

$Logs = Get-WinEvent -LogName Security -FilterXPath $FilterXML
ForEach ($L in $Logs) {
   [xml]$XML = $L.toXml()
   $TimeStamp = $XML.Event.System.TimeCreated.SystemTime
   $SubjectUserName = $XML.Event.EventData.Data[1].'#text'
   $ObjectName = $XML.Event.EventData.Data[6].'#text'
   $AccessMask = $XML.Event.EventData.Data[10].'#text'
   [PSCustomObject]@{'TimeStamp' = $TimeStamp; 'SubjectUserName' = $SubjectUserName; 'ObjectName' = $ObjectName; 'AccessMask' = $AccessMask }
}
```
This filter will query the security log for all 4662 event IDs and only return results in which the SubjectUserSid value is that of  offsec account, the ObjectName is the ObjectGUID of  Domain Admins group, and the OperationType is Object Access.

The following XPATH query list can be used to enumerate access to Domain Admins group **performed by user different of offsec**:
```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
     *[System[(EventID=4662)]] and 
     *[EventData[(Data[@Name='ObjectName']='%{0ca1d341-b9ee-4d46-ab3b-3a2732aa4b51}')]] and
     *[EventData[(Data[@Name='OperationType']='Object Access')]]
     </Select>
   <Suppress Path="Security">
    *[EventData[(Data[@Name='SubjectUserSid']='S-1-5-21-2154860315-1826001137-329834519-1107')]]
   </Suppress>
  </Query>
</QueryList>
```

Another example can be the following where the expected guid is listed
```
$FilterXML = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
     *[System[(EventID=4662)]] and 
     *[EventData[(Data[@Name='OperationType']='Object Access')]] and
     *[EventData[Data[@Name='ObjectName'] and 
     (Data='%{a11236c4-e6ae-4dc7-ad58-92b6b6b5f83d}' or 
     Data='%{a1a88fa6-e570-4520-9b21-6bad8483979b}' or 
     Data='%{6e1648e7-b100-4bdf-b497-7061e8d7a068}' or 
     Data='%{74215987-5fa5-4e36-b4d2-c9fdc5fca747}' or 
     Data='%{c2e86461-de97-4ef5-881c-e6ccfb97df5d}' or    
     Data='%{02f71039-cf2c-47a8-aeeb-ff257851f149}')]]
   </Select>
  </Query>
</QueryList>
'@
```
Login with NTLM
```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624)]]
    and 
    *[EventData[Data[@Name='LogonType'] and (Data='3')]]
    and
 *[EventData[Data[@Name='AuthenticationPackageName'] and (Data='NTLM')]]
    </Select>
  </Query>
</QueryList>
```
## Windows Lateral movement
PTH : (EventID=4624) where LogonType is equal 9
```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624)]]
    and 
    *[EventData[Data[@Name='LogonType'] and (Data='9')]]
    </Select>
  </Query>
</QueryList>
```
PTH with service creation and startup
```
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
    *[System[(EventID=7045)]]
    and
    *[EventData[Data[@Name='ServiceName'] and (Data='PSEXESVC')]]
    or
    *[System[(EventID=7036)]]
    and
    *[EventData[Data[@Name='param1'] and (Data='PSEXESVC')]]
    </Select>
  </Query>
</QueryList>
```
### Enumerating brute force domain credentials
```
Get-BadPwdCount -List | Sort BadPwdCount -Descending
```
- Get lockout threshold
```
net accounts
```
- Extract lockout events
```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
    *[System[(EventID=4740)]]
    </Select>
  </Query>
</QueryList>
```
- Configure domain controller to generate faillure events after lockout 
```
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

.\Audit-TargetedFailedLogons.ps1 | Group-Object WorkstationName | Select Name,Count

. .\Get-BadPwdCount.ps1
Get-BadPwdCount -Expected 10

.\Audit-FailedLogons.ps1 | Group-Object WorkstationName | Select Name,Count
.\Audit-FailedLogons.ps1 | Select TargetUserName, WorkstationName
```
### Terminal services 
```
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational">
    <Select Path="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational">
      *[System[(EventID=1149)]]
   </Select>
  </Query>
</QueryList>


.\Audit-TerminalServices.ps1
```

## Detect abuse of Kerberos Ticket (DC method)
```
auditpol /get /category:"Account Logon"
```
 
```
# XPath XML for TGT kerberos events
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
     *[System[band(Keywords,9007199254740992) and (EventID=4768)]]
    </Select>
  </Query>
</QueryList>

# Extract username and ip from 4768 events
$TimeStamp = $XML.Event.System.TimeCreated.SystemTime
$TargetUserName = $XML.Event.EventData.Data[0].'#text'
$IPAddress = $($XML.Event.EventData.Data[9].'#text')
If ($IPAddress -eq '::1') {
	$IPAddress = $(Test-Connection -ComputerName $env:COMPUTERNAME -Count 1 | Select -ExpandProperty IPv4Address).IPAddressToString
}
else {
	$IPAddress = $IPAddress.split('::ffff:')[-1]
}

# XPath XML for TGS kerberos events
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
     *[System[band(Keywords,9007199254740992) and (EventID=4769)]]
   </Select>
  </Query>
</QueryList>

# Extract username and ip from 4769 events
$TimeStamp = $XML.Event.System.TimeCreated.SystemTime
$TargetUserName = $($XML.Event.EventData.Data[0].'#text' -split '@')[0]
$IPAddress = $($XML.Event.EventData.Data[6].'#text')
If ($IPAddress -eq '::1') {
    $IPAddress = $(Test-Connection -ComputerName $env:COMPUTERNAME -Count 1 | Select -ExpandProperty IPv4Address).IPAddressToString
}
else {
    $IPAddress = $IPAddress.split('::ffff:')[-1]
}

# Ticket stealing detection logic
$TGT = Get-TGT
$TGS = Get-TGS
ForEach ($T in $TGS) {
    $Valid = $TGT | Where-Object {$_.TargetUserName -eq $($T.TargetUserName) -and $_.IPAddress -eq $($T.IPAddress)}
    If (!$Valid) {
        $T
    }
}
```
### Detect abuse of Kerberos Ticket (Endpoint method)
- Get-SessionUsers function
```
Function Get-SessionUsers {
    Begin {
        $Sessions = @()
        $Klist = klist sessions
    }
    Process {
        $Sessions = $Klist | Where-Object { $_ -like "*Session*$env:USERDOMAIN*" } | ForEach-Object { 
            [PSCustomObject]@{'LogonId' = $(($_ -split ' ')[3]).substring(2); 'User' = $($_ -split ' ')[4]}
        }
    }
    End {
        return $Sessions
    }
}
```
- Grab . .\Invoke-PTTSweep.ps1
- Detection 
```
Get-SessionUsers | Invoke-PTTSweep
```
## Kerberoasting: request and detect 
- Request TGS
```
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
$Searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
$Searcher.PageSize = 1000

$Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(ServicePrincipalName=*))"

$SPN = $Searcher.FindAll() | Select Path, @{l='SPN'; e={$_.Properties.serviceprincipalname}}

foreach($spn in $SPN)
{
    Add-Type -AssemblyName System.IdentityModel
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.SPN
}
```
- Detect
```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
     *[System[(EventID=4769)]] 
     and
     *[EventData[Data[@Name='TicketEncryptionType'] and (Data='0x17' or Data='0x18')]]
   </Select>
  </Query>
</QueryList>
```

## AD persisyence detection
- Check if account management audit is enabled 
```
auditpol /get /category:"Account Management"
```
- Detect persistence **Get Get-SecurityGroupChanges.ps1**
```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]</Select>
  </Query>
</QueryList>

# from common security group 
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]</Select>
  </Query>
</QueryList>


# full xpath filter
$FilterXML = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]
    and
 *[EventData[Data[@Name='TargetUserName'] and (Data='Administrators' or Data='Domain Admins' or Data='Enterprise Admins')]]
    </Select>
  </Query>
</QueryList>
'@
$Logs = Get-WinEvent -FilterXml $FilterXML
ForEach ($L in $Logs) {
   [xml]$XML = $L.toXml()
   $TimeStamp = $XML.Event.System.TimeCreated.SystemTime
   $MemberName = $XML.Event.EventData.Data[0].'#text'
   $GroupName = $XML.Event.EventData.Data[2].'#text'
   $SubjectUserName = $XML.Event.EventData.Data[6].'#text'
 [PSCustomObject]@{'TimeStamp' = $TimeStamp; 'MemberName' = $MemberName; 'GroupName' = $GroupName; 'SubjectUserName' = $SubjectUserName; 'ChangeType' = "($EventID) $ChangeType" }
}
```
### User modification (Get Get-UserChanges.ps1)
```
# XPath filter for user account management events performed by damin user
<QueryList>
  <Query Id="0" Path="Security">
    <Select
Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and Task = 13824]]
    and 
    *[EventData[Data[@Name='SubjectUserName'] and
(Data='dadmin')]]
    </Select>
  </Query>
</QueryList>
```
### Golden ticket detection (Get Get-KerberosSettings.ps1, Get-LogonIds.ps1, Get-Tickets.ps1, Invoke-GoldenSweep.ps1)
```
Get-LogonIds | Get-Tickets | Select LogonId,StartTime,EndTime | Sort EndTime
Get-LogonIds | Get-Tickets | Invoke-GoldenSweep
```
## ELK 
- KQL Query for Sysmon ProcessCreate Events
```
host.hostname: "appsrv01" and data_stream.dataset : "windows.sysmon_operational" and process.name : "svchost.exe" and event.code: "1"
```
- KQL Query for Apache access log
```
"apache-access" and host.hostname: "web01" and not source.ip: 127.0.0.1
```
- KQL Query for Snort logs
```
tags : "snort.log" and network.type : "ipv4"
```
- OSQuery for text files on every Windows user's Desktop
```
select directory, filename from file where path like 'C:\Users\%\Desktop\%' and filename like '%.txt';
```
- OSQuery for processes listening on network ports
```
select distinct processes.name, listening_ports.port, listening_ports.address, processes.pid from processes join listening_ports on processes.pid = listening_ports.pid;
```
- OSQuery for all processes with outbound connections to nonstandard ports
```
select pos.pid, p.name, pos.local_address, pos.remote_address, pos.local_port, pos.remote_port from process_open_sockets pos join processes p on pos.pid = p.pid where pos.remote_port not in (80, 443) and pos.family = 2 and pos.local_address not in ("0.0.0.0", "127.0.0.1");
```

## Case 1 ELK
- KQL query to filter on Windows XP and suspect attacking IP
```
user_agent.os.full : "Windows XP" and source.address : "192.168.51.54"
```
- KQL query to filter out HTTP Not Found and HTTP Forbidden responses
```
user_agent.os.full : "Windows XP" and source.address : "192.168.51.54" and not http.response.status_code : (404 or 403)
```
### Phase One Detection Rules
- Enumeration
Threshold => "apache-access" and http.response.status_code: (404 or 403)
- Web command injection
Custom query => "apache-access" and (url.query : \*+\* or url.query : \*%20\* ) and http.response.status_code: 200

## Case 2 ELK
- Filtering on network activity from two suspect sources (either attacker or tunneled one)
```
source.ip : 192.168.51.54 or source.ip: 172.16.51.33
```
- KQL query to find logon failure and success from web01
```
source.ip: 172.16.51.33 and event.code: (4625 or 4624)
```
### Detection rule
- Define rule for SSH using root account
#Custom query
process.name : "sshd" and  user.name : "root" and system.auth.ssh.event : "Accepted"
- Rule to identify brute forcing authentication against  Windows machines.
#Threshold
event.code : "4625", group by source.ip >= 100
@Securuty Overide
if source.ip = "172.16.51.254" (snort machine) severity low

## Case 3 ELK (Persistence and Privilege Escalation)
- Filtering on all Sysmon events matching user offsec activity
```
agent.name: "appsrv01" and user.name: "offsec" and event.dataset : "windows.sysmon_operational"
```
- Filtering on all Sysmon events matching user adm1n activity
```
agent.name: "appsrv01" and user.name: "adm1n" and event.dataset : "windows.sysmon_operational"
```
- SQL query to get all logged in users from appsrv01
```
select user, strftime('%Y-%m-%d %H:%M:%S', time, 'unixepoch') as time, tty, type from logged_in_users;
```
### Detection rules
- Define rule for DLL Creation by PowerShell
#CustomQuery
event.code : 11 and process.name : "powershell.exe" and rule.name : DLL
- Detect PowerShell's access of lsass.exe
event.code: 10 and winlog.event_data.TargetImage : "C:\\Windows\\system32\\lsass.exe" and process.name: "powershell.exe"

## Case 4 ELK (Phase Four: Perform Actions on Domain Controller)
- Querying for any traffic from endpoints compromised by attacker
```
source.ip: 172.16.51.32 or source.ip: 172.16.51.33 or source.ip: 192.168.51.54
```
- Updated endpoint traffic query including string for suspicious PowerShell script
```
source.ip: 172.16.51.32 or source.ip: 172.16.51.33 or source.ip: 192.168.51.54 or "iw.ps1"
```
- ProcessCreate event of ntdsutil.exe on dc01
```
user.name: "adm1n" with process.name: "ntdsutil.exe" 
```
### Detection rules
- Custom query to detect execution of ntdsutil.exe
event.code: "1" and process.name: "ntdsutil.exe"


## Some commands 
```
#Search for processes by their names
pgrep syslogd
pgrep -l ssh
pgrep -l -u root

# Trace the process that has the /var/log/secure log file currently open
sudo lsof -p $(pgrep syslogd) | grep '/var/log/secure'

#journal (the first process responsible for catching log files)
journalctl -u sshd.service --since "1 hour ago"

#Empty log file
sudo truncate /var/log/auth.log --size 0

#Awk text between two stringd
sudo cat /var/log/apache2/modsec_audit.log | awk '/-A--/,/-F--/'

#Enabling aureport detailed keylogging
session required pam_tty_audit.so enable=*

sudo  aureport --tty

sudo cat /var/log/audit/audit.log | grep "type=TTY" | grep " uid=1002"
#data are in hex and we need to replace any occurrence of 0D with a printable white space value (20).

echo "657869740D" | sed 's/0D/20/g'  | xxd -r -

#PS and UID
ps u -C passwd

grep Uid /proc/2078/status
```


# Dectection method to implement
- filter every ip address 
- check number of event per ip
- Build a list of event ID and description 
- Same for Sysmon ID and Description (already integrated)
- Matching process ID and parent process ID
- Connect from sysmon ; do the stats of all remote ip address (number of connexion per IP address) 
- Check where ParentImage is C:\Windows\SysWOW64\cmd.exe or ends with cmd.exe (1) with NT AUTHORITY\IUSR user (2)
- Process: Where CommandLine is cmd and ParentImage between "C:\Program Files" (and optional) user is NT AUTHORITY\SYSTEM
- Process: C:\Windows\SysWOW64\cmd.exe or powershell run by NT AUTHORITY\SYSTEM; get the PID and search for all process having its PID as PPID
- Network: source - dest where image is in "C:\Program Files (x86)\Sync" or not in C:\Windows
- Check on UAC bypass (with fodhelper) to be updated (the ones with ##)
- Get-SecurityEvent where Service File Name contents `\\.\pipe\` (Service creation for privesc)
- Get-SysmonEvent 13 where TargetObject contents `HKLM\System\CurrentControlSet\Services` or Details contents `\\.\pipe\` (Service creation for privesc)
- Get-SysmonEvent 1 (process) where user is NT AUTHORITY\SYSTEM, ParentImage is C:\Windows\System32\services.exe, CommandLine contents `\\.\pipe\` (Service creation for privesc)
- Get-SysmonEvent 1 (process) where CommandLine contents 'C:\Windows\system32\sc.exe' and 'binpath' (Attacking Service)
- Get-SysmonEvent 1 (process) where ParentImage is 'C:\Windows\System32\net.exe' (Attacking Service)
- Get-SysmonEvent 13 (register) where TargetObject contents 'HKLM\System\CurrentControlSet\Services'
- Get-SecurityEvent where Service Account is LocalSystem and/or Service Start Type is 2 and/or Service File Name is custom path
- Get-SysmonEvent 3 (Network) where User: NT AUTHORITY\SYSTEM
- Search ScheduledTask where <RunLevel>HighestAvailable</RunLevel>; extract  <Command>C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe</Command>
- Print all service (Get-SecurityEvent with EventID 4697); print Service File Name: 
- Print all process (Get-SysmonEvent 1) where CommandLine or OriginalFileName contains 'sc.exe'
- Print network (Get-SysmonEvent 3) where User: NT AUTHORITY\SYSTEM; DestinationIp: (192.168.51.50 attacker) 
- Get-WDLogEvent where LevelDisplayName is Warning
- Get-WDLogEvent 1116 
- Check RealTimeProtection change at *HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection*
- Search custom path in *Path* and *Process Name* fields of *Get-WDLogEvent 1116*
- *Get-SysmonEvent 11* where *TargetFilename* ends with *.cmdline* and/or located at *C:\Users\offsec\AppData\Local\Temp\* (AMSI bypass c# running)
- *Get-SysmonEvent 11* where *TargetFilename* ends with *.dll* and/or located at *C:\Users\offsec\AppData\Local\Temp\* (AMSI bypass c# running)
- *Get-SysmonEvent 11* where *Image* contains 'csc.exe' and *TargetFilename* ends with *.dll* or *.cmdline*  (AMSI bypass c# running)
- *Get-SysmonEvent 1* where *CommandLine* contains with *csc.exe* and (*.dll* or *.cmdline*) (AMSI bypass c# running)
- *Get-PSLogEvent 4104* where *LevelDisplayName* is warning
- PTH : (EventID=4624) where LogonType is equal 9
- PTH : EventID 7045, 7036
- PTH : Successful login (4026), where LogonType is 3 and include NTLM as an authentication package name. (check xpath filter)
- Brute force domain: . .\Get-BadPwdCount.ps1, event id 4740, 
- Check Domain Admin connecting to standard users machine
- Implement XPath XML for terminal services
- Implement dectection of access to lsass.exe
- Command run with High integrity level or System

