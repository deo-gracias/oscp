# OSDA 

## ToDo
- https://portal.offsec.com/courses/soc-200/books-and-videos/modal/modules/windows-server-side-attacks/web-application-attacks/extra-mile

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

## Status & SubStatus code
C000006D (Status) => bad username or authentication information
C000006A (SubStatus) => bad username or authentication information

## Sysmon ID 
1 => Process created
3 =>  Network connection
11 => File created

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

