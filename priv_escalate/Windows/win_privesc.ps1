mkdir C:\Windows\Temp\test

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


print_output("System detail")
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"


print_output("List all env variables")
Get-ChildItem Env: | ft Key,Value

print_output("Listing drive")
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

print_output("Current user Local Group")
Get-LocalGroup | ft Name

print_output("Checking Administrator group member")
Get-LocalGroupMember Administrators  2> C:\windows\temp\test\null.txt  | ft Name, PrincipalSource
Get-LocalGroupMember Administrateurs  2> C:\windows\temp\test\null.txt  | ft Name, PrincipalSource

print_output("Checking Impersonate Privilege")
whoami /priv | findstr /i Impersonate

print_output("Checking Computer Users ")
Get-LocalUser | ft Name,Enabled,LastLogon

print_output("Checking computer information")
net accounts

print_output("Network addresses")
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address

print_output("Localhost listening connections")
netstat -ano | findstr /i LISTENING | findstr "127.0.0.1"

print_output("Listening connections")
netstat -ano | findstr /i LISTENING | findstr  /V "127.0.0.1"

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
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue

print_output("Checking saved wifi ")
cmd /c "netsh wlan show profile"
#for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on

print_output("Getting Auto-Login in Register")
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2> C:\windows\temp\test\null.txt  | findstr "DefaultUserName DefaultDomainName DefaultPassword" 

print_output("PowerShell history")
cat (Get-PSReadlineOption).HistorySavePath

print_output("Getting process running only localy")
$a=netstat -ano | findstr /i LISTENING | findstr "127.0.0.1"
$b=$a[1..$a.count] | ConvertFrom-String | select p6
$local_process_id = @()
foreach ($proc in $b){
    if ($local_process_id -notcontains $proc.p6) {$local_process_id += $proc.p6 }
}

foreach($proc in $local_process_id){
    Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Handle -eq $proc} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}},Path,CommandLine | ft -AutoSize -Wrap
    #Get-Process -ID $proc | select Name, Id, Path
}

print_output("Getting others process running")
$a=netstat -ano | findstr /i LISTENING | findstr /V "127.0.0.1"
$b=$a[1..$a.count] | ConvertFrom-String | select p6
$local_process_id = @()
foreach ($proc in $b){
    if ($local_process_id -notcontains $proc.p6) {$local_process_id += $proc.p6 }
}

foreach($proc in $local_process_id){
    Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Handle -eq $proc -and $_.Name -notlike "svchost.exe" -and $_.Name -notlike "lsass.exe" -and $_.Name -notlike "services.exe"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}},Path,CommandLine | ft -AutoSize -Wrap
    #Get-Process -ID $proc | select Name, Id, Path | where-Object {$_.Name -notlike "svchost" -and $_.Name -notlike "lsass" -and $_.Name -notlike "services"}
}

print_output("Process running as another user")
tasklist /v /fi "username ne N/A" /fi "username ne $env:UserName"

print_output("Process running as current user")
tasklist /v /fi "username eq $env:UserName"

print_output("Software installed on the computer")
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

print_output("Software installed for the current user")
$InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

print_output("Scheduled tasks")
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

print_output("Startup tasks")
wmic startup get caption,command

print_output("Hijacked dll")
$candidate_process_id = @()
$a = Get-Process | Where-Object {$_.Path}
$b=$a.id




$a=netstat -ano | findstr /i LISTENING | findstr "127.0.0.1"
$b=$a[1..$a.count] | ConvertFrom-String | select p6
$local_process_id = @()
foreach ($proc in $b){
    if ($local_process_id -notcontains $proc.p6) {$local_process_id += $proc.p6 }
}

foreach($proc in $local_process_id){
    Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Handle -eq $proc} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}},Path,CommandLine | ft -AutoSize -Wrap
    #Get-Process -ID $proc | select Name, Id, Path
}