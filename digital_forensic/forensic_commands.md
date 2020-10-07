# Digital forensic command line

## Evidence acquisition 

### Collecting Network evidence
#### TcpDump & RawCap
```
#Listing interface availbale for capturing packet
tcpdump -D
#Verbose capture
tcpdump -i ens33 -v
#Saving analyzed log in file 
tcpdump -i ens33 -vvv -w capture.pcap
#Specifying the source host
tcpdump -i ens33 src host 192.168.10.54
#Specifying the destination host
tcpdump -i ens33 dst host 162.4.5.23

#RawCap.exe (For Windows)
RawCap.exe -help

RawCap.exe 5 RawCap.pcap
#Here 5 is the n0 of interface displayed in the RawCap help 
```

#### Mergecap 
Mergecap allows to merge combine multiple packet capture files from different source
```
mergecap -help
mergecap -w switches.pcap switch1.pcap switch2.pcap switch3.pcap
```
#### Editcap 
Editcap allows analysts to manipulate the packet capture files into smaller segments for easier review. The default split is 50,000 packet segments
```
editcap -F pcap -c evidence.pcap split.pcap
editcap -F pcap-t+600 evidence.pcap split.pcap
```

### Acquiring Host-Based Evidence
Different levels of volatility of digital evidence that should be taken into account when determining the order of acquisition:

1. CPU Registers 
2. RAM
3. PageFile or SwapFile 
4. Storage Drives: SSD,HDD,USB

**Local acquisition tools**
+ FTK Imager
+ Winpmem (https://winpmem.velocidex.com/) *Available for Windows, Linux and Mac*
```
winpmem-2.1.exe --format raw -o e:\Laptop1
#Remote mem collection
C:/winpmem-2.1.exe - | nc 192.168.0.56 4455
```
+ RAM Capturer

Capturing volatile data in VMware include the following processes
1. Pause the system
2. Transfer the VMSS and VMEM files to a removable media source
3. To create the .dmp (composed of VMSS and VMEM files) using cmss2core; tools from VMWARE
`C:\Program Files (x86)\VMware\VMware Workstation>vmss2core.exe suspect.vmss suspect.vmem`

`C:\Program Files (x86)\VMware\VMware Workstation>vmss2core.exe -W suspect.vmss suspect.vmem`

**Collecting log from event viewer**
```wevtutil epl<Log Type> E:\<FileName>.evtx```

**FTK Imager also allows for the capture of registry key settings and other information**
1. Open FTK Imager and navigate to the File tab.
2. Click on Obtain Protected Files. 
3. Click on Browse... and navigate to the evidence directory location.
4. Next, click the radio button for Password recovery and all registry files and click
OK. Once the tool completes, the registry and password data will be transferred to the evidence  folder. This command directs FTK Imager so that it obtains the necessary registry files to recover the system passwords. These include the user, system, SAM, and NTUSER.DAT files. From here, analysis can take place before the imaging process.

**Another tool really helpful and fast is CyLR.exe that is a standalone application**
`CyLR.exe -od out_dir -of out_file `

**As for MAGNET Encrypted Disk Detector, it can help to detect whether or not Disk has been encrypted**

### Forensic Imaging
Prior to imaging, we have to :
1. Weep the drive using **Eraser** application with US DoD 5220.22-M (8-306./E) (3 Pass) option selected
2. Set en encryption sofware (*Like VeaCrypt*) for the evidences that will be collected. This allow to secure the data. A good option is to reseve 2 partitions, one for tools and the other for data recovered from forensic.

### Imaging Techniques
#### Dead imaging
+ **Imaging using FTK Imager** (with E01 format)
+ **Remote acquisition with F-Response**
+ **In Linux with dc3dd**

`dc3dd if=dev/sdbof=ideapad.img hash=md5 log=dc3ddlog.txt`

## Analyzing evidences 

### Analyzing Network evidence

+ DNS blacklists
https:/​ / ​ bitbucket.​ org/​ ethanr/​ dns-​ blacklists/

This script takes a text file created by the log source or analyst and compares it to lists of IP addresses and domains that have been blacklisted

+ SIEM tools
+ Elastic Search
+ Analyzing NetFlow

**Malware traffic analysis sample :** http://malware-traffic-analysis.net/

+ Dnstop
Dnstop parses packet capture
files and ascertains the sources and count of DNS queries from internal hosts
`dnstop 2019-03-13-Emotet-with-Trickbot.pcap`

+ Moloch
Moloch is an open source packet capture and search system that allows analysts and responders to examine large network packet captures.

+ Wireshark

### Analyzing System memory
#### Redline

#### Volatility
```
#for windows memory
##Image information
volatility -f cridex_laptop.mem imageinfo

##Process list
volatility -f cridex_laptop.mem -profile=WinXPSP2x86 pslist

##Process scan
volatility -f cridex_laptop.mem -profile=WinXPSP2x86 psscan

##Process tree
volatility -f cridex_laptop.mem -profile=WinXPSP2x86 pstreee

##DLL list
volatility -f cridex_laptop.mem -profile=WinXPSP2x86 -p 1640 dlllist

##Process xview
volatility -f cridex_laptop.mem -profile=WinXPSP2x86 psxview

##Network connexion scan
volatility -f cridex_laptop.mem -profile=WinXPSP2x86 connscan


```

#### Others search
```
strings cridex_laptop.mem | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
strings cridex_laptop.mem | grep "http://"
```

### Log analysis 
Windows Logs are stored offline in C:\Windows\System32\winevt\logs
+ 4624 and 4634—logon and logoff
+ 4625—account failed logon
+ 4672—special privileges assigned to new logon (Good for detecting privesc)
+ 4688—a new process has been created (Good for detecting programm run)
+ 4768-4773—Kerberos service (Good for detecting TGT TGS etc)
+ 5140—a network share object was accessed
+ 7045—a new service was installed

Events logs can be collected 
+ via scripts using wevtutil epl Setup,System,Security,Application
+ via CyLR.exe

To acquire the log files from a local system and send them to a Skadi instance, proceed as follows:
`CyLR.exe -s 192.168.207.130:22 -u skadi -p skadi`

#### Analysis of suspicious Event Log
**DeepBlueCLI:** https:/​/github.​com/sans-blue-​team/​DeepBlueCLI
`.\DeepBlue.ps1 Security.evtx`

**Tools for triage**
+ Event Log Explorer: https://eventlogxp.com/​
+ Skadi: https://github.com/orlikoski/Skadi/
```
#From victim 
CyLR.exe -s 192.168.49.132:22 -u skadi -p skadi

#On skadi console
cdqr in:alien-pc.zip out:Results -z -max_cpu
cdqr in:Results/alien-pc.plaso -plaso_db -es_kb winevt
```