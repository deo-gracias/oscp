# Volatility
```
vol.py --info

#Scan for profile
vol.py -f memdump.mem kdbgscan | grep -i ntbuild
vol.py -f memdump.mem imageinfo


vol.py -f memdump.mem --profile=Win10.. -h

vol.py -f memdump.mem --profile=Win10.. envars
vol.py -f memdump.mem --profile=Win10.. hivelist
vol.py -f memdump.mem --profile=Win10.. hashdump Win7SP0x86 -y SYS_ADDR -s SAM_ADDR  

vol.py -f memdump.mem --profile=Win10.. pslist | grep --color=never 0x
vol.py -f memdump.mem --profile=Win10.. cmdline
vol.py -f memdump.mem --profile=Win10.. console
vol.py -f memdump.mem --profile=Win10.. pslist
vol.py -f memdump.mem --profile=Win10.. psscan
vol.py -f memdump.mem --profile=Win10.. pstree
vol.py -f memdump.mem --profile=Win10.. pstree | egrep 'lsass|services|winlogon'

#Dump process
vol.py -f memdump.mem --profile=Win10.. procdump -p 3360 --dump-dir=./
vol.py -f memdump.mem --profile=Win10.. memdump -p 3360 --dump-dir=./

#Scan 
vol.py -f memdump.mem --profile=Win10.. modscan

vol.py -f memdump.mem --profile=Win10.. malfind -p 1928,868
vol.py -f memdump.mem --profile=Win10.. hollowfind

vol.py --plugin=./winesap/plugin -f memory.mem --profile=Win10.. autoruns --match 
#(Better than default autorun plugin of vol)

vol.py -f memdump.mem --profile=Win10.. malprocfind

#Network scan
vol.py -f memdump.mem --profile=Win10.. netscan

## Baseline (Detect known/unknown processes, services and drivers) with https://github.com/csababarta/volatility_plugins : processbl, servicebl, driverbl

vol.py -f memdump.mem --profile=Win10.. processbl -h
vol.py -f memdump.mem --profile=Win10.. processbl -B clean.raw -U 2> /dev/null
vol.py -f memdump.mem --profile=Win10.. servicebl -B clean.raw -U 2> /dev/null
vol.py -f memdump.mem --profile=Win10.. driverbl -B clean.raw -U 2> /dev/null

#Prefetch
#Download the prefetch plugin from github superponible and put the file in the plugin folder
```


# Registry analysis
https://gist.github.com/exp0se/1bae653b790cf5571d20
