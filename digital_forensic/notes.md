# Note to keep in mind doing memory forensic
- There is **only one lsass** process in the memory
- **lsass.exe** should everytime has as parent process **winlogon.exe** in some system wininit.exe
- **svchost.exe** should everytime has as parent process **services.exe**