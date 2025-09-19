# Academy machine

IP address: 10.0.2.152

```
└─$ sudo arp-scan -l            
Interface: eth0, type: EN10MB, MAC: 08:00:27:d2:26:79, IPv4: 10.0.2.15
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.2.1        52:54:00:12:35:00       (Unknown: locally administered)
10.0.2.2        52:54:00:12:35:00       (Unknown: locally administered)
10.0.2.3        08:00:27:e6:9a:7b       (Unknown)
10.0.2.152      08:00:27:47:22:9e       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.856 seconds (137.93 hosts/sec). 4 responded

```


By watching the nmap output there is an interesting note - note.txt file in ftp server.

Resource: https://hackviser.com/tactics/pentesting/services/ftp

![alt text](image.png)

There is a note. Useful string: cd73502828457d15655bbd7a63fb0bc8

Try to check with a hash-identifier tool in kali. After open https://crackstation.net/ to decrypt the MD5 hash - student.

Command: ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.152/FUZZ




This one is interesting

![alt text](image-1.png)

Looking first on /academy directory, there is a Login page with valid credentials: 10201321:student

There is a function of changing or set a photo or avatar.

Try toupload the reverse shell:https://github.com/pentestmonkey/php-reverse-shell


![](image-2.png)

Privilege Escalation:

start a server on attacker machine with python:

python3 -m http.server 8081

Then downloas linpeas.sh
Resource:  https://github.com/peass-ng/PEASS-ng/releases/tag/20250904-27f4363e

mysql password: My_V3ryS3cur3_P4ss
User: grimmie

By using pspy because of the backup.sh:

![alt text](image-3.png)

Then use the bash to get the reverse shell from pentestmonkey:

![alt text](image-4.png)
