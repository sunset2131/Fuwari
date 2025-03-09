---
title: HackMyVM-Runas
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Runas.

windows靶机

> https://hackmyvm.eu/machines/machine.php?vm=Runas
> 

## 信息收集 & 扫描

```c
nmap -sP 192.168.56.0/24               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 09:49 EST
Nmap scan report for 192.168.56.1
Host is up (0.00028s latency).
MAC Address: 0A:00:27:00:00:23 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00024s latency).
MAC Address: 08:00:27:C8:55:1D (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.5
Host is up (0.00027s latency).
MAC Address: 08:00:27:C0:A2:2F (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
```

```c
nmap -sT -min-rate 10000 -p- 192.168.56.5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 09:51 EST
Warning: 192.168.56.5 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.56.5
Host is up (0.00065s latency).
Not shown: 64645 closed tcp ports (conn-refused), 878 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
MAC Address: 08:00:27:C0:A2:2F (Oracle VirtualBox virtual NIC)
```

存在`445`端口，可能存在永恒之蓝

```c
nmap -sT -sV -O -p 80,135,139,3389,445 192.168.56.5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 10:00 EST
Nmap scan report for 192.168.56.5
Host is up (0.00061s latency).

PORT     STATE SERVICE        VERSION
80/tcp   open  http           Apache httpd 2.4.57 ((Win64) PHP/7.2.0)
135/tcp  open  msrpc          Microsoft Windows RPC
139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds   Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.94SVN%I=7%D=1/2%Time=6776AA10%P=x86_64-pc-linux-gnu%r(
SF:TerminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x03\0\x08\0\x0
SF:3\0\0\0");
MAC Address: 08:00:27:C0:A2:2F (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
Network Distance: 1 hop
Service Info: Host: RUNAS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

```c
nmap -script=vuln -p 80,135,139,445,3389 192.168.56.5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 10:02 EST
Nmap scan report for 192.168.56.5
Host is up (0.00094s latency).

PORT     STATE SERVICE
80/tcp   open  http
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-trace: TRACE is enabled
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|_  /: Root directory w/ directory listing
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
MAC Address: 08:00:27:C0:A2:2F (Oracle VirtualBox virtual NIC)

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
```

还是先从`80`端口开始渗透

## web渗透

![image.png](image%205.png)

点击`index.php` 

![image.png](image%206.png)

看着像是文件包含，尝试常规的文件（靶机是windows环境）

读取`system.ini`成功

![image.png](image%207.png)

再尝试读取别的，我输入了一个不存在文件夹，爆出了服务器的绝对路径`C:\Apache24\htdocs\`

![image.png](image%208.png)

尝试读取配置文件发现读取失败，尝试了伪协议后也发现无效

尝试直接读取`flag`文件，读取成功…

`HMV{Username_Is_My_Hint}`

![image.png](image%209.png)

再读取用户`flag` ，也可以

![image.png](image%2010.png)

`HMV{User_Flag_Was_A_Bit_Bitter}`

![image.png](image%2011.png)