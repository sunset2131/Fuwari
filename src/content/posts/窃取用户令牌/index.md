---
title: 窃取用户令牌
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# 窃取用户令牌

1. **使用 `incognito` 模块**
    
    ```bash
    meterpreter > use incognito
    ```
    
    - `incognito` 是 Meterpreter 中的一个模块，允许你查看当前系统中的用户令牌，并模拟其他用户的令牌。
    - 该模块可以列出和模拟当前目标机器上可用的所有用户令牌。
2. **列出可用令牌**
    
    ```bash
    meterpreter > list_tokens -
    ```
    
    - `list_tokens -u` 命令列出了当前目标系统中可用的用户令牌。
    - 你看到的输出是目标机器上所有的用户账户以及它们的相关权限信息，包括：
        - **NT AUTHORITY\LOCAL SERVICE** 和 **NT AUTHORITY\NETWORK SERVICE**：是 Windows 系统上的低权限服务账户。
        - **NT AUTHORITY\SYSTEM**：是 Windows 系统中的高权限账户，拥有最高的系统访问权限。
        - **TEST\administrator** 和 **WIN2008\Administrator**：是两个本地或域用户账户，通常是管理员账户。
3. **模拟 `TEST\administrator` 用户**
    
    ```bash
    meterpreter > impersonate_token "TEST\administrator"
    ```
    
    - `impersonate_token "TEST\administrator"` 命令使 Meterpreter 会话模拟 `TEST\administrator` 用户的令牌。
    - 如果成功模拟了该用户的令牌，你将获得该用户的权限，这意味着你将能够以 `TEST\administrator` 用户的身份执行操作，拥有该账户的权限。
4. **成功模拟令牌**
    
    ```bash
    [+] Delegation token available
    [+] Successfully impersonated user TEST\administrator
    ```
    
    - 这意味着令牌模拟操作已经成功完成，当前 Meterpreter 会话拥有 `TEST\administrator` 用户的权限。
    - 可以执行如查看和修改文件、执行命令、访问其他资源等操作，所有这些都将作为 `TEST\administrator` 用户执行。