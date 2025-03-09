---
title: Linux常规提权思路
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# Linux常规提权思路

> https://www.cnblogs.com/linuxsec/articles/11966287.html | https://www.cnblogs.com/sfsec/p/15163907.html
> 
1. SUID提权
    
    命令执行者要有二进制文件的执行权，命令执行者执行二进制文件时会获得该程序的属主身份。
    
    SUID权限只在程序执行过程中
    
    `find / -perm -u=s -type f 2>/dev/null` 收集具有SUID权限的文件
    
2. SUDO提权
    
    > https://www.huangmj.com/17116743651246.html#41-sudo-node
    > 
3. CMS的配置文件
    
    特别是关于数据库的，链接数据库需要提供账户密码，密码可能是系统中某些用户的密码，可尝试
    
4. 使用find寻找敏感文件
    
    backup或者pass，可能存在密码，用户多就找/home目录下文件内容带pass的，`grep -R -i pass /home/* 2>/dev/null`
    
5. `UDF`提权
    
    数据库自定义函数，需要拥有数据库`root`权限
    
6. 通过 `crontab`
    
    一般存放路径：`/etc/crontab` 和`/etc/cron.d/`
    
7. bash历史记录
    
    当前用户下家目录存在`.bash_history`  存在之前用户的命令记录，可能会有敏感内容
    
8. **`/etc/passwd`** 权限问题
    
    **如果我们能够对 `/etc/passwd`文件内容进行伪造、篡改，那就能很轻易的登录成功并获取任意用户权限**
    
    不过一般情况下，只有 root 用户拥有对 `/etc/passwd`文件的写入权限，其他用户均只有读取权限。但有时候由于系统管理员的错误配置，也会给我们带来可乘之机
    
    1. 如果具有 `/etc/passwd`的 w (写入) 权限，可以直接添加一个 root 权限的用户
    2. 如果 `/etc/passwd`中存储 root 用户密码哈希，可以使用 john 进行破解
9. 内核提权
    
    使用`searchexploit`来搜索内核版本，找到本地权限提升的使用
    
    脏牛漏洞(CVE-2016–5195)，又叫Dirty COW
    
    ```python
    # 影响范围
    Centos7/RHEL7     3.10.0-327.36.3.el7
    Cetnos6/RHEL6     2.6.32-642.6.2.el6
    Ubuntu 16.10      4.8.0-26.28
    Ubuntu 16.04      4.4.0-45.66
    Ubuntu 14.04      3.13.0-100.147
    Debian 8          3.16.36-1+deb8u2
    Debian 7          3.2.82-1
    ```