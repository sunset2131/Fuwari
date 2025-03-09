---
title: 文件包含
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# 文件包含

通常搭配文件上传来使用，因为文件包含你需要知道文件名，搭配伪协议等

文件包含又分为:`LFI` `local file include` 本地文件包含 和 `RFI` `remote file include` 远程文件包含

## 思路

`local file include`

1. 通过文件上传，上传文件在服务器上
2. 没有文件上传，借助日志文件（UA），session文件写入
3. 伪协议没有上传文件也能进行PHP代码执行，读文件，写文件（编码算法转换）

![image.png](image%2041.png)

## 伪协议

### 条件

- `allow_url_fopen`:off/on
- `allow_url_include` :off/on

### 使用方法

[segmentfault.com](https://segmentfault.com/a/1190000018991087)

1. **`file://` 用于访问本地文件系统**
    
    ```php
    file://E:\phpStudy\PHPTutorial\WWW\phpinfo.txt
    ```
    
2. **`php://`** 有`php://input`，`php://output`，`php://fd`，`php://memory`，`php://temp`，`php://filter` 比较常用的是`input`和`filter` 
    
    其中`php://filter` 有字符串过滤器，转换过滤器，压缩过滤器，加密过滤器
    
    ```php
    php://filter/read=convert.base64-encode/resource=[文件名]
    php://filter/resource=[文件名] 直接读取
    php://input + [POST DATA]
    ```
    
3. **`zip:// & bzip2:// & zlib://`** 尚未了解
    
    ```php
    zip://[压缩文件绝对路径]%23[压缩文件内的子文件名]
    ```
    
4. **`data://`** 
    
    ```php
    data://text/plain,<?php%20phpinfo();?>
    data://text/plain;base64,<-base64编码->
    ```
    
5. **`http:// & https://`** 
6. **`phar://`** 

## session条件竞争

默认保存路径：`/tmp` 或 `/var/lib/php/session`

```php
# 必备条件

session.upload_progress.enabled = on:该参数设置为On时，才会进行文件上传进度的记录。

session.upload_progress.cleanup = on:该参数开启时，会在文件上传结束时对用户session内容进行自动清除。

session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS":	该参数与prefix作为我们的键名。方便我们的shell编写，可控。

session.upload_progress.prefix = "upload_progress_":该参数表示与name一起构成我们的键名。
```

[【文件包含&amp;条件竞争】详解如何利用session.upload_progress文件包含进行... - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/288430.html)

php.ini中`session.use_strict_mode`选项默认是0，在这个情况下，用户可以自己定义自己的sessionid，例如当用户在cookie中设置`sessionid=Lxxx`时，PHP就会生成一个文件`/tmp/sess_Lxxx`，此时也就初始化了session，并且会将上传的文件信息写入到文件`/tmp/sess_Lxxx`中去

利用Python的多线程，进行**条件竞争**

## filter使用iconv来绕过

```php
convery.iconv.*的使用有两种方法:
convert.iconv.<input-encoding>.<output-encoding> 
 
convert.iconv.<input-encoding>/<output-encoding>
```

常用 `ucs-2be` ，`ucs-2le` 

思路：先用`linux`对`payload`进行编码，之后使用`filter`对传入`payload`进行解码，例如`ctfshow - web117`

## windows下文件包含

1. 尝试读取 `c:\WINDOW\system.ini`
2. 成功读取剩下的常规操作