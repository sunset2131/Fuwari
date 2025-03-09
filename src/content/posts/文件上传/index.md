---
title: 文件上传
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# 文件上传

## 概述

![image.png](image%2030.png)

通常防范有：前端检测`JavaScript`，后端检测，后缀名检测，黑名单，白名单，文件头，`MIME` ，内容检测二次渲染等

绕过：前端验证可以修改`js`，后缀名大小写绕过，解析漏洞,黑名单扩展名的漏网之鱼，截断上传，双写绕过,语言特性

> https://cloud.tencent.com/developer/article/1938541
> 

### 常见文件头 & 标识

1. **GIF**
    - 文件头标识：`GIF87a` 或 `GIF89a`
    - 十六进制：`47 49 46 38 37 61`（GIF87a）或 `47 49 46 38 39 61`（GIF89a）
2. **JPEG**
    - 文件头标识：`ÿØÿà`（十六进制表示 `FF D8 FF E0`）
    - 十六进制：`FF D8 FF E0` 或 `FF D8 FF E1`（不同的JPEG版本可能有些微差异）
3. **PNG**
    - 文件头标识：`\x89PNG\r\n\x1A\n`
    - 十六进制：`89 50 4E 47 0D 0A 1A 0A`
4. **BMP**
    - 文件头标识：`BM`
    - 十六进制：`42 4D`
5. **PDF**
    - 文件头标识：`%PDF`
    - 十六进制：`25 50 44 46`
6. **ZIP**
    - 文件头标识：`PK`
    - 十六进制：`50 4B 03 04`
7. **RAR**
    - 文件头标识：`Rar!`
    - 十六进制：`52 61 72 21 1A 07 00`
8. **EXE**
    - 文件头标识：`MZ`
    - 十六进制：`4D 5A`
9. **MP3**
    - 文件头标识：ID3标签
    - 十六进制：`49 44 33`
10. **WAV**
    - 文件头标识：`RIFF`
    - 十六进制：`52 49 46 46`
11. **TIFF**
    - 文件头标识：`II` 或 `MM`
    - 十六进制：`49 49 2A 00` 或 `4D 4D 00 2A`
12. **ISO**
    - 文件头标识：`CD001`
    - 十六进制：`43 44 30 30 31`

### htaccess文件（文件解析漏洞）

`htaccess`文件是`Apache`服务器中的一个配置文件，它负责相关目录下的网页配置。

- **上传覆盖.htaccess文件，重写解析规则，将上传的图片马以脚本方式解析**

```jsx
# 所有GIF文件
<IfModule mime_module>
	AddHandler php5-script .gif          
	SetHandler application/x-httpd-php   
</IfModule>
# 特定gif文件
<FilesMatch "自定义.gif">
	SetHandler application/x-httpd-php
	AddHandler php5-script .gif
</FilesMatch>
```

### 复现 - Apache 换行解析 **(CVE-2017-15715)**

> https://vulhub.org/#/environments/httpd/CVE-2017-15715/
> 

条件：Apache HTTPd `2.4.0~2.4.29`，可以绕过黑名单限制

在解析PHP时，`1.php\x0A`将被按照PHP后缀进行解析，导致绕过一些服务器的安全策略。

1. 使用vulhub进入靶场
    
    ![image.png](image%2031.png)
    
2. 抓个空白包
    
    ![image.png](image%2032.png)
    
    发现版本存在换行解析漏洞
    
3. 尝试上传带有phpinfo的1.php文件得到的相应包如下
    
    ```bash
    POST / HTTP/1.1
    Host: 192.168.75.52:8080
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate, br
    Content-Type: multipart/form-data; boundary=---------------------------139649390739867334813226318500
    Content-Length: 364
    Origin: http://192.168.75.52:8080
    Sec-GPC: 1
    Connection: keep-alive
    Referer: http://192.168.75.52:8080/
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i
    
    -----------------------------139649390739867334813226318500
    Content-Disposition: form-data; name="file"; filename="1.php"
    Content-Type: application/octet-stream
    
    <?php phpinfo();?>
    -----------------------------139649390739867334813226318500
    Content-Disposition: form-data; name="name"
    
    1.php
    -----------------------------139649390739867334813226318500--
    
    ```
    
    ![image.png](image%2033.png)
    
    badfile上传失败，随后上传1.php.jpg发现上传成功，所以是黑名单拦截
    
    ![image.png](image%2034.png)
    
4. 利用该版本漏洞尝试
    
    思路是： 修改`1.php`后的hex为`0a` 
    
    我们多打几个`a`，方便找出php后面，`a`的hex为`61`
    
    ![image.png](image%2035.png)
    
    很明显可以找到
    
    ![image.png](image%2036.png)
    
    将第一个改为0a
    
    ![image.png](image%2037.png)
    
    改完之后换行了，然后删除多余的a，但是不要多删，保持换行状态
    
    ![image.png](image%2038.png)
    
    并修改名字(除了1.php以外的名字)
    
    ![image.png](image%2039.png)
    
    上传成功
    
5. 随后访问2.php，但是后面要加上%0a
    
    ![image.png](image%2040.png)
    

## 黑&白盒寻找漏洞思路

### 黑盒:寻找一切存在文件上传的功能应用

1、个人用户中心是否存在文件上传功能

2、后台管理系统是否存在文件上传功能

3、字典目录扫描探针文件上传构造地址

4、字典目录扫描探针编辑器目录构造地址

### 白盒:看三点，中间件，编辑器，功能代码

1、中间件直接看语言环境常见搭配

2、编辑器直接看目录机构或搜索关键字

3、功能代码直接看源码应用或搜索关键字