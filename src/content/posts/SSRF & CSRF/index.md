---
title: SSRF & CSRF
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# SSRF & CSRF

## CSRF 跨站请求伪造

Cross-site requestforgery  跨站请求伪造

XSS攻击是跨站脚本攻击，CSRF攻击是请求伪造

`XSS`是实现`CSRF`的诸多途径中的一条，但并不是唯一的一条

> https://blog.csdn.net/qq_43378996/article/details/123910614
> 

### CSRF 攻击条件

1. 目标用户已经登录了网站，能够执行网站的功能
2. 目标用户访问了攻击者构造的`URL`（可以配合XSS）

### 黑盒判断CSRF安全问题

1. 看验证来源是否要求 - referer
2. 看凭据有无token
3. 看关键操作有无验证

### 如何找/挖掘

1. 直接复现看有没有
    
    成功→有
    
    失败→代码→缺陷过滤（绕过）→有
    
    失败→代码→完全过滤→没有
    

### 复现 - MetInfo5.3.1 CSRF

通过`csrf`跨站添加管理员，源代码网上可以找到

前提条件：

- 被攻击者是登陆着管理后台的
- 知道被攻击网站使用的是什么CMS

---

1. 进入网站后台，查看仅有的用户（被攻击者视角）
    
    ![image.png](image%2026.png)
    
2. 知道网站cms是MetInfo后我们到网上找源代码，然后本地搭建，抓取创建用户的数据包（攻击者视角）
    
    使用`CSRFTester` ，一个用于构建CSRf数据包的工具
    
    使用`CSRFTester` 抓取创建用户的数据包（在我们本地运行就行，只要是被攻击者是同一个cms）
    
3. 随便输入数据（攻击者视角），`CSRFTester` 然后开始抓取，点击创建用户`yun`后，返回`CSRFTester` 查看抓到的数据包，很明
4. 显的数据包，然后导出HTML（攻击者视角）
    
    ![image.png](image%2027.png)
    
5. 修改导出的HTML数据包，这一部分就是修改数据的，`yun`应该是用户名，下面`123`应该就是密码，我们修改用户名为`hehe` ，密码为`123456` ，然后吧多余的`post`表单删掉，就留下我们创建用户的表单 ，IP地址可以改为`127.0.0.1` ,因为被攻击者的网站可能在本地（攻击者视角）
    
    ![image.png](image%2028.png)
    
6. 构建完数据包后，我们构建一个XSS，点击后跳转到我们构建HTML地址，然后我们想方设法让被攻击者点击我们的XSS链接（攻击者视角）
7. 被攻击者出于好奇点了我们的含有XSS攻击的链接，自动跳转到我们的构建好的创建用户的HTML，此时因为管理员后台是登陆状态的，所以直接提交HTML表单即可（被攻击者视角）
    
    此时被攻击者点击了我们的链接
    
    他的后台就会偷偷的出现了一个新的管理员账户
    
    ![image.png](image%2029.png)
    

## SSRF 服务器请求伪造

> https://www.cnblogs.com/miruier/p/13907150.html
> 

Server Side RequestForgery   服务器端请求伪造

SSRF 形成的原因大都是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制

可以通过SSRF进行探针攻击（扫描内网机器）

### 可能出现漏洞的地方

1. 分享：通过URL地址分享网页内容
    
    ```jsx
    share.renren.com/share/buttonshare.do?link=http://www.baidu.com@10.10.16.1
    ```
    
2. 在线翻译
3. 图片、文章收藏功能
    
    ```jsx
    http://title.xxx.com/title?title=http://title.xxx.com/as52ps63de
    ```
    
4. 图片加载与下载
5. 从URL关键字中寻找
    
    `share,wap,url,link,src,source,target,u,display,sourceURl,imageURL,domain`
    

### 产生漏洞的函数

> https://blog.csdn.net/qq_43378996/article/details/124050308
>