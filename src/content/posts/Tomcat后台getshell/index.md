---
title: Tomcat后台getshell
published: 2025-03-09 16:43:11
tags: [WEB安全,漏洞复现]
category: 安全
draft: false
---

# Tomcat后台getshell

## 环境

Tomcat支持在后台部署war文件，可以直接将webshell部署到web目录下。其中，欲访问后台，需要对应用户有相应权限。

- 需要上传war包，为什么不是tar.zip一类的
    
    ```python
    war包是用来进行Web开发时一个网站项目下的所有代码,包括前台HTML/CSS/JS代码,以及后台JavaWeb的代码。
    当开发人员开发完毕时,就会将源码打包给测试人员测试,测试完后若要发布则也会打包成War包进行发布。War包
    可以放在Tomcat下的webapps或word目录,当Tomcat服务器启动时，War包即会随之解压源代码来进行自动部署。
    ```
    
- 哪里找JSP马
    
    > https://github.com/tennc/webshell | https://blog.csdn.net/qq_43615820/article/details/116357744
    > 

## 利用后台上传war包getshell

1. 访问后台，找到上传`WAR`文件
    
    ![image.png](image%2011.png)
    
2. 制作`war`包
    
    ps：大马名不能是`getshell`之类的，较正常的就好
    
    使用`jar`命令制作（需要安装`JDK`）
    
    ```python
    jar cvf <name>.war <name>.jsp
    ```
    
    这里我将`2131.jsp`打包为`2131.war`
    
3. 选择`war`文件后上传
    
    ![image.png](image%2012.png)
    
    ![image.png](image%2013.png)
    
4. 我的包为蚁🗡的一句话马（一般用于反弹shell），所以使用蚁🗡进行测试
    
    ![image.png](image%2014.png)