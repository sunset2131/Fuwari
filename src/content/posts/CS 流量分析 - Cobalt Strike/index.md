---
title: CS 流量分析 - Cobalt Strike
published: 2025-03-09 16:49:16
tags: [应急响应]
category: 安全
draft: false
---

# CS 流量分析 - Cobalt Strike

## Cobalt Strike

> https://forum.butian.net/share/1861 | https://mp.weixin.qq.com/s/CjsqWrm70HVEnolZrRD8oA | https://paper.seebug.org/1922/#22-dns-stagless
> 

版本：4.8

![image.png](image%2014.png)

## CS - HTTP Beacon

使用Beacon HTTP的监听器生成可执行文件，在上线前开始抓包，因为上线也会有数据包

上线后执行命令

![image.png](image%2015.png)

上线后协议是HTTP，过滤IP为测试机并且协议为HTTP

![image.png](image%2016.png)

1. Stage下载
    
    可执行文件 artifact.exe 执行后会有一个Payload下载过程，使用HTTP协议从指定服务器下载Payload
    
    ![image.png](image%2017.png)
    
    心跳包大小都差不多，其中HTTP请求路径不统一，但是都符合`checksum8` 规则，即：路径（这里是`NBYt`）的 ASCII 之和与 256 取余计算值等于 92（32位）或者93（64位）
    
    ```java
    public class EchoTest {
        public static long checksum8(String text) {
            if (text.length() < 4) {
                return 0L;
            }
            text = text.replace("/", "");
            long sum = 0L;
            for (int x = 0; x < text.length(); x++) {
                sum += text.charAt(x);
            }
            return sum % 256L;
        }
        public static void main(String[] args) throws Exception {
            System.out.println(checksum8("NBYt"));
        }
    }
    ```
    
    运行结果`93`，所以这是一个`x64`的后门程序
    
    将初始心跳包导出，并使用https://github.com/DidierStevens/DidierStevensSuite 里的`1768.py`进行解析
    
    ![image.png](image%2018.png)
    
    其中的`0x0007`是公钥
    
2. beacon上线
    
    随后beacon按照设置的频率以GET方法向服务器发起心跳请求，请求的Cookie携带靶机的信息
    
    ![image.png](image%2019.png)
    
    此时靶机能在CS客户端看到
    
    ![image.png](image%2020.png)
    
    对加密Cookie进行解密，在CS服务端文件夹中存在`.cobaltstrike.beacon_keys`文件，`.cobaltstrike.beacon_keys`文件里存储了一个序列化对象这个对象中包含着一个密钥对里面存储着RSA公私钥
    
    提取`.cobaltstrike.beacon_keys` 的公私钥 工具来自：https://5ime.cn/cobaltstrike-decrypt.html
    
    ```java
    # getkey.py
    import base64
    import javaobj.v2 as javaobj
    
    with open(".cobaltstrike.beacon_keys", "rb") as fd:
        pobj = javaobj.load(fd)
    
    def format_key(key_data):
        key_data = bytes(map(lambda x: x & 0xFF, key_data))
        formatted_key = base64.encodebytes(key_data).decode().replace('\n', '')  # Remove newline from base64 encoding
        return formatted_key
    
    privateKey = format_key(pobj.array.value.privateKey.encoded.data)
    publicKey = format_key(pobj.array.value.publicKey.encoded.data)
    
    print(f"privatekey:{privateKey}")
    print(f"publickey:{publicKey}")
    ```
    
    通过`python getkey.py` 即可获得公私钥
    
    ![image.png](image%2021.png)
    
    首先查看公钥是否和之前解析心跳包出来的一样，将公钥进行base64解密，然后转换为hex
    
    ![image.png](image%2022.png)
    
    对比之后是一样的，确认无误，那么现在就可以对Cookie里的（元数据）进行解密了
    
    ![image.png](image%2023.png)
    
    先对私钥进行转换
    
    ![image.png](image%2024.png)
    
    使用工具`cs-decrypt-metadata.py`  来自：https://github.com/DidierStevens/DidierStevensSuite
    
    使用格式：`python cs-decrypt-metadata.py -p 私钥 加密数据`
    
    解密数据后可以看到是测试机的信息，重要的是`Raw Key`
    
    ![image.png](image%2025.png)
    
3. 命令下发
    
    如果服务端有命令下发，则会放在心跳包的返回包中
    
    ![image.png](image%2026.png)
    
    前面执行的getuid
    
    ![image.png](image%2027.png)
    
    上面我们解密元数据已经拿到Rawkey
    
    ```java
    Raw key:  1b6dd2bf65431556fb49045c67d64ff5
     aeskey:  a8d0b3af8648119bc6e70db0b0ee4bd6
     hmackey: 9792d337dbcf622c79d1dd0ea21b0959
    ```
    
    ![image.png](image%2028.png)
    
    使用工具：`cs-parse-http-traffic.py` 来自https://github.com/DidierStevens/Beta
    
    我这里解不出来，说是`HMACkey`错误，但是检查无误，正常解码出来应该是带有`whomai`的字符串
    
4. 结果回传
    
    beacon处理完数据后，将数据通过POST方法回传
    
    ![image.png](image%2029.png)
    

## CS - HTTPS Beacon

HTTPS beacon的过程，在HTTP beacon的基础上进行了TLS握手加密

![image.png](image%2030.png)

## CS - DNS Beacon

![image.png](image%2031.png)

> https://forum.butian.net/share/380 | https://www.ddosi.org/cobaltstrike-hide/#2_DNS%E4%B8%8A%E7%BA%BF
> 

## 特征

### HTTP请求

http-beacon通信中，默认使用get方法向 `/dpixel`、`/__utm.gif`、`/pixel.gif` 等地址发起请求

可以在`Malleable C2 Profile`中设置

```java
# define indicators for an HTTP GET
http-get {
	# Beacon will randomly choose from this pool of URIs
	set uri "/ca /dpixel /__utm.gif /pixel.gif /g.pixel /dot.gif /updates.rss /fwlink /cm /cx /pixel /match /visit.js /load /push /ptj /j.ad /ga.js /en_US/all.js /activity /IE9CompatViewList.xml";

	client {
		# base64 encode session metadata and store it in the Cookie header.
		metadata {
			base64;
			header "Cookie";
		}
	}

	server {
		# server should send output with no changes
		header "Content-Type" "application/octet-stream";

		output {
			print;
		}
	}
}
```

以及回传数据时的URL`/submit.php`和参数`id`

```java
# define indicators for an HTTP POST
http-post {
	# Same as above, Beacon will randomly choose from this pool of URIs [if multiple URIs are provided]
	set uri "/submit.php";

	client {
		header "Content-Type" "application/octet-stream";

		# transmit our session identifier as /submit.php?id=[identifier]
		id {
			parameter "id";
		}

		# post our output with no real changes
		output {
			print;
		}
	}
```

同时请求头存在 cookie 字段并且值为 base64 编码后的非对称算法加密数据

![image.png](image%2032.png)

**心跳包解密**，抓包心跳包使用`1768.py`进行解密可以看到数据

![image.png](image%2018.png)

**结果回传**，beacon端处理完数据后，通过`POST`的方式回传数据，默认请求文件`submit.php?id=`

![image.png](image%2033.png)

### HTTPS 请求

**JA3和JA3S值(强特征)**，在ClientHello和ServerHello中（我突然发现和MSF的值是一样的），各类系统值也是不一样的，可以收集不同操作系统JA3值进行记录，下面是`Windows10`的beacon值

```java
72a589da586844d7f0818ce684948eea
f176ba63b4d68e576b5ba345bec2c7b7
```

**HTTPS证书**，默认不配置CS证书时，使用的时CS自带的证书，使用keytool进行查看，全是CS的特征，定位到查杀即可

```java
keytool -list -v -keystore cobaltstrike.store
```

```java
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
输入密钥库口令:  
密钥库类型: PKCS12
密钥库提供方: SUN

您的密钥库包含 1 个条目

别名: cobaltstrike
创建日期: 2025年1月18日
条目类型: PrivateKeyEntry
证书链长度: 1
证书[1]:
所有者: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike, L=Somewhere, ST=Cyberspace, C=Earth
发布者: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike, L=Somewhere, ST=Cyberspace, C=Earth
序列号: e1bd756753f87c21
生效时间: Sat Jan 18 00:56:26 EST 2025, 失效时间: Fri Apr 18 01:56:26 EDT 2025
证书指纹:
         SHA1: 10:D5:C1:FF:77:FF:27:88:61:9F:5B:46:B7:1E:56:5D:AC:AD:CE:61
         SHA256: 62:17:B0:0B:AE:0D:8B:D6:08:85:12:FB:88:9C:D7:BC:04:74:D0:91:B5:EC:AC:17:CF:39:3B:80:F1:22:3F:3B
签名算法名称: SHA384withRSA
主体公共密钥算法: 3072 位 RSA 密钥
版本: 3
```

### DNS

dns-beacon 通信中，默认使用 “cdn.”、“www6.”、“api.”、“www.”、“post.”  为开头发起 dns 请求，并且查询结果伴随 0.0.0.0、0.0.0.80、0.0.0.241 等非常规 IP 

### Checksum8

运行 staging 模式的pe文件，会向指定服务器的`checksum8` 路径发起请求来下载 stage

心跳包大小都差不多，其中HTTP请求路径不统一，但是都符合`checksum8` 规则，即：路径（这里是`NBYt`）的 ASCII 之和与 256 取余计算值等于 92（32位）或者93（64位）

同时命中以下三条规则则触发告警：

① 由客户端发起并与目标服务器建立连接：flow: established, to_server;

② 请求路径长度为5：urilen:4<>6;

③ 调用lua计算路径的ascii之和并与256做取余操作，结果为92：luajit:checksum8_check.lua 。

```java
public class EchoTest {
    public static long checksum8(String text) {
        if (text.length() < 4) {
            return 0L;
        }
        text = text.replace("/", "");
        long sum = 0L;
        for (int x = 0; x < text.length(); x++) {
            sum += text.charAt(x);
        }
        return sum % 256L;
    }
    public static void main(String[] args) throws Exception {
        System.out.println(checksum8("NBYt"));
    }
}
```

运行结果`93`，所以这是一个`x64`的后门程序