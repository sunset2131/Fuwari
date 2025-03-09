---
title: Suricata 规则
published: 2025-03-09 16:49:16
tags: [应急响应]
category: 安全
draft: false
---

# Suricata 规则

> 如何使用Suricata：https://www.cnblogs.com/smileleooo/p/18169413 | 官方文档：https://docs.suricata.io/en/suricata-7.0.8/quickstart.html#basic-setup | snort语法
> 

https://github.com/al0ne/suricata-rules/tree/master/CobaltStrike

https://github.com/ainrm/cobaltstrike-suricata-rules ：其中的 **`checksum8_check.lua`** 改为

```java
function init (args)
    local needs = {}
    needs["http.uri"] = tostring(true)
    return needs
end

function match(args)
    local uri_raw = tostring(args["http.uri"])
    local uri = string.sub(uri_raw, 2, -1) -- 去除uri中的"/"
    local sum = 0

    for i=1,#uri do
        local x = string.sub(uri,i,i)
        sum = sum + string.byte(x)
    end

    local checksum = sum % 256
    if checksum == 92 or checksum == 93 then -- 匹配32或者64为应用
        return 1 -- 符合checksum8规则，匹配成功
    else 
        return 0 -- 不符合checksum8规则，匹配失败
    end
end
```

冰蝎 4.1 流量检测，仅对默认配置生效

```java
alert http any any <> any any (msg:"Chr1s：检测到冰蝎流量";\
	 http.method; content:"POST";\
	 http.content_type; content:!"multipart/form-data"; \
	 nocase; file.data; content:!"&"; \
	 http.content_len; byte_test:0,>=,4000,0,string,dec; \
	 http.header; content:"Connection|3a 20|Keep-Alive"; \
	 nocase; http.accept_enc; content:"gzip"; \
	 nocase; filestore; sid:66601001; rev:1;\
)
```