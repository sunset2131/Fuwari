---
title: HackMyVM-HMVLabs Chapter 1 Venus
published: 2025-03-09 16:23:40
tags: [HackMyVM]
category: 靶机
draft: false
---

# HMVLabs Chapter 1: Venus.

### Flag 1

```python
hacker@venus:~$ cat mission.txt
################
# MISSION 0x01 #
################

## EN ##
User sophia has saved her password in a hidden file in this folder. Find it and log in as sophia.

## ES ##
La usuaria sophia ha guardado su contraseña en un fichero oculto en esta carpeta.Encuentralo y logueate como sophia.

```

```python
hacker@venus:~$ ls -al
total 44
drwxr-x--- 1 root   hacker 4096 Apr  5  2024 .
drwxr-xr-x 1 root   root   4096 Apr  5  2024 ..
-rw-r----- 1 root   hacker   31 Apr  5  2024 ...
-rw-r--r-- 1 hacker hacker  220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 hacker hacker 3526 Apr 23  2023 .bashrc
-rw-r----- 1 root   hacker   16 Apr  5  2024 .myhiddenpazz
-rw-r--r-- 1 hacker hacker  807 Oct  8 18:39 .profile
-rw-r----- 1 root   hacker  287 Apr  5  2024 mission.txt
-rw-r----- 1 root   hacker 2542 Apr  5  2024 readme.txt
hacker@venus:~$ cat .myhiddenpazz
Y1o645M3mR84ejc
```

```python
hacker@venus:~$ su sophia
Password:
sophia@venus:/pwned/hacker$ ls
```

```python
sophia@venus:/pwned/hacker$ cd ~
sophia@venus:~$ ls
flagz.txt  mission.txt
sophia@venus:~$ cat flagz.txt
8===LUzzNuv8NB59iztWUIQS===D~~
```

### Flag 2

```python
sophia@venus:~$ cat mission.txt
################
# MISSION 0x02 #
################

## EN ##
The user angela has saved her password in a file but she does not remember where ... she only remembers that the file was called whereismypazz.txt

## ES ##
La usuaria angela ha guardado su password en un fichero pero no recuerda donde... solo recuerda que el fichero se llamaba whereismypazz.txt
```

```python
sophia@venus:~$ find / -name whereismypazz.txt 2>/dev/null
/usr/share/whereismypazz.txt
sophia@venus:~$ cat /usr/share/whereismypazz.txt
oh5p9gAABugHBje
```

```python
sophia@venus:~$ su angela
Password:
angela@venus:/pwned/sophia$ cd ~
angela@venus:~$ ls
findme.txt  flagz.txt  mission.txt
angela@venus:~$ cat flagz.txt
8===SjMYBmMh4bk49TKq7PM8===D~~
```