# PortQuiver - "端口袖箭"，一款轻量化的端口扫描工具

## 简介
基于Go编写的高性能端口扫描工具，支持多种扫描技术。

包括四种扫描方法：全端口扫描，常见端口扫描，自定义端口扫描，自定义端口范围扫描。

包括六种扫描模式：TCP-CONNECT，TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP-CONNECT。

各种模式和方法可以自由切换和选择，使用简单，代码通俗易懂，并附有详细注释，方便基于该工具进行再次改进和功能添加。

目前只支持Linux/系统，除了TCP CONNECT和UDP扫描，其它类型扫描都要使用管理员权限运行

## 安装
直接下载zip压缩包，放到Linux上解压
```
unzip PortQuiver-main.zip
```
进入解压完的文件夹
```
cd PortQuiver-main
```
编译所有文件
```
go build -o portquiver *.go
```
运行程序查看帮助信息，如果显示帮助信息说明安装成功
```
./portquiver -h
```

## 使用说明
```
选项:
-t string    目标地址 (IP/域名)  
-p string    指定端口 (如: 80,443,1000-2000)
-s string    扫描类型: CONNECT,SYN,ACK,FIN,NULL,UDP (默认: CONNECT)
（除了 TCP CONNECT 和 UDP 扫描，其它类型扫描要使用管理员权限）
    T：TCP CONNECT
    S：TCP SYN
    A：TCP ACK
    F：TCP FIN
    N：TCP NULL
    U：UDP
-A           全端口扫描 (1-65535)
-C           常见端口扫描
-R int       并发扫描次数 (默认：500)

示例:
./portquiver -t example.com -A
sudo ./portquiver -t example.com -A -s A
./portquiver -t 192.168.1.1 -p 80,443,22
./portquiver -t 192.168.1.1 -p 1-1000
./portquiver -t example.com -C -R 1000
