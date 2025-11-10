# ReconQuiver - "侦察袖箭"，一款轻量化端口扫描和主机探测工具

## 简介
基于Go编写的轻量化端口扫描和主机探测工具，支持多种扫描/探测技术。
各种模式和方法可以自由切换，使用简单，代码通俗易懂，并附有详细注释，方便基于该工具进行再次改进和功能添加。
目前只支持Linux/系统，以下模式需要使用管理员权限运行：TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP(主机探测)。

### 端口扫描
包括四种扫描方法：全端口扫描，常见端口扫描，自定义端口扫描，自定义端口范围扫描。

包括六种扫描模式：TCP-CONNECT，TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP-CONNECT。

### 存活主机探测
包括三种探测方法：C段探测，自定义主机范围探测，自定义主机列表探测。

包括九种探测模式：ARP，ICMP-PING，ICMP-ADDRESSMASK，ICMP-TIMESTAMP，TCP-CONNECT，TCP-SYN，UDP-CONNECT，OXID，NETBIOS。

包括对主机MAC地址，主机信息(所属厂商，类型，操作系统，主机名)，主机状态，判断主机存活原因的获取

## 安装
直接下载zip压缩包，放到Linux上解压
```
unzip ReconQuiver-main.zip
```
进入项目目录并编译
```
cd ReconQuiver-main
go build -o reconquiver cmd/scanner/main.go
```
运行程序查看帮助信息，如果显示帮助信息说明安装成功
```
./reconquiver -h
```

## 使用说明
```
用法：./reconquiver [选项]

端口扫描模式
选项:
-t string    目标地址 (IP/域名)
-p string    指定端口 (如: 80,443,1000-2000)
-s string    扫描类型选择: T(TCP CONNECT),TS(SYN),TA(ACK),TF(FIN),TN(NULL),U(UDP) (默认: T)
-A           全端口扫描 (1-65535)
-C           常见端口扫描

主机探测模式
选项:
-d           启用主机发现模式
-B string    C段探测 (如: 192.168.1.0/24)
-E string    自定义IP范围探测 (如: 192.168.1.1-100)
-L           自定义IP列表探测 (逗号分隔或文件路径)
-m string    主机探测模式类型选择: A(ARP),ICP(ICMP-PING),ICA(ICMP-ADDRESSMASK),ICT(ICMP-TIMESTAMP),T(TCP-CONNECT),TS(TCP-SYN),U(UDP-CONNECT),N(NETBIOS),O(OXID) (默认: ICP)

公共选项:
-R int       并发扫描次数 (默认：300，一些模式默认选用其它合适的并发数量)

这些模式需要使用管理员权限运行：TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP(主机探测)。

端口扫描常用命令:
./reconquiver -t traget -A  -R 5000               TCP全端口扫描(推荐并发5000)
sudo ./reconquiver -t target -A -s TS -R 200      SYN全端口扫描(推荐并发200)
./reconquiver -t target -C -s U                   UDP常见端口扫描(使用默认并发500) 
sudo ./reconquiver -t target -C -s TA -R 5        ACK常见端口扫描(推荐并发5)

主机探测常用命令:
./reconquiver -d -B traget -m A                   ARP模式进行C段探测
./reconquiver -d -B traget -m ICP                 ICMP-PING模式进行C段探测
./reconquiver -d -B traget -m T                   TCP模式进行C段探测
sudo ./reconquiver -d -B traget -m TS             TCP-SYN模式进行C段探测
sudo ./reconquiver -d -B traget -m U              UDP模式进行C段探测
