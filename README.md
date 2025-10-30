# ReconQuiver - "侦察袖箭"，一款轻量化端口扫描和主机探测工具

## 简介
基于Go编写的轻量化端口扫描工具，支持多种扫描技术。

各种模式和方法可以自由切换和选择，使用简单，代码通俗易懂，并附有详细注释，方便基于该工具进行再次改进和功能添加。

目前只支持Linux/系统，以下模式需要使用管理员权限运行：TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL。

### 端口扫描
包括四种扫描方法：全端口扫描，常见端口扫描，自定义端口扫描，自定义端口范围扫描。

包括六种扫描模式：TCP-CONNECT，TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP-CONNECT。

### 存活主机探测
包括三种探测方法：C段探测，自定义主机范围探测，自定义主机列表探测。

包括九种探测模式：ARP，ICMP-PING，ICMP-ADDRESSMASK，ICMP-TIMESTAMP，TCP-CONNECT，TCP-SYN，UDP-CONNECT，OXID，NETBIOS。

## 安装
直接下载zip压缩包，放到Linux上解压
```
unzip reconQuiver-main.zip
```
进入解压完的文件夹
```
cd reconQuiver-main
```
编译所有文件
```
go build -o reconquiver *.go
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

主机发现模式
选项:
-d           启用主机发现模式
-B string    C段探测 (如: 192.168.1.0/24)
-E string    自定义IP范围探测 (如: 192.168.1.1-100)
-L           自定义IP列表探测 (逗号分隔或文件路径)
-m string    主机探测模式类型选择: A(ARP),ICP(ICMP-PING),ICA(ICMP-ADDRESSMASK),ICT(ICMP-TIMESTAMP),T(TCP-CONNECT),TS(TCP-SYN),U(UDP-CONNECT),N(NETBIOS),O(OXID) (默认: ICP)

公共选项:
-R int       并发扫描次数 (默认：500)

示例
端口扫描:
./reconquiver -t example.com -A                    //对 example.com 的全端口进行 CONNECT 扫描
sudo ./reconquiver -t example.com -A -s A          //对 example.com 的全端口进行 ACK 扫描
./reconquiver -t 192.168.1.1 -p 80,443,22          //对 192.168.1.1 的 80,443,22 端口进行 CONNECT 扫描
sudo ./reconquiver -t example.com -C -R 1000 -s S  //对 example.com 的常见端口进行并发 1000 的 SYN 扫描

主机发现:
./reconquiver -d -B 192.168.1.0/24 -m ICP         //对192.168.1.0/24进行C段ICMP-PING探测
./reconquiver -d -E 192.168.1.1-100 -m A          //对192.168.1.1-100的主机进行ARP探测
./reconquiver -d -L 192.168.1.1,192.168.1.2 -m T  //对192.168.1.1,192.168.1.2两台主机进行探测
sudo ./reconquiver -d -B 192.168.1.0/24 -m TS     //对192.168.1.0/24进行C段TCP-SYN探测


