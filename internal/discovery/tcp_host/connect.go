package tcp_host

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

type TCPCONNECTResult2 struct {
	scanip   string
	Hostname string
	State    string
	Reason   string // 添加原因字段
}

var results_tcpconnect2 []TCPCONNECTResult2 // 存储所有主机存活探测的扫描结果

// TCP CONNECT 主机存活扫描操作
func Tcp_connect(ipaddres []string, rate int) {
	sem := make(chan struct{}, rate)
	fmt.Println("开始 TCP CONNECT 扫描...")
	start := time.Now()

	for _, ipaddr := range ipaddres { //外层遍历ip地址
		//扫描端口不要设置太多，可能会触发目标的防护机制
		keyPorts := []int{80, 443, 22, 23, 53, 135, 139, 445, 8080, 8443}
		for _, port := range keyPorts { //内层遍历端口
			scanner.Wg.Add(1)
			go func(ip string, Port int) {
				sem <- struct{}{}
				defer func() { <-sem }()
				defer scanner.Wg.Done()

				addres := fmt.Sprintf("%s:%d", ip, Port)
				conn, err := net.DialTimeout("tcp", addres, time.Second*3)

				if err == nil {

					// 连接成功 - 主机存活且端口开放
					result := TCPCONNECTResult2{
						scanip:   ip,
						Hostname: "",
						State:    "up",
						Reason:   "port_open",
					}
					scanner.Mu.Lock()
					results_tcpconnect2 = append(results_tcpconnect2, result)
					scanner.Mu.Unlock()
					conn.Close()
					return
				}

				// 分析错误类型
				errStr := err.Error()

				// 检查RST包响应（连接被拒绝）
				if strings.Contains(errStr, "refused") ||
					strings.Contains(errStr, "reset") ||
					strings.Contains(errStr, "RST") {

					// RST包 - 主机存活但端口关闭
					result := TCPCONNECTResult2{
						scanip:   ip,
						Hostname: "",
						State:    "up",
						Reason:   "port_closed_rst",
					}
					scanner.Mu.Lock()
					results_tcpconnect2 = append(results_tcpconnect2, result)
					scanner.Mu.Unlock()
					return
				}

				// 检查其他表明主机存活的错误
				if strings.Contains(errStr, "no route") ||
					strings.Contains(errStr, "unreachable") ||
					strings.Contains(errStr, "host is down") {
					// 网络不可达 - 可能不存活
					return
				}

				// 超时或其他错误 - 不视为存活

			}(ipaddr, port)
		}
	}
	scanner.Wg.Wait()

	//获取MAC地址
	var targetIps []string
	for _, result := range results_tcpconnect2 {
		targetIps = append(targetIps, result.scanip)
	}
	MacResult := scanner.GetMac(targetIps)

	//获取主机信息
	var datas []scanner.HostInfoResult //HostInfoResult在hostinfo代码里已经定义成全局变量
	for _, result := range results_tcpconnect2 {
		data := scanner.HostInfoResult{
			IP:  result.scanip,
			MAC: MacResult[result.scanip],
		}
		datas = append(datas, data)
	}
	collector := scanner.NewHostInfo() //这一行确实已经调用了函数
	InfoResult := collector.GetHostInfoBatch(datas)

	sum := 0 //统计存活的主机数
	fmt.Println("存活主机列表：")
	//fmt.Println("IP地址\t\tMAC地址\t\t\t状态\t\t原因\t\t主机信息")
	results := make(map[string]int)
	for _, v := range results_tcpconnect2 {
		//过滤掉重复记录的主机
		if results[v.scanip] == 0 {
			sum++
			//fmt.Printf("%s\t%s\t%s\t%s\t%s\n", v.scanip, MacResult[v.scanip], InfoResult[v.scanip], v.State, v.Reason)

			fmt.Printf("IP地址:%s\n", v.scanip)
			fmt.Printf("MAC地址:%s\n", MacResult[v.scanip])
			fmt.Printf("主机信息:%s\n", InfoResult[v.scanip])
			fmt.Printf("主机状态:%s\n", v.State)
			fmt.Printf("存活原因:%s\n", v.Reason)
			fmt.Println()
		}
		results[v.scanip]++
	}
	fmt.Println()
	fmt.Printf("共发现 %d 台存活主机\n", sum)
	usetime := time.Now().Sub(start)
	fmt.Printf("运行时间:%v 秒\n", usetime)
}
