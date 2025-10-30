package tcp_host

import (
	"fmt"
	"net"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

type TCPCONNECTResult2 struct {
	scanip string
	State  string
}

// 存储所有主机存活探测的扫描结果
var results_tcpconnect2 []TCPCONNECTResult2

// TCP CONNECT 主机存活扫描操作
func Tcp_connect(ipaddres []string) {
	sem := make(chan struct{}, 500)
	fmt.Println("开始 TCP CONNECT 扫描...")
	fmt.Println()
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
				if err != nil {
					return
				}
				result := TCPCONNECTResult2{
					scanip: ip,
					State:  "up",
				}
				scanner.Mu.Lock()
				results_tcpconnect2 = append(results_tcpconnect2, result)
				scanner.Mu.Unlock()
				conn.Close()
			}(ipaddr, port)
		}
	}
	scanner.Wg.Wait()
	sum := 0 //统计存活的主机数
	fmt.Println("存活主机列表：")
	fmt.Println("IP地址\t\t状态")
	results := make(map[string]int)
	for _, v := range results_tcpconnect2 {
		//过滤掉重复记录的主机
		if results[v.scanip] == 0 {
			sum++
			fmt.Printf("%s\t%s\t\n", v.scanip, v.State)
		}
		results[v.scanip]++
	}
	fmt.Println()
	fmt.Printf("共发现 %d 台存活主机\n", sum)
	usetime := time.Now().Sub(start)
	fmt.Printf("运行时间:%v 秒\n", usetime)
}
