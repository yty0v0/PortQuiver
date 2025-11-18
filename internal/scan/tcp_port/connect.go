package tcp_port

import (
	"fmt"
	"net"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scan/utils"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

// TCP CONNECT扫描结果结构体
type TCPCONNECTResult struct {
	Port    int
	State   string
	Service string
}

// 存储所有结果
var results_tcpconnect []TCPCONNECTResult

// TCP CONNECT全端口扫描操作
func Tcp_connect(ipaddres string, port []int, rate int) { //ipaddres为扫描地址，port存储要扫描的端口

	//如果rate是默认值，则设置为并发5000（并发5000的结果更准确）
	if rate == 300 {
		rate = 5000
	}

	sem := make(chan struct{}, rate) //设置并发控制
	fmt.Printf("开始TCP CONNECT扫描 %s...\n", ipaddres)
	start := time.Now()
	for _, ports := range port {
		scanner.Wg.Add(1)
		go func(j int) {
			sem <- struct{}{}
			defer func() { <-sem }()
			defer scanner.Wg.Done()
			addres := fmt.Sprintf("%s:%d", ipaddres, j)
			conn, err := net.DialTimeout("tcp", addres, time.Second*3) // DialTimeout() 比 Dial() 增加了超时时间
			if err != nil {
				return //这里的 return 是退出当前的匿名 goroutine 函数，而不是退出外层循环
			}

			// 创建新的结果实例（避免共享变量）
			result := TCPCONNECTResult{
				Port:    j,
				State:   "open",
				Service: "",
			}

			scanner.Mu.Lock()
			results_tcpconnect = append(results_tcpconnect, result)
			scanner.Mu.Unlock()
			conn.Close()
		}(ports)
	}
	scanner.Wg.Wait()

	//获取端口服务
	var data_port []int
	for _, result := range results_tcpconnect {
		data_port = append(data_port, result.Port)
	}
	detector := utils.NewProtocolDetector(3 * time.Second)
	results := detector.BatchDetect(ipaddres, data_port)

	fmt.Println("\n扫描结果:")
	fmt.Println("端口\t状态\t服务")
	for _, v := range results {
		fmt.Printf("%d\topen\t%s", v.Port, v.Service)
		fmt.Println()
	}
	usetime := time.Now().Sub(start)
	fmt.Println()
	fmt.Printf("共发现 %d 个端口开放\n", len(results))
	fmt.Printf("运行时间:%v 秒\n", usetime)
}
