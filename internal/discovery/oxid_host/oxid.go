package oxid_host

import (
	"fmt"
	"net"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

type OXIDResult struct {
	IP       string
	HostInfo string
	State    string
	Reason   string
}

// 使用更通用的 RPC 绑定请求 - EPM (Endpoint Mapper)
var epmBindRequest = []byte{
	// RPC Bind Header
	0x05, 0x00, // RPC 版本 5.0
	0x0b,                   // 包类型: Bind (11)
	0x03,                   // 包标志
	0x10, 0x00, 0x00, 0x00, // 数据表示
	0x48, 0x00, // 分片长度: 72
	0x00, 0x00, // 认证长度: 0
	0x01, 0x00, 0x00, 0x00, // 调用ID: 1

	// Bind Data
	0xd0, 0x16, 0xd0, 0x16, // 最大传输大小: 5840
	0x00, 0x00, 0x00, 0x00, // 关联组ID: 0
	0x01, 0x00, // 上下文项数量: 1

	// Context Item
	0x00, 0x00, 0x00, 0x00, // 上下文ID: 0
	0x01, 0x00, // 抽象语法数量: 1

	// Abstract Syntax: EPM (Endpoint Mapper) - 这是135端口的标准服务
	0xe1, 0xaf, 0xab, 0x1d, 0xc9, 0x11, 0x9f, 0xe8,
	0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
	0x02, 0x00, 0x00, 0x00, // 版本: 2.0

	0x01, 0x00, // 传输语法数量: 1

	// Transfer Syntax: NDR
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00, // NDR 版本: 2.0
}

// 方法2：基本RPC验证
var simpleRPCRequest = []byte{
	// RPC头部 (16字节)
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
	0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,

	// 绑定数据头部 (8字节)
	0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,

	// 上下文项 (40字节)
	0x01, 0x00, 0x00, 0x00, // 上下文项数量: 1
	0x00, 0x00, 0x00, 0x00, // 上下文ID: 0
	0x01, 0x00, // 抽象语法数量: 1

	// 使用一个简单的UUID（全零但版本不为零）
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, // 版本: 1.0

	0x01, 0x00, // 传输语法数量: 1

	// NDR传输语法
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00, // NDR版本: 2.0
}

// 方法3: 空请求
var nullRequest = []byte{
	0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
	0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

var results_oxid []OXIDResult //存储所有存活主机

// 简化的 RPC 扫描函数
func Oxid(ipaddres []string, rate int) {
	fmt.Println("开始 RPC 服务探测...")

	start := time.Now()

	//如果rate是默认值，则设置为并发50（并发50的结果更准确）
	if rate == 300 {
		rate = 50
	}
	sem := make(chan struct{}, rate)

	for _, ipaddr := range ipaddres {
		scanner.Wg.Add(1)
		go func(ip string) {
			sem <- struct{}{}
			defer scanner.Wg.Done()
			defer func() { <-sem }()

			success, method := simpleRPCProbe(ip)
			if success {

				result := OXIDResult{
					IP:       ip,
					HostInfo: "",
					State:    "up",
					Reason:   method,
				}
				scanner.Mu.Lock()
				results_oxid = append(results_oxid, result)
				scanner.Mu.Unlock()
			}
		}(ipaddr)
	}
	scanner.Wg.Wait()

	//获取MAC地址
	var targetIps []string
	for _, result := range results_oxid {
		targetIps = append(targetIps, result.IP)
	}
	MacResult := scanner.GetMac(targetIps)

	//获取主机信息
	var datas []scanner.HostInfoResult //HostInfoResult在hostinfo代码里已经定义成全局变量
	for _, result := range results_oxid {
		data := scanner.HostInfoResult{
			IP:  result.IP,
			MAC: MacResult[result.IP],
		}
		datas = append(datas, data)
	}
	collector := scanner.NewHostInfo() //这一行确实已经调用了函数
	InfoResult := collector.GetHostInfoBatch(datas)

	fmt.Println("OXID服务发现:")
	fmt.Println("探测标准: OXID 135端口开放且RPC服务开放")
	if len(results_oxid) > 0 {
		//fmt.Println("IP地址\t\tMAC地址\t\t\t主机信息\t\t状态\t\t原因")
		for _, v := range results_oxid {
			//fmt.Printf("%s\t%s\t%s\t%s\t%s\n", v.IP, MacResult[v.IP], v.HostInfo, v.State, v.Reason)

			fmt.Printf("IP地址:%s\n", v.IP)
			fmt.Printf("MAC地址:%s\n", MacResult[v.IP])
			fmt.Printf("主机信息:%s\n", InfoResult[v.IP])
			fmt.Printf("主机状态:%s\n", v.State)
			fmt.Printf("存活原因:%s\n", v.Reason)
			fmt.Println()
		}
	} else {
		fmt.Println("未发现Windows RPC服务")
	}

	usetime := time.Since(start)
	fmt.Printf("RPC主机数量：%d\n", len(results_oxid))
	fmt.Printf("运行时间: %v\n", usetime)
}

// 使用多种方法进行探测
func simpleRPCProbe(ip string) (bool, string) {
	// 方法1: EPM 绑定
	if success := probe(ip, epmBindRequest); success {
		return true, "EPM绑定成功"
	}

	// 方法2: 端口连接 + 基本响应检查
	if success := probe(ip, simpleRPCRequest); success {
		return true, "基本RPC响应"
	}

	// 方法3: 空请求检查
	if success := probe(ip, nullRequest); success {
		return true, "空请求响应"
	}

	return false, ""
}

// 发包进行探测
func probe(ip string, checkRequest []byte) bool {
	conn, err := net.DialTimeout("tcp", ip+":135", 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))

	_, err = conn.Write(checkRequest)
	if err != nil {
		return false
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return false
	}

	return validateRPCResponse(buffer[:n])
}

// 响应验证
func validateRPCResponse(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	// 检查基本的 RPC 头部
	if data[0] != 0x05 || data[1] != 0x00 {
		return false
	}

	// 接受 Bind Ack (0x0C) 或 Bind Nack (0x0D) 或其他有效响应
	packetType := data[2]
	if packetType == 0x0C || packetType == 0x0D || packetType == 0x02 || packetType == 0x03 {
		return true
	}

	return false
}
