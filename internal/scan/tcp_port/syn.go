package tcp_port

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yty0v0/ReconQuiver/internal/scan/utils"
	"github.com/yty0v0/ReconQuiver/internal/scanner"

	"net"
	"time"
)

type TCPSYNResult struct {
	Port    int
	State   string
	Service string
}

// 存储所有结果
var results_tcpsyn []TCPSYNResult

func Tcp_syn(ip string, port []int, rate int) {

	//如果rate是默认值，则设置为并发200（并发200的结果更准确）
	if rate == 300 {
		rate = 200
	}

	sem := make(chan struct{}, rate) //设置并发控制
	start := time.Now()
	fmt.Printf("开始TCP SYN扫描 %s...\n", ip)
	for _, ports := range port {
		scanner.Wg.Add(1)
		go func(j int) {
			sem <- struct{}{}
			defer scanner.Wg.Done()
			defer func() { <-sem }()
			check := SynScan(ip, j)
			if check {
				// 创建新的结果实例（避免共享变量）
				result := TCPSYNResult{
					Port:    j,
					State:   "open",
					Service: "",
				}

				scanner.Mu.Lock()
				results_tcpsyn = append(results_tcpsyn, result)
				scanner.Mu.Unlock()
			}
		}(ports)
	}
	scanner.Wg.Wait()

	//获取端口服务
	var data_port []int
	for _, result := range results_tcpsyn {
		data_port = append(data_port, result.Port)
	}
	detector := utils.NewProtocolDetector(3 * time.Second)
	results := detector.BatchDetect(ip, data_port)

	fmt.Println("\n扫描结果:")
	fmt.Println("端口\t状态\t服务")
	for _, v := range results {
		fmt.Printf("%d\topen\t%s", v.Port, v.Service)
		fmt.Println()
	}

	fmt.Printf("共发现 %d 个端口开放\n", len(results))
	usetime := time.Now().Sub(start)
	fmt.Printf("运行时间：%v 秒 \n", usetime)
}

// 构造SYN数据包并进行探测
func SynScan(dstIp string, dstPort int) bool {
	srcIp, srcPort, err := scanner.GetlocalIPPort(dstIp) //获取本地的出口ip和端口
	if err != nil {
		return false
	}

	dstAddrs, _ := net.LookupIP(dstIp)
	dstip, err := scanner.SelectIPv4(dstAddrs)
	if err != nil {
		return false
	}

	dstport := layers.TCPPort(dstPort)
	srcport := layers.TCPPort(srcPort)

	//构造IP报头
	ip := &layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}
	//构造TCP报头
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		SYN:     true,
	}

	//计算TCP校验和
	err = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return false
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		return false
	}

	deadline := time.Now().Add(4 * time.Second) //设置for循环操作的总超时

	//监听响应并分析
	for {
		conn.SetDeadline(time.Now().Add(200 * time.Millisecond)) //设置读取超时,100毫秒
		if time.Now().After(deadline) {                          //总超时到了直接结束
			return false
		}

		b := make([]byte, 4096)

		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 短超时，继续等待
			}
			return false
		}
		if addr.(*net.IPAddr).IP.Equal(dstip) {

			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) {
					if tcp.SYN && tcp.ACK {
						return true
					} else {
						return false
					}
				}
			}
		}
	}
}
