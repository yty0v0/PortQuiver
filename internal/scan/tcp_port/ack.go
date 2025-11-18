package tcp_port

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

// ACKScanResult 扫描结果
type TCPACKResult struct {
	Port   int
	State  string // "filtered", "unfiltered", "unknown"
	Reason string
}

var results []TCPACKResult

func Tcp_ack(target string, ports []int, rate int) {
	timeout := 4 * time.Second
	start := time.Now()
	fmt.Printf("开始TCP ACK扫描 %s...\n", target)

	//如果rate是默认值，则设置为并发5（并发5的结果更准确）
	if rate == 300 {
		rate = 5
	}

	ACKScan(target, ports, rate, timeout)

	fmt.Println("\n扫描结果:")
	fmt.Println("端口\t状态\t\t说明")
	unfiltered := 0
	filtered := 0
	unknown := 0
	for _, result := range results {
		if result.State == "unfiltered" {
			fmt.Printf("%d\t%s\t%s\n", result.Port, result.State, result.Reason)
			unfiltered++
		} else if result.State == "filtered" {
			filtered++
		} else {
			unknown++
		}
	}
	duration := time.Since(start)
	fmt.Println()
	fmt.Printf("共发现 %d 个端口没被过滤，%d 个端口超时无响应（可能被防火墙过滤），%d 个端口出现错误\n", unfiltered, filtered, unknown)
	fmt.Printf("扫描完成，耗时: %v\n", duration)
}

// ACKScan 执行TCP ACK扫描
func ACKScan(target string, ports []int, rate int, timeout time.Duration) {

	// 解析目标地址
	dstAddrs, err := net.LookupIP(target)
	if err != nil {
		fmt.Errorf("DNS解析失败: %v", err)
		return
	}

	// 选择IPv4地址
	dstip, err := scanner.SelectIPv4(dstAddrs)
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}

	// 获取本地IP（用于构造数据包）
	srcIP, _, err := scanner.GetlocalIPPort(dstip.String())
	if err != nil {
		fmt.Errorf("获取本地IP失败: %v", err)
		return
	}

	// 创建原始套接字（需要root权限）
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		fmt.Errorf("创建原始套接字失败: %v", err)
		return
	}
	defer conn.Close()

	sem := make(chan struct{}, rate) //设置并发控制

	// 扫描每个端口
	for _, port := range ports {
		scanner.Wg.Add(1)
		go func(Port int) {
			var result TCPACKResult
			sem <- struct{}{} //  获取一个许可（向 channel 发送一个值)，如果此时达到最大并发数量会阻塞进程
			defer scanner.Wg.Done()
			defer func() { <-sem }() // 使用函数结束时，许可被释放
			result.Port = Port

			// 发送ACK包并等待响应
			state, reason, err := scanPortWithACK(conn, srcIP, dstip, Port, timeout)
			if err != nil {
				result.State = "unknown"
				result.Reason = err.Error()
			} else {
				result.State = state
				result.Reason = reason
			}

			scanner.Mu.Lock()
			results = append(results, result)
			scanner.Mu.Unlock()

			// 避免过快扫描
			time.Sleep(100 * time.Millisecond)

		}(port)
	}
	scanner.Wg.Wait()
	return
}

// scanPortWithACK 对单个端口进行ACK扫描
func scanPortWithACK(conn net.PacketConn, srcIP, dstip net.IP, port int, timeout time.Duration) (string, string, error) {
	srcPort := scanner.GenerateRandomPort()

	// 构造TCP/IP数据包
	packet, err := createACKPacket(srcIP, dstip, srcPort, port)
	if err != nil {
		return "unknown", "构造数据包失败", err
	}

	// 发送ACK包
	if err := sendPacket(conn, packet, dstip); err != nil {
		return "unknown", "发送数据包失败", err
	}

	// 监听响应
	return listenForResponse(conn, srcPort, port, dstip, timeout)
}

// createACKPacket 构造ACK数据包
func createACKPacket(srcIP, dstip net.IP, srcPort, dstPort int) ([]byte, error) {
	// IP头部
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}

	// TCP头部（设置ACK标志位）
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		Window:  1024,
		Seq:     scanner.GenerateRandomSeq(), // 随机序列号
	}

	// 设置校验和
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	// 序列化数据包
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// sendPacket 发送数据包
func sendPacket(conn net.PacketConn, packet []byte, dstip net.IP) error {
	_, err := conn.WriteTo(packet, &net.IPAddr{IP: dstip})
	return err
}

// listenForResponse 监听并分析响应
func listenForResponse(conn net.PacketConn, srcPort, dstPort int, dstip net.IP, timeout time.Duration) (string, string, error) {

	deadline := time.Now().Add(timeout)

	buffer := make([]byte, 4096)

	for {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

		if time.Now().After(deadline) {
			return "filtered", "超时无响应（可能被防火墙过滤）", nil
		}

		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 短超时，继续等待
			}
			return "unknown", "读取响应失败", err
		}

		// 检查响应来源
		if !addr.(*net.IPAddr).IP.Equal(dstip) {
			continue // 不是目标IP的响应
		}

		// 解析TCP包
		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// 验证端口匹配
			if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) {
				if tcp.RST {
					return "unfiltered", "收到RST响应（端口未被过滤）", nil
				} else {
					return "unknown", "收到非RST响应", nil
				}
			}
		}
	}
}
