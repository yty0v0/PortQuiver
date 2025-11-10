package tcp_host

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yty0v0/ReconQuiver/internal/scanner"

	"net"
	"time"
)

type TCPSYNResultSurvival struct {
	IP       string
	HostInfo string
	State    string
	Reason   string
}

var results_tcpsyn_su []TCPSYNResultSurvival //存储所有存活主机

func Tcp_syn(ipaddres []string, rate int) {
	sem := make(chan struct{}, rate) //设置并发控制
	start := time.Now()
	fmt.Printf("开始TCP SYN扫描... ")
	for _, ipaddr := range ipaddres {
		//扫描端口不要设置太多，可能会触发目标的防护机制
		keyPorts := []int{80, 443, 22, 23, 53, 135, 139, 445, 8080, 8443}
		for _, port := range keyPorts {
			scanner.Wg.Add(1)
			go func(j int, ip string) {
				sem <- struct{}{}
				defer scanner.Wg.Done()
				defer func() { <-sem }()
				state, reason := SynScan(ip, j)
				if state != "down" {

					// 创建新的结果实例（避免共享变量）
					result := TCPSYNResultSurvival{
						IP:       ip,
						HostInfo: "",
						State:    state,
						Reason:   reason,
					}

					scanner.Mu.Lock()
					results_tcpsyn_su = append(results_tcpsyn_su, result)
					scanner.Mu.Unlock()
				}
			}(port, ipaddr)
		}
	}
	scanner.Wg.Wait()

	//获取MAC地址
	var targetIps []string
	for _, result := range results_tcpsyn_su {
		targetIps = append(targetIps, result.IP)
	}
	MacResult := scanner.GetMac(targetIps)

	//获取主机信息
	var datas []scanner.HostInfoResult //HostInfoResult在hostinfo代码里已经定义成全局变量
	for _, result := range results_tcpsyn_su {
		data := scanner.HostInfoResult{
			IP:  result.IP,
			MAC: MacResult[result.IP],
		}
		datas = append(datas, data)
	}
	collector := scanner.NewHostInfo() //这一行确实已经调用了函数
	InfoResult := collector.GetHostInfoBatch(datas)

	fmt.Println("\n扫描结果:")
	//fmt.Println("IP地址\t\tMAC地址\t\t\t主机信息\t\t状态\t\t原因")
	results := make(map[string]int)
	sum := 0 //记录存活主机数量
	for _, v := range results_tcpsyn_su {
		//过滤重复记录的ip地址
		if results[v.IP] == 0 {
			sum++
			//fmt.Printf("%s\t%s\t%s\t%s\t%s\n", v.IP, MacResult[v.IP], v.HostInfo, v.State, v.Reason)
			fmt.Printf("IP地址:%s\n", v.IP)
			fmt.Printf("MAC地址:%s\n", MacResult[v.IP])
			fmt.Printf("主机信息:%s\n", InfoResult[v.IP])
			fmt.Printf("主机状态:%s\n", v.State)
			fmt.Printf("存活原因:%s\n", v.Reason)
			fmt.Println()
		}
		results[v.IP]++
	}
	fmt.Println()
	fmt.Printf("共发现 %d 台主机存活\n", sum)
	usetime := time.Now().Sub(start)
	fmt.Printf("运行时间：%v 秒 \n", usetime)
}

// 构造SYN数据包并进行探测，返回状态和原因
func SynScan(dstIp string, dstPort int) (string, string) {
	srcIp, srcPort, err := scanner.GetlocalIPPort(dstIp) //获取本地的出口ip和端口
	if err != nil {
		return "down", "local_ip_error"
	}

	dstAddrs, _ := net.LookupIP(dstIp)
	dstip, err := scanner.SelectIPv4(dstAddrs)
	if err != nil {
		return "down", "dst_ip_error"
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
		return "down", "serialize_error"
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return "down", "conn_error"
	}
	defer conn.Close()

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		return "down", "send_error"
	}

	deadline := time.Now().Add(4 * time.Second) //设置for循环操作的总超时

	//监听响应并分析
	for {
		conn.SetDeadline(time.Now().Add(200 * time.Millisecond)) //设置读取超时,100毫秒
		if time.Now().After(deadline) {                          //总超时到了直接结束
			return "down", "timeout"
		}

		b := make([]byte, 4096)

		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 短超时，继续等待
			}
			return "down", "read_error"
		}
		if addr.(*net.IPAddr).IP.Equal(dstip) {

			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) {
					// SYN-ACK: 端口开放，主机存活
					if tcp.SYN && tcp.ACK {
						return "up", "port_open"
					}

					// ACK: 可能是有状态的防火墙
					if tcp.ACK {
						return "up", "firewall_ack"
					}

					// RST: 端口关闭，但主机存活
					if tcp.RST {
						return "up", "port_closed_rst"
					}

					// 不存活
					return "down", " "
				}
			}
		}
	}
}
