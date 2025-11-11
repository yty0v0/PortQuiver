package icmp_host

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scanner"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ADDRESSMASKResult struct {
	IP       string
	HostInfo string
	State    string
	Reason   string
}

var results_addressmask []ADDRESSMASKResult

// ICMP 地址掩码探测存活主机
func Addressmask(ipaddres []string, rate int) {
	// 定义ICMP地址掩码相关常量
	const (
		ICMPTypeAddressMaskRequest = 17 // 地址掩码请求
		ICMPTypeAddressMaskReply   = 18 // 地址掩码回复
	)

	fmt.Println("开始ICMP地址掩码探测...")
	start := time.Now()

	//如果rate是默认值，则设置为并发50（并发50的结果更准确）
	if rate == 300 {
		rate = 20
	}
	sem := make(chan struct{}, rate) // 并发控制，最多20个goroutine

	for i, ipaddr := range ipaddres {
		scanner.Wg.Add(1)
		go func(Ip string, seq int) {
			sem <- struct{}{}
			defer scanner.Wg.Done()
			defer func() { <-sem }()

			// 创建ICMP连接
			conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				fmt.Printf("创建连接失败 %s: %v\n", Ip, err)
				return
			}
			defer conn.Close()

			// 生成唯一ID和序列号
			pid := uint16(os.Getpid() & 0xffff)

			// 构造地址掩码请求数据 (8字节)
			addressMaskData := make([]byte, 8)
			binary.BigEndian.PutUint16(addressMaskData[0:2], pid)         // ID (2字节)
			binary.BigEndian.PutUint16(addressMaskData[2:4], uint16(seq)) // Seq (2字节)
			binary.BigEndian.PutUint32(addressMaskData[4:8], 0)           // Address Mask (4字节，请求时为0)

			// 创建ICMP地址掩码请求消息 - 使用 RawBody
			msg := icmp.Message{
				Type: ipv4.ICMPType(ICMPTypeAddressMaskRequest),
				Code: 0,
				Body: &icmp.RawBody{
					Data: addressMaskData,
				},
			}

			// 序列化消息
			wb, err := msg.Marshal(nil)
			if err != nil {
				fmt.Printf("序列化失败 %s: %v\n", Ip, err)
				return
			}

			// 解析目标地址
			host, err := net.ResolveIPAddr("ip4", Ip)
			if err != nil {
				fmt.Printf("解析地址失败 %s: %v\n", Ip, err)
				return
			}

			// 发送地址掩码请求
			_, err = conn.WriteTo(wb, host)
			if err != nil {
				fmt.Printf("发送失败 %s: %v\n", Ip, err)
				return
			}

			// 设置总超时
			deadline := time.Now().Add(3 * time.Second)

			for {
				// 检查总超时
				if time.Now().After(deadline) {
					return
				}

				// 设置读取超时
				conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

				// 读取响应
				rb := make([]byte, 1500)
				n, peer, err := conn.ReadFrom(rb)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // 超时继续等待
					}
					return
				}

				// 验证响应来源IP
				peerIP, ok := peer.(*net.IPAddr)
				if !ok {
					continue
				}
				if peerIP.String() != Ip {
					continue // 不是目标IP的响应
				}

				// 解析ICMP消息
				rm, err := icmp.ParseMessage(1, rb[:n]) //告诉解析器这是ICMP协议的数据，解析出完整的ICMP消息结构
				if err != nil {
					continue
				}

				// 检查是否为地址掩码回复
				if rm.Type != ipv4.ICMPType(ICMPTypeAddressMaskReply) {
					//fmt.Printf("非地址掩码回复 %s: Type=%d\n", Ip, rm.Type)
					continue
				}

				// 提取消息体数据
				var responseData []byte
				switch body := rm.Body.(type) {
				case *icmp.RawBody:
					responseData = body.Data
				default:
					continue
				}

				// 验证响应数据长度
				if len(responseData) < 8 {
					continue
				}

				// 解析响应中的ID和序列号
				responseID := binary.BigEndian.Uint16(responseData[0:2])
				responseSeq := binary.BigEndian.Uint16(responseData[2:4])

				// 检查ID和序列号是否匹配
				if responseID == pid && responseSeq == uint16(seq) {

					result := ADDRESSMASKResult{
						IP:       Ip,
						HostInfo: "",
						State:    "up",
						Reason:   "收到响应",
					}

					scanner.Mu.Lock()
					results_addressmask = append(results_addressmask, result)
					scanner.Mu.Unlock()
					return // 收到响应，退出循环
				}
			}
		}(ipaddr, i)
	}
	scanner.Wg.Wait()

	//去重，因为可能收到多个icmp的相同响应
	var results_addressmask_nosame []ADDRESSMASKResult
	check := make(map[string]bool)
	for _, result := range results_addressmask {
		if !check[result.IP] {
			check[result.IP] = true
			results_addressmask_nosame = append(results_addressmask_nosame, result)
		}
	}

	//获取MAC地址
	var targetIps []string
	for _, result := range results_addressmask_nosame {
		targetIps = append(targetIps, result.IP)
	}
	MacResult := scanner.GetMac(targetIps)

	//获取主机信息
	var datas []scanner.HostInfoResult //HostInfoResult在hostinfo代码里已经定义成全局变量
	for _, result := range results_addressmask_nosame {
		data := scanner.HostInfoResult{
			IP:  result.IP,
			MAC: MacResult[result.IP],
		}
		datas = append(datas, data)
	}
	collector := scanner.NewHostInfo() //这一行确实已经调用了函数
	InfoResult := collector.GetHostInfoBatch(datas)

	// 输出结果
	fmt.Println("存活主机列表：")
	//fmt.Println("IP地址\t\tMAC地址\t\t\t主机信息\t\t状态\t\t原因")
	j := 0
	for _, v := range results_addressmask_nosame {
		//fmt.Printf("%s\t%s\t%s\t%s\t%s\n", v.IP, MacResult[v.IP], v.HostInfo, v.State, v.Reason)

		fmt.Printf("IP地址:%s\n", v.IP)
		fmt.Printf("MAC地址:%s\n", MacResult[v.IP])
		fmt.Printf("主机信息:%s\n", InfoResult[v.IP])
		fmt.Printf("主机状态:%s\n", v.State)
		fmt.Printf("存活原因:%s\n", v.Reason)
		fmt.Println()

		j++
	}

	usetime := time.Since(start)
	fmt.Printf("存活主机数量：%d\n", j)
	fmt.Printf("运行时间: %v\n", usetime)
}
