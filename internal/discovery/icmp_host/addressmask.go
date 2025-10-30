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

// ICMP 地址掩码探测存活主机
func Addressmask(ipaddres []string) {
	// 定义ICMP地址掩码相关常量
	const (
		ICMPTypeAddressMaskRequest = 17 // 地址掩码请求
		ICMPTypeAddressMaskReply   = 18 // 地址掩码回复
	)

	var survival = make(map[string]string) // 存储存活主机地址
	fmt.Println("开始ICMP地址掩码探测...")
	start := time.Now()
	sem := make(chan struct{}, 20) // 并发控制，最多20个goroutine

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
					fmt.Printf("非地址掩码回复 %s: Type=%d\n", Ip, rm.Type)
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
					scanner.Mu.Lock()
					survival[Ip] = "up"
					scanner.Mu.Unlock()
					return // 收到响应，退出循环
				}
			}
		}(ipaddr, i)
	}

	scanner.Wg.Wait()

	// 输出结果
	fmt.Println("存活主机列表：")
	fmt.Println("IP地址\t\t状态")
	j := 0
	for k, v := range survival {
		fmt.Printf("%s %s\n", k, v)
		j++
	}

	usetime := time.Since(start)
	fmt.Printf("\n存活主机数量：%d\n", j)
	fmt.Printf("运行时间: %v\n", usetime)
}
