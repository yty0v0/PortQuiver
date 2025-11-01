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

// ICMP时间戳探测存活主机
func Timestamp(ipaddres []string, rate int) {
	var survival = make(map[string]string) //存储存活的主机
	fmt.Println("开始ICMP时间戳探测...")
	start := time.Now()
	sem := make(chan struct{}, rate)

	for i, ipaddr := range ipaddres {
		scanner.Wg.Add(1)
		go func(Ip string, seq int) {
			sem <- struct{}{}
			defer scanner.Wg.Done()
			defer func() { <-sem }()

			// 创建ICMP连接
			conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			// 生成唯一ID和序列号
			pid := uint16(os.Getpid() & 0xffff)
			currentTime := uint32(time.Now().UnixNano() / 1e6) // 毫秒时间戳

			// 构造时间戳请求数据 (20字节)
			timestampData := make([]byte, 20)
			binary.BigEndian.PutUint16(timestampData[0:2], pid)         // ID (2字节)
			binary.BigEndian.PutUint16(timestampData[2:4], uint16(seq)) // Seq (2字节)
			binary.BigEndian.PutUint32(timestampData[4:8], currentTime) // Originate (4字节)
			binary.BigEndian.PutUint32(timestampData[8:12], 0)          // Receive (4字节)
			binary.BigEndian.PutUint32(timestampData[12:16], 0)         // Transmit (4字节)
			// 剩余4字节填充0

			// 创建ICMP时间戳请求消息
			msg := icmp.Message{
				Type: ipv4.ICMPTypeTimestamp, // Type 13 - 时间戳请求
				Code: 0,
				Body: &icmp.RawBody{ // 使用 RawBody 替代弃用的 DefaultMessageBody
					Data: timestampData,
				},
			}

			// 序列化消息
			wb, err := msg.Marshal(nil)
			if err != nil {
				return
			}

			// 解析目标地址
			host, err := net.ResolveIPAddr("ip4", Ip)
			if err != nil {
				return
			}

			// 发送时间戳请求
			_, err = conn.WriteTo(wb, host)
			if err != nil {
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
				conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

				// 读取响应
				rb := make([]byte, 1500)
				n, sourceAddr, err := conn.ReadFrom(rb)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() { //判断是否为超时错误
						continue // 超时继续等待
					}
					return
				}

				// 检查响应来源是否匹配目标IP
				if sourceAddr.String() != Ip {
					continue
				}

				// 解析ICMP消息
				rm, err := icmp.ParseMessage(ipv4.ICMPTypeTimestampReply.Protocol(), rb[:n]) //告诉解析器这是ICMP协议的数据，解析出完整的ICMP消息结构
				if err != nil {
					continue
				}

				// 检查是否为时间戳回复 (Type 14)
				if rm.Type != ipv4.ICMPTypeTimestampReply {
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
				if len(responseData) < 16 {
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
		fmt.Printf("%s\t%s\n", k, v)
		j++
	}

	usetime := time.Since(start)
	fmt.Printf("存活主机数量：%d\n", j)
	fmt.Printf("运行时间: %v\n", usetime)
}
