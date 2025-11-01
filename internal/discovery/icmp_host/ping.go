package icmp_host

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scanner"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// 探测存活主机(icmp探测--ping)
func Ping(ipaddres []string, rate int) {
	var survival = make(map[string]string) //用来存储存活主机地址
	fmt.Println("开始探测...")
	start := time.Now()
	sem := make(chan struct{}, rate) // 创建一个缓冲大小为 20 的信号量 channel，这意味着最多允许 20 个并发 goroutine

	for i, ipaddr := range ipaddres {
		scanner.Wg.Add(1)
		go func(Ip string, seq int) {
			sem <- struct{}{} // 获取一个许可（向 channel 发送一个值），如果已经有 20 个 goroutine 在运行（channel 已满），这里会阻塞，直到有许可被释放
			defer scanner.Wg.Done()
			defer func() { <-sem }() // 释放许可（从 channel 接收值）

			//创建icmp连接
			conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			// 创建 ICMP Echo 消息，这段代码创建了一个完整的ICMP Echo Request消息，用于向目标主机发送"你在吗？"的询问
			pid := os.Getpid() & 0xffff //生成唯一ID，会话标识符，用于匹配请求和响应，目标主机回复时会将相同的ID返回
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho, //指定这是一个ICMP Echo Request（回显请求）
				Code: 0,
				Body: &icmp.Echo{
					ID:   pid,
					Seq:  seq,             //包序列标识，用于检测丢包和排序，每次发送递增，回复包包含相同序列号
					Data: []byte("HELLO"), //测试数据，用于验证数据完整性，目标主机应原样返回此数据
				},
			}

			//序列化信息，将 ICMP 消息结构序列化为字节切片
			wb, err := msg.Marshal(nil)
			if err != nil {
				return
			}

			host, _ := net.ResolveIPAddr("ip4", Ip)

			//发送ping
			_, err = conn.WriteTo(wb, host)
			if err != nil {
				return
			}

			deadline := time.Now().Add(3 * time.Second)

			for {
				//设置读取超时防止阻塞
				conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

				//设置总超时，for循环时间到了直接退出
				if time.Now().After(deadline) {
					return
				}

				//读取响应
				rb := make([]byte, 1500) //rb存储读取的内容
				n, _, err := conn.ReadFrom(rb)
				if err != nil {
					return
				}

				//响应解析和验证
				rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n]) //告诉解析器这是ICMP协议的数据，解析出完整的ICMP消息结构
				if err != nil {
					return
				}
				if rm.Type != ipv4.ICMPTypeEchoReply { //检查消息类型，只处理ICMPTypeEchoReply（类型0，回显应答）
					return
				}
				echo, ok := rm.Body.(*icmp.Echo) //类型断言检查 Body 是否为 *icmp.Echo。echo：如果类型断言成功，返回转换后的 *icmp.Echo 对象；如果失败，返回该类型的零值（nil）。ok：true 表示类型断言成功，false 表示失败
				if ok {
					if echo.ID == pid && echo.Seq == seq {
						scanner.Mu.Lock()
						survival[Ip] = "up"
						scanner.Mu.Unlock()
					}
				}
			}
		}(ipaddr, i)
	}
	scanner.Wg.Wait()

	fmt.Println("存活主机列表：")
	fmt.Println("IP地址\t\t状态")
	j := 0
	for k, v := range survival {
		fmt.Printf("%s\t%s\n", k, v)
		j++
	}

	usetime := time.Now().Sub(start)
	fmt.Println()
	fmt.Printf("存活主机数量：%d \n", j)
	fmt.Printf("运行时间:%v seconds\n", usetime)
}
