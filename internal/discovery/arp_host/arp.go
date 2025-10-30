package arp_host

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

// ARP扫描函数
func Arp(targetIPs []string) {
	survival := make(map[string]string)

	// 手动选择接口
	iface, err := selectNetworkInterface()
	if err != nil {
		log.Printf("选择接口失败: %v", err)
		return
	}

	fmt.Printf("使用接口: %s (索引: %d)\n", iface.Name, iface.Index)

	// 获取选中接口的网络信息
	localIP, localNet, localMAC, err := getInterfaceNetworkInfo(iface)
	if err != nil {
		log.Printf("获取接口网络信息失败: %v", err)
		return
	}

	//fmt.Printf("本地IP: %s, MAC: %s\n", localIP, localMAC)
	//fmt.Printf("网络范围: %s\n", localNet)
	fmt.Printf("扫描个数: %d 个IP地址\n", len(targetIPs))

	// 显示扫描的IP范围
	if len(targetIPs) > 0 {
		fmt.Printf("扫描范围: %s 到 %s\n", targetIPs[0], targetIPs[len(targetIPs)-1])

		// 检查目标IP是否在本地网络内
		firstTarget := net.ParseIP(targetIPs[0])
		if firstTarget != nil && !localNet.Contains(firstTarget) {
			fmt.Printf("警告: 目标IP %s 不在本地网络 %s 中\n", firstTarget, localNet)
			fmt.Printf("ARP扫描只能在本地局域网内进行\n")
			fmt.Printf("建议使用ICMP Echo扫描\n")
		}
	}

	// 检查扫描范围是否包含本地主机，如果包含则添加到存活列表
	localIPStr := localIP.String()
	for _, targetIP := range targetIPs {
		if targetIP == localIPStr {
			scanner.Mu.Lock()
			survival[localIPStr] = localMAC.String()
			scanner.Mu.Unlock()
			break
		}
	}

	// 获取所有pcap设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("查找pcap设备失败: %v", err)
		return
	}

	// 查找匹配的pcap设备
	var pcapDevice string

	for _, device := range devices {
		for _, addr := range device.Addresses {
			if addr.IP.Equal(localIP) {
				pcapDevice = device.Name
				break
			}
		}
		if pcapDevice != "" {
			break
		}
	}

	if pcapDevice == "" {
		log.Printf("未找到可用的pcap设备")
		return
	}

	// 打开pcap句柄
	handle, err := pcap.OpenLive(pcapDevice, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("打开设备失败: %v", err)
		return
	}
	defer handle.Close()

	// 设置过滤器 - 捕获所有ARP包
	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Printf("设置过滤器失败: %v\n", err)
		fmt.Println("不进行过滤器设置，程序继续运行")
	}

	// 创建包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	fmt.Println("开始ARP探测...")
	start := time.Now()

	stopChan := make(chan struct{})

	// 启动接收goroutine
	go func() {
		receiveCount := 0 // 总接收包数统计
		replyCount := 0   // ARP回复包数统计

		for {
			select {
			case <-stopChan:
				fmt.Printf("接收完成: 共接收 %d 个包，其中 %d 个ARP回复\n", receiveCount, replyCount)
				return
			case packet := <-packets: //传入从网络接口中读取到的数据包
				if packet == nil {
					continue
				}
				receiveCount++

				// 解析ARP层
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}

				arp, ok := arpLayer.(*layers.ARP)
				if !ok {
					continue
				}

				// 检查是否是ARP回复
				if arp.Operation == layers.ARPReply {
					replyCount++
					senderIP := net.IP(arp.SourceProtAddress).String()          // 发送者IP
					senderMAC := net.HardwareAddr(arp.SourceHwAddress).String() // 发送者MAC
					targetIP := net.IP(arp.DstProtAddress).String()             // 目标IP

					// 记录所有ARP回复
					scanner.Mu.Lock()
					if _, exists := survival[senderIP]; !exists {
						survival[senderIP] = senderMAC
						fmt.Printf(">>> 发现存活主机: %s -> %s (回复目标IP: %s)\n",
							senderIP, senderMAC, targetIP)
					}
					scanner.Mu.Unlock()
				}
			}
		}
	}()

	// 发送ARP请求
	sem := make(chan struct{}, 50) // 减少并发数避免网络拥塞
	sentCount := 0                 // 统计发送的请求数

	for i, targetIP := range targetIPs {

		if targetIP == localIPStr {
			continue //跳过本机ip，避免扫描自己
		}

		scanner.Wg.Add(1)
		sentCount++

		go func(ip string, seq int) {
			sem <- struct{}{}
			defer scanner.Wg.Done()
			defer func() { <-sem }()

			time.Sleep(time.Duration(seq*50) * time.Millisecond) // 增加间隔
			sendARPRequest(handle, localMAC, localIP, ip)        //发送APR数据包
		}(targetIP, i)
	}
	scanner.Wg.Wait()

	fmt.Printf("总共发送了 %d 个ARP请求\n", sentCount)
	fmt.Println("所有ARP请求发送完成")

	fmt.Println("等待接收ARP回复...")
	lastDiscoveryTime := time.Now()

	for {
		time.Sleep(1 * time.Second)
		scanner.Mu.Lock()
		currentCount := len(survival)
		scanner.Mu.Unlock()

		// 如果有新发现，更新最后发现时间
		if currentCount > 0 {
			lastDiscoveryTime = time.Now()
		}

		// 如果超过3秒没有新发现，就退出
		if time.Since(lastDiscoveryTime) > 3*time.Second {
			//fmt.Println("连续3秒无新发现，结束等待")
			break
		}

		// 最大等待15秒
		if time.Since(start) > 15*time.Second {
			//fmt.Println("达到最大等待时间15秒")
			break
		}
	}

	// 停止接收
	close(stopChan)
	time.Sleep(500 * time.Millisecond) // 等待goroutine安全退出

	// 输出最终结果
	scanner.Mu.Lock()
	j := len(survival)
	fmt.Println("\n存活主机列表:")
	if j == 0 {
		fmt.Println("未发现任何存活主机")
		fmt.Println("\n可能原因:")
		fmt.Println("1. 目标IP范围内确实没有其他活跃主机")
		fmt.Println("2. 目标主机配置为不响应ARP请求")
		fmt.Println("3. 企业网络有ARP限制")
		fmt.Println("4. 防火墙阻止了ARP回复")
	} else {
		fmt.Println("IP地址\t\t\tMAC地址\t\t\t\t类型")
		//fmt.Println("--------\t-------------------\t--------")
		for ip, mac := range survival {
			hostType := "其他主机"
			if ip == localIPStr {
				hostType = "本机"
			}
			fmt.Printf("%-15s\t%s\t%s\n", ip, mac, hostType)
		}
	}
	scanner.Mu.Unlock()

	usetime := time.Since(start)
	fmt.Printf("\n扫描完成:\n")
	fmt.Printf("存活主机数量: %d\n", j)
	fmt.Printf("运行时间: %v\n", usetime)

	return
}

// 获取网络信息函数 - 基于选择的接口
func getInterfaceNetworkInfo(iface *net.Interface) (net.IP, *net.IPNet, net.HardwareAddr, error) {
	addrs, err := iface.Addrs() //获取这个网络接口的所有ip地址
	if err != nil {
		return nil, nil, nil, err
	}

	//遍历所有的ip地址
	for _, addr := range addrs {
		v, ok := addr.(*net.IPNet)   //将接口的类型转换为 *net.IPNet，并进行ok断言
		if ok && v.IP.To4() != nil { //只处理*net.IPNet类型的地址，只关注IPv4地址
			return v.IP, v, iface.HardwareAddr, nil //返回：IP地址、网络范围、MAC地址
		}
	}

	return nil, nil, nil, fmt.Errorf("no IPv4 address found for interface %s", iface.Name)
}

// 发送ARP请求
func sendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP, dstIP string) {
	targetIP := net.ParseIP(dstIP).To4()
	if targetIP == nil {
		return //转换失败
	}

	// 以太网帧头
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 广播
		EthernetType: layers.EthernetTypeARP,
	}

	// ARP层
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    targetIP,
	}

	// 序列化包
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		return
	}

	// 发送包
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return
	}
}

// 显示可用接口并让用户选择
func selectNetworkInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces() //获取所有网络接口
	if err != nil {
		return nil, err
	}

	fmt.Println("可用的网络接口:")
	var validInterfaces []net.Interface
	for i, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 { //判断网络接口是否开启，是否是回环地址
			addrs, _ := iface.Addrs() //获取这个接口的所有ip地址
			var ipAddrs []string
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					ipAddrs = append(ipAddrs, ipnet.IP.String())
				}
			}
			if len(ipAddrs) > 0 {
				validInterfaces = append(validInterfaces, iface)
				fmt.Printf("%d: %s (MAC: %s, IP: %v)\n", i, iface.Name, iface.HardwareAddr, ipAddrs)
			}
		}
	}

	// 检查是否有有效的网络接口
	if len(validInterfaces) == 0 {
		return nil, fmt.Errorf("no valid network interfaces found")
	}

	fmt.Print("请选择接口编号: ")
	var choice int
	_, err = fmt.Scanln(&choice)
	if err != nil || choice < 0 || choice >= len(interfaces) {
		return nil, fmt.Errorf("invalid choice")
	}

	return &interfaces[choice], nil
}
