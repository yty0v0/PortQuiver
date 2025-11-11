package scanner

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ARP扫描函数
func GetMac(targetIPs []string) map[string]string {
	//如果传入的是空的情况
	if targetIPs == nil || len(targetIPs) == 0 {
		return nil
	}

	survival := make(map[string]string)

	// 自动选择接口
	_, localIP, localNet, localMAC, err := selectNetworkInterfaceAuto()
	if err != nil {
		fmt.Println("MAC地址获取失败")
		return survival
	}

	//fmt.Printf("自动选择接口: %s (IP: %s, MAC: %s)\n", iface.Name, localIP, localMAC)

	// 显示扫描的IP范围
	if len(targetIPs) > 0 {
		// 检查目标IP是否在本地网络内
		firstTarget := net.ParseIP(targetIPs[0])
		if firstTarget != nil && !localNet.Contains(firstTarget) {
			fmt.Println("MAC地址获取失败")
			return survival
		}
	}

	// 检查扫描范围是否包含本地主机，如果包含则添加到存活列表
	localIPStr := localIP.String()
	for _, targetIP := range targetIPs {
		if targetIP == localIPStr {
			Mu.Lock()
			survival[localIPStr] = localMAC.String()
			Mu.Unlock()
			break
		}
	}

	// 获取所有pcap设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("MAC地址获取失败")
		return survival
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
		fmt.Println("MAC地址获取失败")
		return survival
	}

	// 打开pcap句柄
	handle, err := pcap.OpenLive(pcapDevice, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("MAC地址获取失败")
		return survival
	}
	defer handle.Close()

	// 设置过滤器 - 捕获所有ARP包
	_ = handle.SetBPFFilter("arp")

	// 创建包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	//fmt.Println("开始ARP探测...")
	start := time.Now()

	stopChan := make(chan struct{})

	// 启动接收goroutine
	go func() {
		receiveCount := 0 // 总接收包数统计
		replyCount := 0   // ARP回复包数统计

		for {
			select {
			case <-stopChan:
				//fmt.Printf("接收完成: 共接收 %d 个包，其中 %d 个ARP回复\n", receiveCount, replyCount)
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
					//targetIP := net.IP(arp.DstProtAddress).String()             // 目标IP

					// 记录所有ARP回复
					Mu.Lock()
					if _, exists := survival[senderIP]; !exists {
						survival[senderIP] = senderMAC
						//fmt.Printf(">>> 发现存活主机: %s -> %s (回复目标IP: %s)\n", senderIP, senderMAC, targetIP)
					}
					Mu.Unlock()
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

		Wg.Add(1)
		sentCount++

		go func(ip string, seq int) {
			sem <- struct{}{}
			defer Wg.Done()
			defer func() { <-sem }()

			time.Sleep(time.Duration(seq*50) * time.Millisecond) // 增加间隔
			sendARPRequest1(handle, localMAC, localIP, ip)       //发送APR数据包
		}(targetIP, i)
	}
	Wg.Wait()

	//fmt.Printf("总共发送了 %d 个ARP请求\n", sentCount)
	//fmt.Println("所有ARP请求发送完成")

	//fmt.Println("等待接收ARP回复...")
	lastDiscoveryTime := time.Now()

	for {
		time.Sleep(1 * time.Second)
		Mu.Lock()
		currentCount := len(survival)
		Mu.Unlock()

		// 如果有新发现，更新最后发现时间
		if currentCount > 0 {
			lastDiscoveryTime = time.Now()
		}

		// 如果超过3秒没有新发现，就退出
		if time.Since(lastDiscoveryTime) > 3*time.Second {
			break
		}

		// 最大等待15秒
		if time.Since(start) > 15*time.Second {
			break
		}
	}

	// 停止接收
	close(stopChan)
	time.Sleep(500 * time.Millisecond) // 等待goroutine安全退出

	return survival
}

// 自动选择网络接口
func selectNetworkInterfaceAuto() (*net.Interface, net.IP, *net.IPNet, net.HardwareAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	type GetMacResult struct {
		iface    *net.Interface
		ip       net.IP
		net      *net.IPNet
		mac      net.HardwareAddr
		priority int
	}

	var results []GetMacResult //存储所有可用的接口

	for i := range interfaces {
		iface := &interfaces[i]

		// 跳过未启用和回环接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			// 计算优先级
			priority := 0

			// 无线网络优先 (通常为主要网络)
			if iface.Name == "WLAN" || iface.Name == "wlan0" || iface.Name == "Wi-Fi" {
				priority += 30
			}

			// 有线网络次之
			if iface.Name == "以太网" || iface.Name == "eth0" || iface.Name == "Ethernet" {
				priority += 20
			}

			// 虚拟机网络最后
			if iface.Name == "以太网 2" || iface.Name == "VMware" || iface.Name == "VirtualBox" {
				priority += 10
			}

			candidate := GetMacResult{
				iface:    iface,
				ip:       ipNet.IP,
				net:      ipNet,
				mac:      iface.HardwareAddr,
				priority: priority, //记录优先级
			}

			results = append(results, candidate)
		}
	}

	//如果没发现任何网络接口就直接返回
	if len(results) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("no suitable network interfaces found")
	}

	// 选择优先级最高的接口
	bestCandidate := results[0]
	for _, candidate := range results {
		if candidate.priority > bestCandidate.priority {
			bestCandidate = candidate
		}
	}

	//fmt.Printf("自动选择网络接口: %s (优先级: %d)\n", bestCandidate.iface.Name, bestCandidate.priority)
	return bestCandidate.iface, bestCandidate.ip, bestCandidate.net, bestCandidate.mac, nil
}

// 发送ARP请求 (保持不变)
func sendARPRequest1(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP, dstIP string) {
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
