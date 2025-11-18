package utils

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// HostInfoResult 输入数据结构
type HostInfoResult struct {
	IP  string
	MAC string
}

// HostInfo 主机信息结构体
type HostInfo struct {
	IP         string
	MAC        string
	Hostname   string
	Vendor     string       //设备厂商
	DeviceType string       //设备类型
	OSLikely   string       //可能的操作系统
	Confidence int          //置信度(1-100)
	macDB      *MACVendorDB //MAC厂商数据库，指针类型 - 存储的是内存地址
	dnsCache   sync.Map     //DNS缓存
}

// MACVendorDB MAC厂商数据库
type MACVendorDB struct {
	vendors map[string]string //在结构体中定义了一个map类型的字段，以vendors命名
}

// NewMACVendorDB 创建厂商数据库（创建一个构造函数，返回类型是指针）
func NewMACVendorDB() *MACVendorDB {
	// 1. 创建空的MACVendorDB实例
	db := &MACVendorDB{
		vendors: make(map[string]string), //初始化 vendors 字段为一个空的 map
	}
	// 2. 调用initVendors()填充数据
	db.initVendors()
	// 3. 返回包含完整数据的db
	return db // 现在db.vendors包含了所有厂商映射
}

// initVendors 初始化常见厂商OUI，m为接收者，MACVendorDB为接收者类型
// 通过db.initVendors()调用时，db就相当于参数传入m
func (m *MACVendorDB) initVendors() {
	//定义MACVendorDB结构体里vendors的值
	m.vendors = map[string]string{
		// 虚拟化
		"00:0C:29": "VMware",
		"00:50:56": "VMware",
		"08:00:27": "VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:15:5D": "Microsoft-HyperV",
		"0A:00:27": "Hyper-V",

		// 网络设备厂商
		"AA:BB:CC": "Cisco",
		"00:1C:0E": "Huawei",
		"00:26:BB": "H3C",
		"00:1D:0F": "Dell",
		"00:24:E8": "Huawei",
		"00:1A:A9": "Cisco",
		"00:1B:21": "Cisco",
		"7C:00:4D": "Huawei",
		"3C:FF:D8": "Huawei",

		// 手机和消费设备
		"38:65:04": "Honor Device",
		"E0:0A:F6": "ZTE",
		"E2:CD:F8": "Samsung",
		"12:2E:AC": "Unknown",

		// 服务器
		"00:1C:42": "Supermicro",
		"00:0E:0C": "IBM",
		"00:1A:64": "HP",
		"00:21:5A": "Dell",
		"00:14:38": "Dell",

		// 消费设备
		"34:23:BA": "Apple",
		"8C:85:90": "Apple",
		"64:66:B3": "Apple",
		"00:1B:2F": "Intel",
		"00:1E:65": "D-Link",
		"00:23:12": "Intel",
		"00:26:4A": "TP-Link",
		"00:13:10": "Nvidia",
		"00:1F:F3": "ASUS",

		// 常见网络设备
		"00:19:5B": "Netgear",
		"00:21:6A": "Netgear",
		"00:26:F2": "Netgear",
		"00:50:7F": "Netgear",
		"00:E0:4C": "Realtek",
		"00:13:D4": "Realtek",
		"00:14:D1": "Realtek",
		"00:17:31": "Realtek",
		"00:1E:68": "Realtek",
		"00:22:B0": "Realtek",

		// 更多手机厂商
		"34:BB:1F": "Xiaomi",
		"64:09:80": "Xiaomi",
		"8C:85:80": "Huawei",
		"AC:E0:10": "Huawei",
		"FC:E6:67": "Huawei",
		"0C:5A:9E": "Samsung",
		"30:B6:37": "Samsung",
		"5C:3C:27": "Samsung",
		"88:30:8A": "Apple",
		"F0:98:9D": "Apple",

		//新华三的设备
		"38:AD:8E": "New H3C Technologies",
		//"00:26:BB": "H3C",
		//"00:1A:A9": "H3C",
		"00:0F:E2": "H3C",
	}
}

// NewHostInfo 创建HostInfo实例
func NewHostInfo() *HostInfo {
	return &HostInfo{
		macDB: NewMACVendorDB(),
	}
}

// GetHostInfoBatch 批量获取主机信息
func (h *HostInfo) GetHostInfoBatch(datas []HostInfoResult) map[string]string {
	results := make(map[string]string)

	for _, data := range datas {
		info := h.GetHostInfo(data.IP, data.MAC)
		results[data.IP] = info
	}

	return results
}

// GetHostInfo 单个主机信息收集，返回主机信息字符串
func (h *HostInfo) GetHostInfo(ip, mac string) string {
	h.reset()
	h.IP = ip
	h.MAC = strings.ToUpper(mac)

	// 分层信息收集
	h.collectByMAC()
	h.collectByDNS()
	h.collectByNetworkAnalysis()

	return h.formatResult()
}

// GetVendor 获取MAC地址厂商
func (m *MACVendorDB) GetVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(mac[:8])               // mac[:8] 取前8个字符，如 "00:0C:29"，strings.ToUpper() 转为大写，确保大小写一致
	if vendor, exists := m.vendors[prefix]; exists { //查看目标MAC地址是否常见厂商的MAC地址库中
		return vendor
	}
	return "unknown"
}

// reset 重置结构体状态
func (h *HostInfo) reset() {
	h.IP = ""
	h.MAC = ""
	h.Hostname = "unknown"
	h.Vendor = "unknown"
	h.DeviceType = "unknown"
	h.OSLikely = "unknown"
	h.Confidence = 0
}

// collectByMAC 通过MAC地址收集信息
func (h *HostInfo) collectByMAC() {
	if h.MAC == "" {
		return
	}

	// 验证MAC地址格式
	if !h.isValidMAC(h.MAC) {
		h.Vendor = "invalid-mac"
		h.Confidence = 0
		return
	}

	// 获取厂商信息
	vendor := h.macDB.GetVendor(h.MAC)
	h.Vendor = vendor

	// 基于MAC推断设备类型和操作系统
	h.inferFromMAC()

	// MAC地址本身提供基础置信度
	h.Confidence += 30
}

// collectByDNS DNS查询
func (h *HostInfo) collectByDNS() {
	if h.IP == "" {
		return
	}

	// 检查缓存
	if cached, ok := h.dnsCache.Load(h.IP); ok {
		if hostname, ok := cached.(string); ok && hostname != "" {
			h.Hostname = hostname
			h.Confidence += 15

			// 基于主机名进一步分析 - 这里会覆盖之前的MAC推断
			h.analyzeHostname(hostname)
			return
		}
	}

	// DNS反向查询
	names, err := net.LookupAddr(h.IP)
	if err == nil && len(names) > 0 {
		hostname := names[0]
		if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}
		h.Hostname = hostname
		h.dnsCache.Store(h.IP, hostname)
		h.Confidence += 15

		// 基于主机名进一步分析 - 这里会覆盖之前的MAC推断
		h.analyzeHostname(hostname)
	}
}

// collectByNetworkAnalysis 网络特征分析
func (h *HostInfo) collectByNetworkAnalysis() {
	if h.IP == "" {
		return
	}

	ip := net.ParseIP(h.IP) // 尝试将字符串解析为net.IP类型
	if ip == nil {
		return
	}

	// 私有地址识别
	if h.isPrivateIP(ip) {
		h.Confidence += 5
	}

	// 特殊地址识别
	switch h.IP {
	case "127.0.0.1", "::1":
		h.DeviceType = "Local Host"
		h.OSLikely = "Local OS"
		h.Confidence = 100
	case "0.0.0.0":
		h.DeviceType = "Any Interface"
		h.Confidence = 100
	case "255.255.255.255":
		h.DeviceType = "Broadcast"
		h.Confidence = 100
	}
}

// inferFromMAC 基于MAC地址推断详细信息
func (h *HostInfo) inferFromMAC() {
	mac := h.MAC
	vendor := h.Vendor

	// 虚拟化环境识别
	if h.isVirtualizationMAC(mac) {
		h.DeviceType = "Virtual Machine"
		//从上到下依次检查每个 case 的条件,第一个为true的条件会被执行，执行完后退出整个switch
		switch { //根据之前获取的厂商来推断可能的操作系统
		case strings.Contains(vendor, "VMware"):
			h.OSLikely = "VMware Guest"
		case strings.Contains(vendor, "VirtualBox"):
			h.OSLikely = "VirtualBox Guest"
		case strings.Contains(vendor, "QEMU"):
			h.OSLikely = "KVM/QEMU Guest"
		case strings.Contains(vendor, "HyperV"):
			h.OSLikely = "Hyper-V Guest"
		default:
			h.OSLikely = "Virtualized OS"
		}
		h.Confidence += 20
		return
	}

	// 网络设备识别
	if h.isNetworkDeviceMAC(mac) {
		h.DeviceType = "Network Device"
		switch {
		case strings.Contains(vendor, "Cisco"):
			h.OSLikely = "Cisco IOS"
		case strings.Contains(vendor, "Huawei"):
			h.OSLikely = "Huawei VRP"
		case strings.Contains(vendor, "H3C"):
			h.OSLikely = "H3C Comware"
		case strings.Contains(vendor, "Dell"):
			h.OSLikely = "Dell OS"
		default:
			h.OSLikely = "Embedded Network OS"
		}
		h.Confidence += 15
		return
	}

	// 服务器识别
	if h.isServerMAC(mac) {
		h.DeviceType = "Server"
		switch {
		case strings.Contains(vendor, "Dell"):
			h.OSLikely = "Server OS (Dell)"
		case strings.Contains(vendor, "HP"):
			h.OSLikely = "Server OS (HP)"
		case strings.Contains(vendor, "IBM"):
			h.OSLikely = "Server OS (IBM)"
		case strings.Contains(vendor, "Supermicro"):
			h.OSLikely = "Server OS"
		default:
			h.OSLikely = "Linux/Windows Server"
		}
		h.Confidence += 10
		return
	}

	// 消费设备 - 更精确的系统推断
	if h.isConsumerDeviceMAC(mac) {
		h.DeviceType = "End Device"
		switch {
		case strings.Contains(vendor, "Apple"):
			h.OSLikely = "macOS/iOS"
		case strings.Contains(vendor, "Samsung"):
			h.OSLikely = "Android/Windows"
		case strings.Contains(vendor, "Honor"):
			h.OSLikely = "Android"
		case strings.Contains(vendor, "ZTE"):
			h.OSLikely = "Android/Windows"
		case strings.Contains(vendor, "Xiaomi"):
			h.OSLikely = "Android"
		case strings.Contains(vendor, "Intel"):
			h.OSLikely = "Windows/Linux"
		case strings.Contains(vendor, "D-Link"):
			h.OSLikely = "Embedded OS"
		default:
			h.OSLikely = "Various OS"
		}
		h.Confidence += 5
		return
	}

	// 默认推断
	h.DeviceType = "Network Device"
	h.OSLikely = "Unknown OS"
}

// 辅助方法
func (h *HostInfo) isValidMAC(mac string) bool {
	_, err := net.ParseMAC(mac) // 尝试解析MAC地址
	return err == nil           // 如果没有错误，说明格式正确
}

func (h *HostInfo) isVirtualizationMAC(mac string) bool {
	virtualPrefixes := []string{"00:0C:29", "00:50:56", "08:00:27", "52:54:00", "00:15:5D"}
	return h.macHasPrefix(mac, virtualPrefixes)
}

func (h *HostInfo) isNetworkDeviceMAC(mac string) bool {
	networkPrefixes := []string{"AA:BB:CC", "00:1C:0E", "00:26:BB", "00:1D:0F", "00:24:E8", "00:1A:A9", "00:1B:21", "7C:00:4D", "3C:FF:D8"}
	return h.macHasPrefix(mac, networkPrefixes)
}

func (h *HostInfo) isServerMAC(mac string) bool {
	serverPrefixes := []string{"00:1C:42", "00:0E:0C", "00:1A:64", "00:21:5A", "00:14:38"}
	return h.macHasPrefix(mac, serverPrefixes)
}

func (h *HostInfo) isConsumerDeviceMAC(mac string) bool {
	consumerPrefixes := []string{
		"34:23:BA", "8C:85:90", "64:66:B3", // Apple
		"38:65:04", "E0:0A:F6", "E2:CD:F8", // 手机设备
		"34:BB:1F", "64:09:80", // Xiaomi
		"0C:5A:9E", "30:B6:37", "5C:3C:27", // Samsung
		"88:30:8A", "F0:98:9D", // Apple
		"00:1B:2F", "00:1E:65", "00:23:12", "00:26:4A", // 其他消费设备
	}
	return h.macHasPrefix(mac, consumerPrefixes)
}

func (h *HostInfo) macHasPrefix(mac string, prefixes []string) bool {
	for _, prefix := range prefixes {
		//检查MAC地址前缀是否匹配指定前缀列表
		if strings.HasPrefix(strings.ToUpper(mac), prefix) {
			return true
		}
	}
	return false
}

// 私有地址空间识别
func (h *HostInfo) isPrivateIP(ip net.IP) bool {
	_, private24, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16, _ := net.ParseCIDR("192.168.0.0/16")
	return private24.Contains(ip) || private20.Contains(ip) || private16.Contains(ip)
}

// 主机名分析
func (h *HostInfo) analyzeHostname(hostname string) {
	lowerHostname := strings.ToLower(hostname) //将主机名统一转为小写，避免大小写匹配问题

	// 过滤掉无意义的主机名
	if hostname == "bogon" || hostname == "localhost" || strings.Contains(lowerHostname, "localdomain") {
		h.Hostname = "unknown"
		return
	}

	// 基于主机名的系统识别 - 主机名分析具有最高优先级
	switch {
	case strings.Contains(lowerHostname, "win-") ||
		strings.Contains(lowerHostname, "windows") ||
		strings.Contains(lowerHostname, "pc-") ||
		strings.Contains(lowerHostname, "desktop"):
		h.DeviceType = "Windows Host"
		h.OSLikely = "Windows"
		h.Confidence += 15 // 主机名识别置信度更高

	case strings.Contains(lowerHostname, "ubuntu") ||
		strings.Contains(lowerHostname, "debian") ||
		strings.Contains(lowerHostname, "centos") ||
		strings.Contains(lowerHostname, "redhat") ||
		strings.Contains(lowerHostname, "fedora") ||
		strings.Contains(lowerHostname, "linux"):
		h.DeviceType = "Linux Host"
		h.OSLikely = "Linux"
		h.Confidence += 15

	case strings.Contains(lowerHostname, "mac") ||
		strings.Contains(lowerHostname, "apple"):
		h.DeviceType = "Apple Device"
		h.OSLikely = "macOS"
		h.Confidence += 15

	case strings.Contains(lowerHostname, "router") ||
		strings.Contains(lowerHostname, "rt-"):
		h.DeviceType = "Router"
		h.OSLikely = "Embedded OS"
		h.Confidence += 10

	case strings.Contains(lowerHostname, "switch") ||
		strings.Contains(lowerHostname, "sw-"):
		h.DeviceType = "Switch"
		h.OSLikely = "Embedded OS"
		h.Confidence += 10

	case strings.Contains(lowerHostname, "firewall") ||
		strings.Contains(lowerHostname, "fw-"):
		h.DeviceType = "Firewall"
		h.OSLikely = "Embedded OS"
		h.Confidence += 10

	case strings.Contains(lowerHostname, "server") ||
		strings.Contains(lowerHostname, "srv-"):
		h.DeviceType = "Server"
		h.OSLikely = "Linux/Windows Server"
		h.Confidence += 10

	case strings.Contains(lowerHostname, "vm") ||
		strings.Contains(lowerHostname, "virtual"):
		h.DeviceType = "Virtual Machine"
		h.OSLikely = "Virtualized OS"
		h.Confidence += 10

	case strings.Contains(lowerHostname, "dc"):
		h.DeviceType = "Domain Controller"
		h.OSLikely = "Windows Server"
		h.Confidence += 15

	default:
		// 如果主机名包含特定模式但未匹配上述情况，保持原有推断
	}
}

// formatResult 格式化返回结果
func (h *HostInfo) formatResult() string {
	if h.Confidence > 100 {
		h.Confidence = 100
	}

	// 根据置信度调整输出
	if h.Confidence < 30 {
		return fmt.Sprintf("信息不足 (置信度: %d%%)", h.Confidence)
	}

	// 标准信息输出
	parts := []string{} //创建一个空的字符串切片

	if h.Vendor != "unknown" {
		parts = append(parts, fmt.Sprintf("%s(厂商)", h.Vendor))
	}
	if h.DeviceType != "unknown" {
		parts = append(parts, fmt.Sprintf("%s(类型)", h.DeviceType))
	}
	if h.OSLikely != "Unknown OS" {
		parts = append(parts, fmt.Sprintf("%s(系统)", h.OSLikely))
	}
	if h.Hostname != "unknown" {
		parts = append(parts, fmt.Sprintf("%s(主机名)", h.Hostname))
	}

	if len(parts) > 0 {
		return fmt.Sprintf("%s (置信度: %d%%)", strings.Join(parts, ", "), h.Confidence)
	}

	return fmt.Sprintf("未知设备 (置信度: %d%%)", h.Confidence)
}

// String 方法，便于输出HostInfo结构体
func (h *HostInfo) String() string {
	return h.formatResult()
}
