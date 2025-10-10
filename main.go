package main

import (
	"flag"    // 用于解析命令行参数
	"fmt"     // 用于输入输出
	"net"     // 用于网络操作和DNS解析
	"strconv" // 用于字符串和数字转换
	"strings" // 用于字符串操作
)

// Config 结构体用于存储所有的配置参数
type Config struct {
	Target     string // 目标地址 (IP或域名)
	Ports      string // 端口字符串 (如 "80,443,1000-2000")
	ScanType   string // 扫描类型
	FullScan   bool   // 是否全端口扫描标志
	CommonScan bool   // 是否常见端口扫描标志
	Rate       int    //扫描并发次数
}

func main() {
	// 1. 解析命令行参数
	config := parseFlags()

	// 2. 验证配置参数是否合法
	if err := validateConfig(config); err != nil {
		fmt.Printf("配置错误: %v\n", err)
		return
	}

	// 3. 根据配置解析出要扫描的端口列表
	ports := parsePorts(config)

	// 4. 解析目标地址 (将域名解析为IP地址)
	ipAddress := resolveTarget(config.Target)

	// 5. 通过扫描类型字符串调用对应扫描函数，执行扫描操作
	getScanMode(config.ScanType, ipAddress, ports, config.Rate)

}

// 解析命令行参数
func parseFlags() *Config {
	config := &Config{} // 创建Config结构体实例，这个实例将用于存储所有解析后的命令行参数值

	// 定义命令行参数：
	// - 参数变量, 参数名, 默认值, 参数说明
	flag.StringVar(&config.Target, "t", "", "目标地址 (IP/域名)")
	flag.StringVar(&config.Ports, "p", "", "端口范围 (如: 80,443,1000-2000)")
	flag.StringVar(&config.ScanType, "s", "T", "扫描类型: CONNECT,SYN,ACK,FIN,NULL,UDP")
	flag.BoolVar(&config.FullScan, "A", false, "全端口扫描 (1-65535)")
	flag.BoolVar(&config.CommonScan, "C", false, "常见端口扫描")
	flag.IntVar(&config.Rate, "R", 500, "并发扫描次数")

	// 自定义帮助信息显示
	flag.Usage = func() {
		fmt.Printf("用法: %s [选项]\n", "portscanner")
		fmt.Println("选项:")
		fmt.Println("  -t string    目标地址 (IP/域名)")
		fmt.Println("  -p string    指定端口 (如: 80,443,1000-2000)")
		fmt.Println("  -s string    扫描类型: CONNECT,SYN,ACK,FIN,NULL,UDP (默认: CONNECT)")
		fmt.Println("     T：TCP CONNECT")
		fmt.Println("     S：TCP SYN")
		fmt.Println("     A：TCP ACK")
		fmt.Println("     F：TCP FIN")
		fmt.Println("     N：TCP NULL")
		fmt.Println("     U：UDP")
		fmt.Println("  -A           全端口扫描 (1-65535)")
		fmt.Println("  -C           常见端口扫描")
		fmt.Println("  -R int       并发扫描次数 (默认：500)")
		fmt.Println("\n示例:")
		fmt.Println("  portquiver -t example.com -A")
		fmt.Println("  portquiver -t example.com -A -s A")
		fmt.Println("  portquiver -t 192.168.1.1 -p 80,443,22")
		fmt.Println("  portquiver -t 192.168.1.1 -p 1-1000")
		fmt.Println("  portquiver -t example.com -C -R 1000")
	}

	// 解析命令行参数，将参数值赋给对应的变量
	flag.Parse()
	return config
}

// 验证配置参数是否合法
func validateConfig(config *Config) error {
	// 检查目标地址是否为空
	if config.Target == "" {
		return fmt.Errorf("必须指定目标地址 (-t)")
	}

	// 定义支持的扫描类型列表
	scanTypes := []string{"T", "S", "A", "F", "N", "U"}
	validScanType := false
	// 遍历检查用户输入的扫描类型是否在支持列表中
	for _, t := range scanTypes {
		if config.ScanType == t {
			validScanType = true
			break
		}
	}
	if !validScanType {
		return fmt.Errorf("不支持的扫描类型: %s", config.ScanType)
	}

	// 检查扫描模式：确保用户只选择了一种扫描模式
	scanModes := 0
	if config.FullScan {
		scanModes++ // 全端口扫描模式
	}
	if config.CommonScan {
		scanModes++ // 常见端口扫描模式
	}
	if config.Ports != "" {
		scanModes++ // 自定义端口模式
	}

	// 如果没有指定任何扫描模式，报错
	if scanModes == 0 {
		return fmt.Errorf("必须指定一种扫描模式: -A(全端口) / -C(常见端口) / -p(指定端口) ")
	}

	// 如果指定了多种扫描模式，报错（避免冲突）
	if scanModes > 1 {
		return fmt.Errorf("只能使用一种扫描模式")
	}

	if config.Rate <= 0 {
		return fmt.Errorf("并发数最小为1")
	}

	return nil
}

// 解析端口配置，返回要扫描的端口列表
func parsePorts(config *Config) []int {
	var ports []int // 存储端口号的切片

	if config.FullScan {
		// 全端口扫描：生成1-65535的所有端口
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		fmt.Println("扫描选择: 全端口扫描 (1-65535)")
	} else if config.CommonScan {
		// 常见端口扫描：使用预定义的常见端口列表
		ports = []int{
			20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443,
			445, 465, 587, 636, 993, 995, 1080, 1433, 1521, 2049, 2375, 2379, 2380, 3000, 3306, 3389, 5432, 5672,
			5900, 5938, 6379, 6443, 8000, 8080, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 11211, 27017, 50000,
		}
		fmt.Println("扫描选择: 常见端口扫描")
	} else if config.Ports != "" {
		// 自定义端口：解析用户输入的端口字符串
		ports = parsePortString(config.Ports)
		fmt.Printf("扫描选择: 自定义端口扫描 (%s)\n", config.Ports)
	}

	return ports
}

// 解析端口字符串，支持逗号分隔和范围表示
func parsePortString(portStr string) []int {
	var ports []int
	// 按逗号分割字符串，得到各个端口或端口范围
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)   // 去除前后空格
		if strings.Contains(part, "-") { //检查字符串中是否包含短横线 - ，找到返回true，没有返回false
			// 处理端口范围 (如 "1000-2000")
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(rangeParts[0]) // 转换起始端口
				end, err2 := strconv.Atoi(rangeParts[1])   // 转换结束端口
				// 检查转换是否成功且范围有效
				if err1 == nil && err2 == nil && start > 0 && end > 0 && start <= end {
					// 生成范围内的所有端口
					for i := start; i <= end; i++ {
						ports = append(ports, i)
					}
				}
			}
		} else {
			// 处理单个端口 (如 "80")
			port, err := strconv.Atoi(part) //将字符串转换为整数
			// 检查端口是否在有效范围内
			if err == nil && port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// 解析目标地址，将域名解析为IP地址
func resolveTarget(target string) string {
	// 使用DNS解析将域名转换为IP地址
	host, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		// 如果解析失败，使用原始输入并显示警告
		fmt.Printf("警告: 无法解析地址 %s, 将直接使用: %v\n", target, err)
		return target
	}
	return host.String() // 返回解析后的IP地址字符串
}

// 获取扫描模式，调用对应函数执行操作
func getScanMode(scanType string, ipaddres string, port []int, rate int) {
	var mode string
	if scanType == "T" {
		mode = "CONNECT"
	}
	if scanType == "S" {
		mode = "SYN"
	}
	if scanType == "A" {
		mode = "ACK"
	}
	if scanType == "F" {
		mode = "FIN"
	}
	if scanType == "N" {
		mode = "NULL"
	}
	if scanType == "U" {
		mode = "UDP"
	}

	fmt.Printf("开始扫描 %s, 端口数量: %d, 模式: %s\n", ipaddres, len(port), mode)

	// 根据扫描类型字符串返回对应的数字标识
	switch scanType {
	case "T":
		tcp_connect(ipaddres, port, rate)
	case "S":
		tcp_syn(ipaddres, port, rate)
	case "A":
		tcp_ack(ipaddres, port, rate)
	case "F":
		tcp_fin(ipaddres, port, rate)
	case "N":
		tcp_null(ipaddres, port, rate)
	case "U":
		udp_connect(ipaddres, port, rate)
	}
}
