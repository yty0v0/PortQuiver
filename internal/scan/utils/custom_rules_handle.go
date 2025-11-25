package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CustomRule 自定义规则结构
type CustomRule struct {
	Name      string   `json:"name"`
	Ports     []int    `json:"ports"`
	Protocol  string   `json:"protocol"` // tcp or udp
	Data      string   `json:"data"`     // 十六进制字符串或普通字符串
	SendFirst bool     `json:"send_first"`
	Match     []string `json:"match"`     // 正则表达式匹配规则
	IsBinary  []bool   `json:"is_binary"` // 每个匹配规则是否为二进制模式
	Service   string   `json:"service"`   // 服务名称
}

// CustomRulesConfig 自定义规则配置
type CustomRulesConfig struct {
	Rules []CustomRule `json:"rules"`
}

// CustomRulesManager 自定义规则管理器
type CustomRulesManager struct {
	rules    []ServiceProbe // 存储加载的自定义规则列表，每个规则都是ServiceProbe类型
	loaded   bool           // 标记规则是否已成功加载的标志位，true表示已加载，false表示未加载
	filePath string         // 自定义规则配置文件的完整路径
	mu       sync.RWMutex   // 读写锁，用于保证并发访问时的线程安全
}

var (
	customRulesManager *CustomRulesManager
	once               sync.Once
)

// GetCustomRulesManager 获取自定义规则管理器单例
func GetCustomRulesManager() *CustomRulesManager {
	once.Do(func() {
		customRulesManager = &CustomRulesManager{
			rules:  make([]ServiceProbe, 0),
			loaded: false,
		}
	})
	return customRulesManager
}

// LoadCustomRules 加载自定义规则
func (crm *CustomRulesManager) LoadCustomRules(filePath string) error {
	crm.mu.Lock()
	defer crm.mu.Unlock()

	crm.filePath = filePath

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// 文件不存在，创建空的配置文件
		if err := crm.createEmptyConfig(filePath); err != nil {
			return fmt.Errorf("创建空配置文件失败: %v", err)
		}
		fmt.Printf("自定义规则文件不存在，已创建空文件: %s\n", filePath)
		return nil
	} else if err != nil {
		//处理其它情况的错误
		return err
	}

	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取自定义规则文件失败: %v", err)
	}

	// 解析JSON
	var config CustomRulesConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析自定义规则JSON失败: %v", err)
	}

	// 转换为ServiceProbe
	crm.rules = make([]ServiceProbe, 0)
	for _, customRule := range config.Rules { //遍历所有自定义的规则
		probe, err := crm.convertToServiceProbe(customRule)
		if err != nil {
			fmt.Printf("警告: 转换规则 %s 失败: %v\n", customRule.Name, err)
			continue
		}
		crm.rules = append(crm.rules, probe)
	}

	crm.loaded = true
	fmt.Printf("成功加载 %d 个自定义规则\n", len(crm.rules))
	return nil
}

// convertToServiceProbe 将自定义规则转换为ServiceProbe
func (crm *CustomRulesManager) convertToServiceProbe(rule CustomRule) (ServiceProbe, error) {
	probe := ServiceProbe{
		Name:      rule.Name,
		SendFirst: rule.SendFirst,
		Ports:     rule.Ports,
	}

	// 处理发送数据
	if rule.Data != "" {
		// 尝试解析为十六进制
		var dataBytes []byte
		if isHexString(rule.Data) {
			hexBytes, err := hexStringToBytes(rule.Data)
			if err != nil {
				// 如果不是有效的十六进制，当作普通字符串处理
				dataBytes = []byte(rule.Data)
			} else {
				dataBytes = hexBytes
			}
		} else {
			// 如果不是十六进制，当作普通字符串处理
			dataBytes = []byte(rule.Data)
		}
		probe.Data = dataBytes
	}

	// 处理匹配规则
	probe.Match = make([]MatchRule, 0)
	for i, matchPattern := range rule.Match {
		isBinary := false

		// 如果有明确的二进制配置，使用配置
		if i < len(rule.IsBinary) {
			isBinary = rule.IsBinary[i]
		} else {
			// 向后兼容：自动检测
			isBinary = crm.autoDetectBinary(matchPattern)
		}

		matchRule := MatchRule{
			PatternStr: matchPattern,
			Service:    rule.Service,
			Proto:      rule.Protocol,
			IsBinary:   isBinary,
		}
		probe.Match = append(probe.Match, matchRule)
	}

	return probe, nil
}

// autoDetectBinary 自动检测是否为二进制模式（向后兼容）
func (crm *CustomRulesManager) autoDetectBinary(pattern string) bool {
	// 简化的二进制模式检测
	if strings.Contains(pattern, "\\x") {
		return true
	}
	// 检测非可打印字符
	for _, r := range pattern {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}
	return false
}

// GetCustomProbesForPort 获取指定端口的自定义探测规则
func (crm *CustomRulesManager) GetCustomProbesForPort(port int) []ServiceProbe {
	crm.mu.RLock()
	defer crm.mu.RUnlock()

	var matchedProbes []ServiceProbe
	for _, probe := range crm.rules {
		// 检查规则是否适用于该端口
		if crm.isProbeForPort(probe, port) {
			matchedProbes = append(matchedProbes, probe)
		}
	}

	return matchedProbes
}

// isProbeForPort 检查探测规则是否适用于指定端口
func (crm *CustomRulesManager) isProbeForPort(probe ServiceProbe, port int) bool {
	// 从规则名称中提取端口信息（Custom_Name_PortXXX格式）
	// 这里可以根据实际需要实现更复杂的端口匹配逻辑
	// 当前实现返回所有自定义规则，让调用方决定如何使用

	//自定义规则没有指定端口时，所有端口都使用此规则
	if len(probe.Ports) == 0 {
		return true
	}

	//自定义规则指定一个或多个端口时，看看是否指定当前扫描的端口
	for _, p := range probe.Ports {
		if p == port {
			return true
		}
	}

	//既不指定所有端口，又没指定当前端口
	return false
}

// createEmptyConfig 创建空的配置文件
func (crm *CustomRulesManager) createEmptyConfig(filePath string) error {
	// 确保目录存在
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 创建示例配置
	exampleConfig := CustomRulesConfig{
		Rules: []CustomRule{
			{
				Name:      "ExampleService",
				Ports:     []int{9999},
				Protocol:  "tcp",
				Data:      "HELLO\r\n",
				SendFirst: true,
				Match:     []string{"^WELCOME.*Version:([0-9.]+)"},
				IsBinary:  []bool{false}, // 明确指定为文本模式
				Service:   "example-service",
			},
		},
	}

	data, err := json.MarshalIndent(exampleConfig, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

// IsLoaded 检查规则是否已加载
func (crm *CustomRulesManager) IsLoaded() bool {
	crm.mu.RLock()
	defer crm.mu.RUnlock()
	return crm.loaded
}

// 工具函数

// isHexString 检查字符串是否为十六进制格式
func isHexString(s string) bool {
	if len(s) < 2 {
		return false
	}
	// 简单的检查：如果包含非十六进制字符，则不是十六进制字符串
	for _, char := range s {
		if !((char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'f') ||
			(char >= 'A' && char <= 'F') ||
			char == ' ') {
			return false
		}
	}
	return true
}

// hexStringToBytes 将十六进制字符串转换为字节数组
func hexStringToBytes(hexStr string) ([]byte, error) {
	// 移除空格
	cleanStr := ""
	for _, char := range hexStr {
		if char != ' ' {
			cleanStr += string(char)
		}
	}

	// 检查长度是否为偶数
	if len(cleanStr)%2 != 0 {
		return nil, fmt.Errorf("十六进制字符串长度必须为偶数")
	}

	bytes := make([]byte, len(cleanStr)/2)
	for i := 0; i < len(cleanStr); i += 2 {
		var b byte
		_, err := fmt.Sscanf(cleanStr[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		bytes[i/2] = b
	}

	return bytes, nil
}
