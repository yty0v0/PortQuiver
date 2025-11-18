package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var Wg sync.WaitGroup
var Mu sync.Mutex

// 辅助函数，获取ipv4地址
func SelectIPv4(addrs []net.IP) (net.IP, error) {
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}
	return nil, fmt.Errorf("未找到IPv4地址")
}

// 根据目标IP获取本地IP和端口
func GetlocalIPPort(dstip string) (net.IP, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip+":54321")
	if err != nil {
		return nil, 0, err
	}

	con, err := net.DialUDP("udp", nil, serverAddr)
	if err == nil {
		udpaddr, ok := con.LocalAddr().(*net.UDPAddr)
		if ok {
			return udpaddr.IP, udpaddr.Port, nil
		}
	}
	defer con.Close()
	return nil, -1, err
}

// generateRandomSeq 生成随机序列号
func GenerateRandomSeq() uint32 {
	return uint32(time.Now().UnixNano())
}

// 获取随机源端口
func GenerateRandomPort() int {
	return 40000 + time.Now().Nanosecond()%1000
}

// 处理ip地址，使主机位可以进行遍历（示例：传入host=192.168.5.1,j=6，经过这个函数可以把host改为192.168.5.6）
func Ip_handle1(host string, j int) string {
	arr := strings.Split(host, ".") //根据'.'将字符串分割成数组
	arr[3] = fmt.Sprintf("%d", j)   //把int类型转为string类型再赋值
	arr1 := strings.Join(arr, ".")  //用'.'重新连接数字每一项
	return arr1
}

// 处理ip地址，处理范围输入的情况，（示例：传入192.168.5.1-100，经过这个函数可以提取出start=1,end=100）
func Ip_handle2(host string) (string, string) {
	var start, end string
	arr := strings.Split(host, "-")

	//判断是范围输入还是单个ip输入
	if len(arr) != 2 { //单个ip输入的情况
		arr1 := strings.Split(arr[0], ".")
		start = arr1[3]
		end = start //初始范围等于结束范围
	} else { //范围ip输入的情况
		end = arr[len(arr)-1]
		arr1 := strings.Split(arr[0], ".")
		start = arr1[3]
	}
	return start, end
}
