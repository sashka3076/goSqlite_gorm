package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	Key1        = "353170776e"
	Nat  string = "//nat"
	// P2P or E2E 前缀
	NatPrefix     string = "//%s/P2P&E2E/"
	NatBodyFormat string = "%s/%s/%s"

	// Nat tracker server之间通讯协议前缀
	S2sPrefix string = "//tcksvr"

	// Tracker S2S Prefix
	SzTrackerS2SPrefix string = "//tcksvr"
	// 默认值
	SzDefault string = "0"
	// port 分隔符号
	SzPortSep string = ":"
	// public Ip分隔
	SzPubSep string = ";"
	// Mac-ip 分隔
	SzMacIpSep string = "-"
	// lan ip 分隔
	SzLanIpSep string = ","
	// 本地ip
	privateIPBlocks []*net.IPNet
	doOnce          sync.Once
	// server default port = ("51pwn" to hex to int) % 65535 = 43283
	ServerDefaultPort int = 43283
	// Tracker server lists
	TrackerServerList []string = []string{}
)

type NatTrackerProtocol struct {
	Msg    string
	Conn   net.PacketConn
	Remote net.Addr
	MsgLen int
}

func Init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// new
func NewNatTrackerProtocol() *NatTrackerProtocol {
	x1 := &NatTrackerProtocol{}
	doOnce.Do(func() {
		Init()
		s11 := x1.HexStr2Str(Key1)
		NatPrefix1 := fmt.Sprintf(NatPrefix, s11)
		NatPrefix = NatPrefix1
		TrackerServerList = append(TrackerServerList, fmt.Sprintf("%s.com:%d", s11, ServerDefaultPort))
		// TrackerServerList = append(TrackerServerList, fmt.Sprintf("127.0.0.1:%d", ServerDefaultPort))
		aS := x1.GetAllTrackerServer()
		for _, j := range aS {
			if "" != j && -1 == x1.ArrStrIndexOf(TrackerServerList, j) {
				TrackerServerList = append(TrackerServerList, j)
			}
		}
	})

	return x1
}

// 私有ip检测
func (r *NatTrackerProtocol) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// generate a UUID
func (r *NatTrackerProtocol) GenerateUUID() string {
	id := uuid.New()
	return id.String()
}

// string to hex
func (r *NatTrackerProtocol) Str2Hex(str string) string {
	return hex.EncodeToString([]byte(str))
}

// HexString to string
func (r *NatTrackerProtocol) HexStr2Str(str string) string {
	s, _ := hex.DecodeString(str)
	return string(s)
}

// hex to in
func (r *NatTrackerProtocol) Hex2Int(hexStr string) int64 {
	value, err := strconv.ParseInt(hexStr, 16, 64)
	if err != nil {
		return -1
	}
	return value
}

// string to port:  ("str" to hex to int) % 65535 =??
func (r *NatTrackerProtocol) Str2Port(str string) int {
	return int(r.Hex2Int(r.Str2Hex(str)) % 65535)
}

// []string indexof
func (r *NatTrackerProtocol) ArrStrIndexOf(a []string, s string) int {
	for i, v := range a {
		if s == v {
			return i
		}
	}
	return -1
}

// get local public Ip to line: ip1:port;ip2:port;ip3:port
func (r *NatTrackerProtocol) GetPublicIP2Line(szPort string) string {
	a, err := r.GetPublicIP()
	if nil == err {
		return SzDefault
	}
	return strings.TrimSuffix(strings.Join(a, SzPortSep+szPort+SzPubSep), SzPubSep)
}

// tracker server to ip lists
func (r *NatTrackerProtocol) TcsvLst2Ips() []string {
	a := []string{}
	for _, i := range TrackerServerList {
		udpAddr, err := net.ResolveUDPAddr("udp", i)
		if nil == err {
			a = append(a, udpAddr.IP.String())
		}
	}
	return a
}

// reg server public ip
func (r *NatTrackerProtocol) RegPublicIP(port string) {
	a1 := r.TcsvLst2Ips()

	a, err := r.GetPublicIP()
	aR := []string{}
	if nil == err && 0 < len(a) {
		for _, v := range a {
			bFd := false
			for _, w := range a1 {
				if -1 < strings.Index(w, v) {
					bFd = true
					continue
				}
			}
			if !bFd {
				aR = append(aR, v+":"+port)
			}
		}
	}
	if 0 < len(aR) {
		s := SzTrackerS2SPrefix + "/" + strings.Join(aR, SzPubSep)
		go r.SendUdp4AllTracker(s)
	}
}

// get all public IP lists
func (r *NatTrackerProtocol) GetPublicIP() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string

	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		// not have mac
		if a != "" {
			addrs, err := ifa.Addrs()
			// get Ip error
			if nil != err {
				continue
			}
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if r.isPrivateIP(v.IP) {
						continue
					}
					as = append(as, v.IP.String())
				case *net.IPAddr:
					if r.isPrivateIP(v.IP) {
						continue
					}
					as = append(as, v.IP.String())
				}
			}
		}
	}
	return as, nil
}

// get Mac-Ip to line
func (r *NatTrackerProtocol) GetMacIPAddrLists2Line4Client() string {
	a, err := r.GetLocalMacIPAddrLists4Client()
	if nil == err {
		s1 := strings.Join(a, SzPubSep)
		// if 20 < len(s1) {
		// 	return s1[0 : len(s1)-1]
		// }
		return s1
	}
	return SzDefault
}

// Get MAC-ip1,ip2;ip4 address
func (r *NatTrackerProtocol) GetLocalMacIPAddrLists4Client() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	aFlt := []string{"192.168.", "10.", "172.16."}
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		// not have mac
		if a != "" {
			addrs, err := ifa.Addrs()
			// get Ip error
			if nil != err {
				continue
			}
			var aR []string
			var x1 string
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					x1 = v.IP.String()
					if r.isPrivateIP(v.IP) {
						if strings.HasPrefix(x1, aFlt[0]) || strings.HasPrefix(x1, aFlt[1]) || strings.HasPrefix(x1, aFlt[2]) {
							aR = append(aR, x1)
						}
					} else {
						aR = append(aR, x1)
					}
				case *net.IPAddr:
					x1 = v.IP.String()
					if r.isPrivateIP(v.IP) {
						if strings.HasPrefix(x1, aFlt[0]) || strings.HasPrefix(x1, aFlt[1]) || strings.HasPrefix(x1, aFlt[2]) {
							aR = append(aR, x1)
						}
					} else {
						aR = append(aR, x1)
					}
				}
			}
			x1 = strings.Join(aR, SzLanIpSep)
			if "" != x1 {
				x1 = a + SzMacIpSep + x1
				if -1 == r.ArrStrIndexOf(as, x1) {
					as = append(as, x1)
				}

			}
		}
	}
	return as, nil
}

// send udp data for one server
func (r *NatTrackerProtocol) SendUdp(szServerIp, msg string) (string, error) {

	address := szServerIp
	// log.Println("start net.Dial ", szServerIp, msg)
	conn, err := net.Dial("udp", address)
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer conn.Close()

	// log.Println("start Write ", msg)
	_, err = conn.Write([]byte(msg))
	if nil != err {
		log.Println(err)
		return "", err
	} else {
		p := make([]byte, 40940)

		// log.Println("start Read ")
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(p)
		if err == nil {
			return string(p[0:n]), nil
		} else {
			return "", err
		}
	}
}

// 这了还需要优化为多线程
func (r *NatTrackerProtocol) SendUdp4AllTracker(msg string) (string, error) {
	var s string
	var err error
	// log.Println("TrackerServerList len:", len(TrackerServerList))
	for _, v := range TrackerServerList {
		s, err = r.SendUdp(v, msg)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(s)
		}

	}
	return s, err
}

// suport IPv4 and IPv6
func (r *NatTrackerProtocol) GetNatPublicIpAndPort4Client() string {
	s, _ := r.SendUdp4AllTracker(Nat)
	return s
}

func (r *NatTrackerProtocol) RegAndGetAllMemberLists4Client(msg string) []string {
	s, _ := r.SendUdp4AllTracker(msg)
	return strings.Split(s, "\n")
}

func (r *NatTrackerProtocol) GetAllTrackerServer() []string {
	s, _ := r.SendUdp4AllTracker(SzTrackerS2SPrefix)
	return strings.Split(s, "\n")
}

// close all log print
func (r *NatTrackerProtocol) CloseAllLogOut() {
	log.SetOutput(ioutil.Discard)
	// defer log.SetOutput(os.Stdout)
	// var std = New(os.Stderr, "", LstdFlags)
}
func main() {
	a, err := NewNatTrackerProtocol().GetLocalMacIPAddrLists4Client()
	if nil == err {
		for _, x := range a {
			log.Println(x)
		}
	}
}
