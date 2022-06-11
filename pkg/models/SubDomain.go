package models

import (
	"gorm.io/gorm"
)

// 存储到ES
type SubDomain struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Tags       string   `json:"tags,omitempty"` // 标识属于那个tag，例如hackerone
}

//http://127.0.0.1:9200/domain_index/_search?q=domain:%20in%20*qianxin*
type Domain struct {
	Domain string   `json:"domain"`
	Ips    []string `json:"ips"`
}

/*
局部性更新文档，下面的代码借助go json的omitempty，在将更新数据对象序列化成json，
可以只序列化非零值字段，实现局部更新。 实际项目采用这种方式时，
需要注意某个字段的零值具有业务意义时，可以采用对应的指针类型实现
*/
type SubDomainItem struct {
	gorm.Model
	Domain    string `json:"domain"`
	SubDomain string `json:"subDomain"`
	ToolName  uint64 `json:"toolName,omitempty"` // 支持多个工具
	Tags      string `json:"tags,omitempty"`     // 标识属于那个tag，例如hackerone
}

// domain to ips
// ip to Domain
type Domain2Ips struct {
	gorm.Model
	Domain   string `json:"domain"`
	Ip       string `json:"ip"`
	ToolName uint64 `json:"toolName,omitempty"` // 支持多个工具
}

// 端口扫描，及端口漏洞扫描
type Ip2Ports struct {
	gorm.Model
	MyId          string `json:"myId,omitempty"` // 对应ES domain id，可以为空
	Ip            string `json:"ip"`
	Port          int    `json:"port"`
	Des           string `json:"des,omitempty"`
	ToolName      uint64 `json:"toolName,omitempty"`      // 支持多个工具
	VulsCheckFlag uint64 `json:"vulsCheckFlag,omitempty"` // 每一位表示一个工具，所以，可以支持64种工具、插件对该port进行扫描
	VulsCheckRst  string `json:"vulsCheckRst,omitempty"`
}

// ip 经纬度 info
// curl -H 'User-Agent:curl/1.0' http://ip-api.com/json/107.182.191.202|jq
type IpInfo struct {
	gorm.Model
	Continent     string  `json:"continent"`
	ContinentCode string  `json:"continentCode"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"countryCode"`
	Region        string  `json:"region"`
	RegionName    string  `json:"regionName"`
	City          string  `json:"city"`
	District      string  `json:"district"`
	Zip           string  `json:"zip"`
	Lat           float64 `json:"lat"`
	Lon           float64 `json:"lon"`
	Timezone      string  `json:"timezone"`
	Offset        string  `json:"offset"`
	Currency      string  `json:"currency"`
	Isp           string  `json:"isp"`
	Org           string  `json:"org"`
	As            string  `json:"as"`
	Asname        string  `json:"asname"`
	Mobile        string  `json:"mobile"`
	Proxy         string  `json:"proxy"`
	Hosting       string  `json:"hosting"`
	Ip            string  `json:"query" gorm:"unique_index"` // IP
}

// 执行任务
type Task struct {
	gorm.Model
	Target   string `json:"target"`
	TaskType uint64 `json:"taskType"`
	PluginId string `json:"pluginId"`
	Status   uint64 `json:"status"` // 状态:待执行，执行中，已完成
}

const (
	// 任务类型
	TaskType_Subdomain   uint64 = 1 << iota // 任务类型：子域名
	TaskType_PortScan    uint64 = 1 << iota // 任务类型：端口扫描
	TaskType_UrlScan     uint64 = 1 << iota // 任务类型：url扫描
	TaskType_Fingerprint uint64 = 1 << iota // 任务类型：指纹识别
	TaskType_VulsScan    uint64 = 1 << iota // 任务类型：漏洞扫描

	// 任务状态
	Task_Status_Pending     uint64 = 1 << iota // 任务状态：待执行
	Task_Status_InExecution uint64 = 1 << iota // 任务状态：执行中
	Task_Status_Completed   uint64 = 1 << iota // 任务状态：已完成

	// 子域名遍历
	SubDomains_Amass     uint64 = 1 << iota // 子域名：amass 7.2k
	SubDomains_Subfinder uint64 = 1 << iota // 子域名：Subfinder 5.6k,https://github.com/projectdiscovery/subfinder
	SubDomains_Sublist3r uint64 = 1 << iota // 子域名：Sublist3r 7.1k
	SubDomains_Gobuster  uint64 = 1 << iota // 服务、目录发现：gobuster 6k,https://github.com/OJ/gobuster// gobuster dns -d google.com -w ~/wordlists/subdomains.txt

	// 端口扫描
	Ip2Ports_VulsCheckFlag_Masscan  uint64 = 1 << iota // 端口扫描工具：masscan 19.1k, https://github.com/robertdavidgraham/masscan
	Ip2Ports_VulsCheckFlag_RustScan uint64 = 1 << iota // 端口扫描工具：RustScan 6.3k,https://github.com/RustScan/RustScan
	Ip2Ports_VulsCheckFlag_Nmap     uint64 = 1 << iota // 端口扫描工具：Nmap, https://github.com/vulnersCom/nmap-vulners

	// 指纹
	ScanType_Fingerprint_Wappalyzer uint64 = 1 << iota // 指纹:wappalyzer 7.5k, https://github.com/wappalyzer/wappalyzer
	ScanType_Fingerprint_WhatWeb    uint64 = 1 << iota // 指纹: WhatWeb 3.8k,https://github.com/urbanadventurer/WhatWeb
	ScanType_Fingerprint_EHole      uint64 = 1 << iota // 指纹:EHole 1.4k,https://github.com/EdgeSecurityTeam/EHole

	// 服务、目录发现
	ScanType_Discovery_Gobuster uint64 = 1 << iota // 服务、目录发现：gobuster 6k,https://github.com/OJ/gobuster
	ScanType_Discovery_Fscan    uint64 = 1 << iota // 服务、目录发现：fscan 3.6k,https://github.com/shadow1ng/fscan
	ScanType_Discovery_Httpx    uint64 = 1 << iota // 服务、目录发现：httpx 3.2k,https://github.com/projectdiscovery/httpx
	ScanType_Discovery_Naabu    uint64 = 1 << iota // 服务、目录发现：naabu 2.1k,https://github.com/projectdiscovery/naabu
	//  Others
	// https://github.com/NVIDIA/NeMo
	// https://github.com/veo/vscan

	// 漏洞扫描
	ScanType_Nuclei uint64 = 1 << iota // 漏洞扫描：nuclei 8.4k，https://github.com/projectdiscovery/nuclei
)
