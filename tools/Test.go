package main

import "log"

const (
	// TaskType
	TaskType_Subdomain uint64 = 1 << iota // 任务类型：子域名
	TaskType_IP2Port   uint64 = 1 << iota // 任务类型：端口扫描
	TaskType_UrlScan   uint64 = 1 << iota // 任务类型：url扫描
	TaskType_VulsScan  uint64 = 1 << iota // 任务类型：漏洞扫描

	// Status
	Task_Status_Pending     uint64 = 1 << iota // 任务状态：待执行
	Task_Status_InExecution uint64 = 1 << iota // 任务状态：执行中
	Task_Status_Completed   uint64 = 1 << iota // 任务状态：已完成

	// PluginId
	SubDomains_Subfinder            uint64 = 1 << iota // 子域名：Subfinder,https://github.com/projectdiscovery/subfinder
	SubDomains_Sublist3r            uint64 = 1 << iota // 子域名：Sublist3r
	SubDomains_Ksubdomain           uint64 = 1 << iota // 子域名：ksubdomain
	Ip2Ports_VulsCheckFlag_Nmap     uint64 = 1 << iota // 端口扫描工具：Nmap
	Ip2Ports_VulsCheckFlag_Masscan  uint64 = 1 << iota // 端口扫描工具：masscan
	Ip2Ports_VulsCheckFlag_RustScan uint64 = 1 << iota // 端口扫描工具：RustScan
)

func main() {
	log.Println(TaskType_Subdomain, TaskType_IP2Port, TaskType_UrlScan, TaskType_VulsScan)
	log.Println(Task_Status_Pending, Task_Status_InExecution, Task_Status_Completed,
		SubDomains_Subfinder, SubDomains_Sublist3r, SubDomains_Ksubdomain, Ip2Ports_VulsCheckFlag_Nmap, Ip2Ports_VulsCheckFlag_Masscan, Ip2Ports_VulsCheckFlag_RustScan)
}
