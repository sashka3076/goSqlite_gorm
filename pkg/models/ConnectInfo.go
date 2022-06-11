package models

import (
	"gorm.io/gorm"
)

// domain info
type DomainInfo struct {
	gorm.Model
	Name string   `json:"name" gorm:"unique_index"`
	Ips  []IpInfo `json:"ips" gorm:"foreignKey:ip;references:name"`
}

// 连接信息
type ConnectInfo struct {
	gorm.Model
	Pid    string `json:"pid"`
	Ip     string `json:"ip"`
	Cmd    string `json:"cmd"`
	IpInfo IpInfo `json:"ipInfo" gorm:"foreignkey:ip;references:ip"`
}
