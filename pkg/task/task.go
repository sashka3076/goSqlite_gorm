package task

import (
	mycmd "github.com/hktalent/goSqlite_gorm/pkg/common"
	db "github.com/hktalent/goSqlite_gorm/pkg/db"
	mymod "github.com/hktalent/goSqlite_gorm/pkg/models"
	"github.com/hktalent/goSqlite_gorm/pkg/sshsv"
	"github.com/robfig/cron"
	"gorm.io/gorm"
	"log"
)

var dbCC *gorm.DB = db.GetDb(&mymod.ConnectInfo{})

func DoAllTask() {
	sshsv.NewSshSv()
	c := cron.New()
	// 秒 分 时 日 月 年
	// 每30秒获取一次本机的互联网连接
	c.AddFunc("30 * * * * *", func() {
		go DoGetConnInfo()
		go mycmd.Locked4MeSafe()
	})
	// 每分钟获取一次wifi 列表
	c.AddFunc("0 1 * * * *", func() {
		go mycmd.DoWifiListsInfo()
	})
	// 每1h更新 重要的github项目
	c.AddFunc("0 0 23 * * *", func() {
		go mycmd.UpTop()
	})
	c.Start()
}

func DoGetConnInfo() {
	var x []mymod.ConnectInfo = mycmd.GetCurConnInfo()
	var queryRst mymod.ConnectInfo
	dbCC.AutoMigrate(&mymod.IpInfo{})
	dbCC.AutoMigrate(&mymod.ConnectInfo{})
	for _, k := range x {
		xx1 := dbCC.Model(&mymod.ConnectInfo{}).Where("ip=? and pid = ?", k.Ip, k.Pid)
		rst := xx1.Find(&queryRst)
		if 0 < rst.RowsAffected {
			rst = xx1.Updates(&k)
			if nil != rst.Error {
				log.Println(rst.RowsAffected, rst.Error)
			}
		} else {
			rst = dbCC.Create(&k)
		}
	}

}

//
//func main() {
//	DoAllTask()
//}
