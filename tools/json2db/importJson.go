package main

import (
	"encoding/json"
	"github.com/hktalent/goSqlite_gorm/pkg/db"
	"github.com/hktalent/goSqlite_gorm/pkg/models"
	"io/ioutil"
	"log"
)

func main() {
	var szFile = "/Users/51pwn/MyWork/mybugbounty/rmtconfig/remoute_serverces.json"
	db.GetDb()
	data, err := ioutil.ReadFile(szFile)
	if nil == err {
		//var m1 map[string]interface{} = make(map[string]interface{})
		//xT := []interface{}{models.WifiLists{}, models.WifiInfo{}, models.Task{}, models.IpInfo{}, models.Ip2Ports{}, models.Domain2Ips{}, models.SubDomainItem{}, models.DomainSite{}, models.Localnet{}, models.ConnectInfo{}, models.RemouteServerce{}, models.DomainInfo{}}
		//for x, j := range xT {
		//	s1 := db.GetTableName(j)
		//	m1[s1] = xT[x]
		//}

		var m map[string]interface{}
		json.Unmarshal(data, &m)
		for _, v := range m {
			a := v.([]interface{})
			t1 := models.RemouteServerce{}
			//t1, ok1 := m1[k]
			//if !ok1 {
			//	continue
			//}
			for _, x := range a {
				m0 := x.(map[string]interface{})
				delete(m0, "date")
				delete(m0, "created_at")
				delete(m0, "updated_at")
				delete(m0, "deleted_at")
				data, err := json.Marshal(x)
				if nil == err {
					//var w models.RemouteServerce
					err = json.Unmarshal(data, &t1)
					if nil == err {
						//log.Println(t1, "save ok")
						id, ok := m0["id"]
						if ok && 0 < db.Update(t1, id) {
							continue
						} else if true { // 0 < db.Create(&t1)
							log.Println(id, "save ok")
						}
					} else {
						log.Println(err, x.(map[string]interface{})["ip"])
					}
				}
			}
			//if t1, ok := m1[k]; ok {
			//	for _, y := range v {
			//		data := json.Marshal()
			//	}
			//}
		}
	}
}
