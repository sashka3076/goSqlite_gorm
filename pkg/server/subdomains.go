package server

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/hktalent/go4Hacker/lib/hacker"
	kv "github.com/hktalent/goSqlite_gorm/pkg/common"
	db "github.com/hktalent/goSqlite_gorm/pkg/db"
	"github.com/hktalent/goSqlite_gorm/pkg/es7"
	mds "github.com/hktalent/goSqlite_gorm/pkg/models"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var esChanNum = make(chan struct{}, 5)

func SaveDomain(domain string, ips []string) string {
	defer func() {
		<-esChanNum
	}()
	esChanNum <- struct{}{}
	//log.Println("start save ", domain)
	var d = mds.Domain{Domain: domain, Ips: ips}
	x1 := es7.NewEs7()
	x2 := x1.GetDoc(d, domain)
	if "" != x2 {
		if -1 == strings.Index(x2, "404 Not Found") && -1 < strings.Index(x2, domain) {
			log.Println("exist ", domain, " ", x2)
			return ""
		}
	}
	s := x1.Create(d, domain)
	log.Println("saved ", domain)
	return s
}

var cache = kv.NewKvDbOp()

var nGetIp = make(chan struct{}, 1024*2)

func GetIps(domain string) []string {
	defer func() {
		<-nGetIp
	}()
	nGetIp <- struct{}{}
	a, err := kv.GetAny[[]string](domain)
	if nil == err {
		return a
	}
	a1 := hacker.GetDomian2IpsAll(domain)
	if nil != a1 && 0 < len(a1) {
		//log.Println("ok ", domain)
		go kv.PutAny[[]string](domain, a1)
	}
	return a1
}

// domain list批量转ip，并存储到ES
// 发现的ip直接跳过ip子项
func DoDomainLists(a []string) {
	if nil != a {
		for _, x := range a {
			go func(x string) {
				// 跳过ip
				xreg, err := regexp.Compile(`(\d{1,3}\.){3}\d{1,3}`)
				if nil == err {
					x11 := xreg.FindAllString(x, -1)
					if nil != x11 && 0 < len(x11) {
						// 做端口扫描任务记录
						return
					}
				}
				if -1 < strings.Index(x, "://") {
					x = strings.Split(x, "://")[1]
				}
				if -1 < strings.Index(x, ":") {
					x = strings.Split(x, ":")[0]
				}
				x = strings.TrimSpace(x)
				if 4 < len(x) {
					a = GetIps(x)
					if 0 < len(a) {
						SaveDomain(x, a)
					}
				}
			}(x)
		}
	}
}

func DoDomain2Ips(s string) {
	if "" != s {
		xreg, err := regexp.Compile(`[\n;]`)
		if nil == err {
			a := xreg.Split(s, -1)
			for i, x := range a {
				if -1 < strings.Index(x, "//") {
					a[i] = strings.Split(x, "//")[1]
				}
				if -1 < strings.Index(a[i], ":") {
					a[i] = strings.Split(a[i], "//")[0]
				}
				a[i] = strings.Replace(a[i], "*", "", -1)
				go (func(s00 string) []string {
					return GetIps(s00)
				})(a[i])
			}
		}
	}
}

func DoListDomains(s string) {
	if "" != s {
		xreg, err := regexp.Compile(`[\n;]`)
		if nil == err {
			a := xreg.Split(s, -1)
			for i, x := range a {
				xreg, err = regexp.Compile(`(\d{1,3}\.){3}\d{1,3}`)
				if nil == err {
					x11 := xreg.FindAllString(s, -1)
					if nil != x11 && 0 < len(x11) {
						continue
					}
				}
				if -1 < strings.Index(x, "//") {
					a[i] = strings.Split(x, "//")[1]
				}
				if -1 < strings.Index(a[i], ":") {
					a[i] = strings.Split(a[i], "//")[0]
				}
				a[i] = strings.Replace(a[i], "*", "", -1)
			}
			go DoDomainLists(a)
		}
	}
}

// 获取domian列表信息
func GetDomainLst(g *gin.Context) {
	a := []string{}
	s := GetParms(g, "dlst")
	x := strings.Split(s, "\n")
	for _, j := range x {
		j = strings.TrimSpace(j)
		if "" != j {
			a = append(a, "domain:%20in%20*"+j+"*")
		}
	}
	if 0 < len(a) {
		log.Println(strings.Join(a, "%20or%20"))
		s = es7.GetUrlInfo("http://127.0.0.1:9200/domain_index/_search?q="+strings.Join(a, "%20or%20"), `{"from": 0,"size": 10000}`)
	} else {
		s = "[]"
	}
	var m1 map[string]interface{}
	json.Unmarshal([]byte(s), &m1)
	g.JSON(http.StatusOK, m1)
}

// 获取参数
func GetParms(g *gin.Context, key string) string {
	s := g.Request.FormValue(key)
	if "" == s {
		var m map[string]string
		g.BindJSON(&m)
		if s1, ok := m["dlst"]; ok {
			s = s1
		}
	}
	return s
}

// dlst=
func SaveDomainLst(g *gin.Context) {
	s := GetParms(g, "dlst")
	DoListDomains(s)
	g.JSON(http.StatusOK, gin.H{"msg": "ok", "code": 200})
}

/*
{
"domain": "xx.com",
"subdomains": []
}

*/
func SaveSubDomain(g *gin.Context) {
	var m mds.SubDomain
	if err := g.BindJSON(&m); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"msg": err, "code": ErrCode})
		return
	}

	if -1 < strings.Index(m.Domain, "//") {
		m.Domain = strings.Split(m.Domain, "//")[1]
	}
	if -1 < strings.Index(m.Domain, ":") {
		m.Domain = strings.Split(m.Domain, ":")[0]
	}
	a := GetIps(m.Domain)
	if 0 < len(a) {
		go SaveDomain(m.Domain, a)
	}
	go DoDomainLists(m.Subdomains)
	g.JSON(http.StatusOK, gin.H{"msg": "ok", "code": 200})
}

// 存储任务
// 执行任务
func DoSubDomain(g *gin.Context) {
	var m mds.SubDomainItem
	if err := g.BindJSON(&m); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"msg": "DoSubDomain " + err.Error(), "code": ErrCode})
		return
	}
	// 多行拆分
	re, err := regexp.Compile(`[;,\n\|]`)
	if nil == err {
		m.Domain = strings.TrimSpace(m.Domain)
		a := re.Split(m.Domain, -1)
		for _, x := range a {
			if -1 < strings.Index(x, "//") {
				x = strings.Split(x, "//")[1]
			}
			if -1 < strings.Index(x, ":") {
				x = strings.Split(x, ":")[0]
			}
			// 跳过ip
			xreg, err := regexp.Compile(`(\d{1,3}\.){3}\d{1,3}`)
			if nil == err {
				x11 := xreg.FindAllString(x, -1)
				if nil != x11 && 0 < len(x11) {
					// 做端口扫描任务记录
					// 存储任务到 SQLite
					task := mds.Task{Target: x, TaskType: mds.TaskType_PortScan, Status: mds.Task_Status_Pending}
					// 任务从表中抓去、执行、更新状态
					if 0 < db.Create[mds.Task](&task) {
						// ;
					}
					continue
				}
			}
			// 存储任务到 SQLite
			// ES 中查询记录数大于1，则任务执行过任务

			task := mds.Task{Target: x, TaskType: mds.TaskType_Subdomain, Status: mds.Task_Status_Pending}
			// 任务从表中抓去、执行、更新状态
			if 0 < db.Create[mds.Task](&task) {
				// ;
			}

			// 存储domain ip到关系到ES
			a := GetIps(x)
			if 0 < len(a) {
				go SaveDomain(x, a)
				// 调用端口扫描
				// ;
			}
		}
	}

	//go DoDomainLists(m.Subdomains)
	g.JSON(http.StatusOK, gin.H{"msg": "ok", "code": 200})
}
func InitSubDomainRoute(router *gin.RouterGroup) {
	router.POST("/subdomian", SaveSubDomain)
	router.POST("/doSubdomian", DoSubDomain)
	// 记录域名(转换域名ips信息 + 域名)
	router.POST("/dlists", SaveDomainLst)
	router.POST("/gdlists", GetDomainLst)

}
