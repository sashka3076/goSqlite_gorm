package main

import (
	"flag"
	"fmt"
	"github.com/hktalent/goSqlite_gorm/pkg/db"
	"github.com/hktalent/goSqlite_gorm/pkg/server"
	"gorm.io/gorm"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"regexp"
	"strings"
)

var nThreads1 = make(chan struct{}, 10000)

type Cve202026134 struct {
	gorm.Model
	Url string `json:"url" gorm:"primaryKey,unique_index"`
}

var saveC = make(chan Cve202026134, 2000)

func Log1(msg ...any) {
	fmt.Print(msg)
}

var db1 = db.GetDb(&Cve202026134{}, "db/Cve202026134")

func SaveOut() {
	for {
		select {
		case x := <-saveC:
			if 0 < db.Create[Cve202026134](&x) {
				Log1(x.Url, " is save")
			} else {
				Log1(x.Url, " save err")
			}
		}
	}
}

func CheckOption(domain string) {
	nThreads1 <- struct{}{}
	defer func() {
		<-nThreads1
	}()
	{
		n1 := 70 - len(domain)
		var s0 = ""
		if 0 < n1 {
			s0 = strings.Repeat(" ", n1)
		}
		Log1("start ", domain, s0+"\r")
	}
	// Post "77beaaf8081e4e45adb550194cc0f3a62ebb665f": unsupported protocol scheme ""
	url := "http://" + domain + ":8090/"
	xreg, err := regexp.Compile(`(\d{1,3}\.){3}\d{1,3}`)
	if nil == err {
		x11 := xreg.FindAllString(domain, -1)
		// 不是ip，domain却无法获取到ip就返回
		if nil == x11 || 0 == len(x11) {
			a1 := server.GetIps(domain)
			if 0 == len(a1) {
				return
			}
		}
	}

	//client := http.Client{
	//	Timeout: time.Duration(3 * time.Second),
	//}
	req, err := http.NewRequest("OPTION", url, nil)
	if err != nil {
		Log1(fmt.Sprintf("%s error %v", domain, err))
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15")
	req.Header.Add("Connection", "close")
	req.Close = true

	//resp, err := client.Do(req)
	resp, err := http.DefaultClient.Do(req)
	if resp != nil {
		defer func() {
			err := resp.Body.Close() // resp 可能为 nil，不能读取 Body
			if nil != err {
				Log1(fmt.Sprintf("%s error %v", domain, err))
			}
		}()
	}
	if err == nil && nil != resp {
		s9, ok := resp.Header["X-Confluence-Request-Time"]
		if ok && 0 < len(s9) && "" != s9[0] {
			saveC <- Cve202026134{Url: url}
			Log1("found ", url)
		}
		return
	}
}

// check CVE-2022-26134
// go build -o ./tools/Check_CVE_2020_26134 ./tools/Check_CVE_2020_26134.go
// DbName="db/Cve202026134" CacheName="db/Cve202026134Cache" ./tools/Check_CVE_2020_26134 -config="${HOME}/MyWork/mybugbounty/allDomains.txt"
func main() {
	var domainsName string
	var debug bool
	flag.StringVar(&domainsName, "config", "./allDomains.txt", "config file name")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.Parse()
	if "" != domainsName {
		s1, err := ioutil.ReadFile(domainsName)
		if nil == err {
			a := strings.Split(strings.TrimSpace(string(s1)), "\n")
			if 0 < len(a) {
				// debug 优化时启用///////////////////////
				if debug {
					go func() {
						fmt.Println("debug info: \nopen http://127.0.0.1:6060/debug/pprof/\n")
						http.ListenAndServe(":6060", nil)
					}()
				}
				//////////////////////////////////////////*/
				//os.Setenv("CacheName", "db/Cve202026134Cache")
				Log1("domains num: ", len(a))
				go SaveOut()
				go server.DoDomainLists(a)
				for _, x := range a {
					go func(x1 string) {
						CheckOption(x1)
					}(x)
				}
				select {}
			}
		}

	}
}
