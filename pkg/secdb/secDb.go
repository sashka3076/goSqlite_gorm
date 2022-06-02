package main

import (
	"github.com/daehee/nvd"
	"log"
)

func main() {
	client, err := nvd.NewClient("./secDb1")
	if nil == err {
		// Fetch single CVE
		//cve, err := client.FetchCVE("CVE-2020-14882")
		// Fetch all recently published and modified CVES
		cves, err := client.FetchUpdatedCVEs()
		if err == nil {
			log.Println(cves)
		} else {
			log.Println(err)
		}
	} else {
		log.Println(err)
	}
}
