#!/bin/bash

# http://127.0.0.1:9200/_cat/indices
curPath=$HOME/MyWork/goSqlite_gorm
cd $HOME/MyWork/advisory-database/advisories/github-reviewed
git fetch --all
git reset --hard origin/main
git pull
cd ${curPath}
./tools/Json2Es -dir="$HOME/MyWork/advisory-database/advisories/github-reviewed" -resUrl="http://127.0.0.1:9200/intelligence_index/_doc/"
wkPath="${HOME}/MyWork/cvelist"
cd $wkPath
git fetch --all
git reset --hard origin/main
git pull
cd ${curPath}
./tools/Json2Es -dir="${wkPath}" -resUrl="http://127.0.0.1:9200/cve_index/_doc/" -IdQuery=".CVE_data_meta.ID" -MdfQuery=".CVE_data_meta.DATE_PUBLIC"
