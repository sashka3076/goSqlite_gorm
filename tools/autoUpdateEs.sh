#!/bin/bash

# http://127.0.0.1:9200/_cat/indices
curPath=`pwd`
wkPath="${HOME}/MyWork/cvelist"
cd $wkPath
git pull
${curPath}/tools/Json2Es -dir="${wkPath}" -resUrl="http://127.0.0.1:9200/cve_index/_doc/" -IdQuery=".CVE_data_meta.ID" -MdfQuery=".CVE_data_meta.DATE_PUBLIC"
cd $HOME/MyWork/advisory-database/advisories/github-reviewed
git pull
${curPath}/tools/Json2Es -dir="${PWD}" -resUrl="http://127.0.0.1:9200/intelligence_index/_doc/"
