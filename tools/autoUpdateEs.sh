#!/bin/bash

# http://127.0.0.1:9200/_cat/indices
curPath=`pwd`
cd $HOME/MyWork/cvelist
git pull
${curPath}/tools/Json2Es -dir="${PWD}" -resUrl="http://127.0.0.1:9200/cve_index/_doc/"
cd $HOME/MyWork/advisory-database/advisories/github-reviewed
git pull
${curPath}/tools/Json2Es -dir="${PWD}" -resUrl="http://127.0.0.1:9200/intelligence_index/_doc/"

