# hacker service tools，Penetration, Attack, Auxiliary Tool
<img width=950 src=https://user-images.githubusercontent.com/18223385/168472883-4bfb402c-8c90-46c0-a8db-a5b22b8b6a25.gif>

# Tools
## json to Es
```bash
cat tools/autoUpdateEs.sh
```
```bash
# http://127.0.0.1:9200/_cat/indices
curPath=`pwd`
cd $HOME/MyWork/cvelist
git pull
tools/Json2Es -dir="${PWD}" -resUrl="http://127.0.0.1:9200/cve_index/_doc/"
cd $HOME/MyWork/advisory-database/advisories/github-reviewed
git pull
tools/Json2Es -dir="${PWD}" -resUrl="http://127.0.0.1:9200/intelligence_index/_doc/"
```
## mac os
- getCurNetConn.sh 获取当前系统网络链接（pid ip cmd&args）
./tools/getCurNetConn.sh f
<img width="1264" alt="image" src="https://user-images.githubusercontent.com/18223385/168608677-dc4a88aa-25fb-4710-8f1b-4f031f69ee0c.png">

- whereami
echo $PPSSWWDD | sudo -S ./tools/whereami
<img width="488" alt="image" src="https://user-images.githubusercontent.com/18223385/168608623-e4e58ab3-cdca-4983-97e6-7bba58410e83.png">

# How build, use
```bash
go install -v github.com/OWASP/Amass/v3/...@master

mkdir ~/MyWork/
git clone https://github.com/hktalent/goSqlite_gorm.git ~/MyWork/
cd ~/MyWork/goSqlite_gorm
go install  github.com/swaggo/swag/cmd/swag@latest
swag init .

MyPwd=`pwd`

go get
go build main.go

git clone https://github.com/hktalent/hackerToolsApp.git ~/MyWork/
cd ~/MyWork/hackerToolsApp/app
yarn install
yarn build
mv dist $MyPwd/

git clone https://github.com/hktalent/Hack-Tools.git ~/MyWork/
cd ~/MyWork/Hack-Tools
yarn install
yarn build
mv dist $MyPwd/hktdist

docker run -d hktalent/webssh2
./main
open http://127.0.0.1:8081/
```
more see file: build.sh

<!--
./tools/ssh-username-enum.py -t 10 -w ~/MyWork/metasploit-framework/data/wordlists/unix_users.txt 

-->

