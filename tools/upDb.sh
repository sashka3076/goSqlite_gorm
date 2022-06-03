xx1=`pwd`
cd $HOME/MyWork/advisory-database
git pull
cd $xx1
./Json2Es -dir="$HOME/MyWork/advisory-database//advisories/github-reviewed/"  -resUrl="http://127.0.0.1:9200/intelligence_index/_doc/"
