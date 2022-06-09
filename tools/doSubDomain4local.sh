#!/bin/bash
xx1=$(echo $1|sed 's/\..*$//g')

$HOME/MyWork/mybugbounty/tools/01-subDomain/01-Amass enum -df $1 -o ${xx1}.txt

