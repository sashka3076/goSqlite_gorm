#!/bin/bash
$HOME/MyWork/TOP/.run.sh
upGit nuclei
upGit nuclei-templates
# upGit advisory-database
upGit cvelist
$HOME/MyWork/goSqlite_gorm/tools/upDb.sh
upGit SecLists
upGit codeql
upAll $HOME/MyWork/bugbounty/
