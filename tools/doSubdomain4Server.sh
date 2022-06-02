#!/bin/bash
domain=$1
tmux new -s subdomain -d
tmux send -t "subdomain" "/root/tools/amass_linux enum -silent -o /root/tools/${domain}_amass.txt -d ${domain}" Enter
tmux send -t "subdomain" "/root/tools/subfinder_linux -o /root/tools/${domain}_subfinder.txt -silent -d ${domain}" Enter
tmux send -t "subdomain" "sublist3r -o /root/tools/${domain}_sublist3r.txt -d ${domain}" Enter
tmux send -t "subdomain" "gobuster dns -o /root/tools/${domain}_gobuster.txt -w subdomains.txt -q -t 64 -d ${domain}" Enter