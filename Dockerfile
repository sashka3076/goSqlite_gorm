FROM ubuntu:latest

RUN apt update -yy && apt upgrade -yy && apt install -yy nmap masscan

