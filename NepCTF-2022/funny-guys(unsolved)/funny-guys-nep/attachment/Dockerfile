FROM ubuntu:20.04
MAINTAINER HRP

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get update && apt-get install -y lib32z1 xinetd build-essential
RUN apt-get update && apt-get install -y patchelf

WORKDIR /root

#copy file
COPY ./flag.sh /root
COPY ./pwn /root
COPY ./flag /root
COPY ./glibc-all-in-one /root/glibc-all-in-one
RUN mkdir /root/X-admin
#COPY  ./www.zip /root/X-admin/
COPY X-admin /root/X-admin


RUN chmod +x /root/*
RUN chown -R root:root /root
RUN chmod -R 777 /root

RUN touch /root/*
RUN touch /root/*/*

RUN patchelf --set-interpreter ./glibc-all-in-one/libs/2.31-0ubuntu9_amd64/ld-2.31.so --set-rpath ./glibc-all-in-one/libs/2.31-0ubuntu9_amd64 pwn


EXPOSE 90
CMD /root/flag.sh
