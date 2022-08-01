FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN sed -i "s/http:\/\/security.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN apt-get update 
RUN apt-get install -y xinetd qemu-system

RUN useradd -m ctf
RUN mkdir -p /home/ctf
RUN mkdir -p /home/ctf/usr/share
RUN mkdir -p /home/ctf/usr/lib/ipxe
RUN cp -r /usr/share/seabios /home/ctf/usr/share
RUN cp -r /usr/share/qemu /home/ctf/usr/share
RUN cp -r /usr/lib/ipxe /home/ctf/usr/lib

COPY ./rootfs.img /home/ctf/rootfs.img
COPY ./start.sh /home/ctf/start.sh
COPY ./vmlinux /home/ctf/vmlinux

RUN chmod 755 /home/ctf/rootfs.img
RUN chmod 755 /home/ctf/start.sh
RUN chmod 755 /home/ctf/vmlinux

COPY ./ctf.xinetd /etc/xinetd.d/ctf

RUN chown root:ctf /home/ctf/start.sh && chmod 750 /home/ctf/start.sh
RUN echo 'ctf - nproc 1500' >>/etc/security/limits.conf

RUN mkdir -p /home/ctf/lib/x86_64-linux-gnu
RUN mkdir -p /home/ctf/lib64
RUN cp -R /lib/x86_64-linux-gnu /home/ctf/lib/
RUN cp -R /usr/lib64 /home/ctf/

RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin && \
    cp /usr/bin/timeout /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin
RUN cp /bin/qemu-system-x86_64 /home/ctf/bin/

RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf 
RUN chmod 777 /home/ctf/dev/null

CMD exec /bin/bash -c "/etc/init.d/xinetd start ; trap : TERM INT; sleep infinity & wait"
EXPOSE 8888
#/etc/init.d/xinetd start
