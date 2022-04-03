FROM ubuntu:20.04
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get install -y lib32z1 xinetd && useradd -u 8888 -m ctfer
CMD ["/usr/sbin/xinetd", "-dontfork"]

