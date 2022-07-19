Hack LLVM!

Docker Guidance:

FROM ubuntu:18.04
  
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd libseccomp-dev libseccomp2 seccomp clang-8 opt llvm-8 python

once your exp.bc(bitcode file) is uploaded

Sever will execute `opt-8 -load ./VMPass.so -VMPass ./exp.bc`

