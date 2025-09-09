# fuzz20 image is the docker image for testing stateful fuzzers
# 1. base image
FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

# 2. apt and python environment\
# for apt mirrors use tsinghua 
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
  apt-get -y update && \
  apt-get install -y sudo apt-utils lib32z1 apt-transport-https python3 python3-pip git \
  vim nano netcat unzip make wget build-essential curl gcc gdb clang openssl\
  graphviz-dev autoconf libgnutls28-dev libssl-dev libcap-dev llvm cmake

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip config set global.index-url http://pypi.tuna.tsinghua.edu.cn/simple && \
  python3 -m pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn && \
  python3 -m pip install -U pip

# 3. add a system user ubuntu:ubuntu and generate passwd
RUN groupadd ubuntu && \
  useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

# 4. let the container still
RUN echo "#!/bin/sh\nsleep infinity" > /home/ubuntu/start.sh
RUN chmod +x /home/ubuntu/start.sh

# 5. clone open source targets from git
USER ubuntu
RUN mkdir /home/ubuntu/experiments
WORKDIR /home/ubuntu/experiments

RUN mkdir /home/ubuntu/experiments/targets 
WORKDIR /home/ubuntu/experiments/targets 

RUN git clone https://github.com/hfiref0x/LightFTP.git lightftp && \
  git clone https://github.com/assist-project/tinydtls-fuzz.git tinydtls && \
  git clone https://github.com/rgaufman/live555.git live555 && \
  git clone https://github.com/openssl/openssl.git openssl && \
  cp -r openssl openssl_for_ssh && \
  git clone https://github.com/vegard/openssh-portable.git openssh && \
  mkdir /home/ubuntu/experiments/targets/openssl_for_ssh_install 

# 6. copy fuzzers and tools
RUN mkdir /home/ubuntu/experiments/tools/
COPY --chown=ubuntu:ubuntu stateful_arena/tools /home/ubuntu/experiments/tools/
RUN mkdir /home/ubuntu/experiments/fuzzers
WORKDIR /home/ubuntu/experiments/fuzzers
RUN git clone https://github.com/aflnet/aflnet.git aflnet && \
  git clone https://github.com/stateafl/stateafl.git stateafl && \
  git clone https://github.com/DonggeLiu/AFLNet_Legion.git aflnetlegion
RUN mkdir /home/ubuntu/experiments/fuzzers/nsfuzz
COPY --chown=ubuntu:ubuntu stateful_arena/nsfuzz /home/ubuntu/experiments/fuzzers/nsfuzz

# 7. create fuzz arena
RUN mkdir /home/ubuntu/experiments/fuzz_arena
ENV FUZZ_ARENA=/home/ubuntu/experiments/fuzz_arena

# 8. create stateful pass stuff
RUN mkdir /home/ubuntu/experiments/stateful_pass/
COPY --chown=ubuntu:ubuntu compile_scripts /home/ubuntu/experiments/stateful_pass/compile_scripts
COPY --chown=ubuntu:ubuntu src /home/ubuntu/experiments/stateful_pass/src

# run the container
CMD ["/home/ubuntu/start.sh"]



