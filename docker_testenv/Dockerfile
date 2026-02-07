FROM ubuntu:22.04

RUN apt-get update && apt-get install -y openssh-server sudo && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /var/run/sshd


RUN useradd -m -s /bin/bash "${USERNAME:-testuser}" && \
    echo "${USERNAME:-testuser}:${PASSWORD:-testpass}" | chpasswd


RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

CMD ["/usr/sbin/sshd", "-D"]