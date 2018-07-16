FROM ubuntu
COPY 00_start/start /opt/pwnable/start
COPY 01_orw/orw /opt/pwnable/orw

RUN apt update \
  && apt install -y \
     binutils \
     bsdmainutils \
     gdb \
     git \
     libc6-i386 \
     netcat \
     python \
     python-pip \
     vim \
  && git clone https://github.com/longld/peda.git ~/peda \
  && echo "source ~/peda/peda.py" >> ~/.gdbinit \
  && pip install pwntools \
  && chmod +x /opt/pwnable/start \
  && chmod +x /opt/pwnable/orw

CMD bash
