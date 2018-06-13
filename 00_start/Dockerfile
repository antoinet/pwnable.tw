FROM ubuntu
COPY start /opt/pwnable/start
RUN chmod +x /opt/pwnable/start && apt update && apt install -y netcat gdb
EXPOSE 10000
CMD netcat -l -p 10000 -e /opt/pwnable/start
