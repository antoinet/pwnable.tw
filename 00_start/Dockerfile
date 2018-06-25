FROM ubuntu
COPY start /opt/pwnable/start
RUN chmod +x /opt/pwnable/start && apt update && apt install -y netcat gdb
EXPOSE 10000
CMD while true; do netcat -l -k -p 10000 -e /opt/pwnable/start; done
