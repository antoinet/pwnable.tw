## Docker environment

### Build
```
$ docker build -t pwnable:latest .
```

### Debugging within Docker
```
$ docker run --rm -it --name pwnable --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwnable bash
```

### Running the binary on the network
```
$ while true; do
    nc -l -p 10000 -e <binary>;
  done
```
