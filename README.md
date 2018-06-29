## Docker environment

### Build
```
$ docker build -t pwnable:latest .
```

### Debugging within Docker
```
$ docker run --rm -it --name pwnable --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwnable bash
```
