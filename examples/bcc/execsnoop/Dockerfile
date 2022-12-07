FROM golang

RUN git clone https://github.com/navarrothiago/gobpf
WORKDIR gobpf
RUN apt update && apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev
COPY . .
RUN gcc threadtest.c -o threadtest -l pthread
CMD go run examples/bcc/execsnoop/execsnoop.go examples/bcc/execsnoop/output.go | grep -e "sleep 1000" -e PID -e threadtest
