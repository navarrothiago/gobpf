docker-build:
	docker build . -t execsnoop
docker-run:
	docker run -v /lib/modules/:/lib/modules/ -v /sys/kernel/debug:/sys/kernel/debug --privileged -it execsnoop
