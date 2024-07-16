
all:
	go build -o ./bin/flannel ./cmd/flannel
	go build -o ./bin/flannel-cni-plugin ./cmd/flannel-cni-plugin