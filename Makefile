
all:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ./bin/flannel ./cmd/flannel
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ./bin/flannel-cni-plugin ./cmd/flannel-cni-plugin