all: build
cmd/goiftop/github.com/amigan/goiftop/cmd/goiftop/iftop.pb.go: cmd/goiftop/iftop.proto
	protoc -I=cmd/goiftop/ --go_out=cmd/goiftop cmd/goiftop/iftop.proto
cmd/goiftop/bindata.go: static/*
	go-bindata -fs -prefix "static/" -pkg main -o cmd/goiftop/bindata.go static/...
build: cmd/goiftop/bindata.go cmd/goiftop/github.com/amigan/goiftop/cmd/goiftop/iftop.pb.go
	go build github.com/amigan/goiftop/cmd/goiftop
clean:
	rm -rf cmd/goiftop/bindata.go goiftop cmd/goiftop/github.com
