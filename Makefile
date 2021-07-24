all: build
cmd/goiftop/bindata.go: static/*
	go-bindata -fs -prefix "static/" -pkg main -o cmd/goiftop/bindata.go static/...
build: cmd/goiftop/bindata.go
	go build github.com/amigan/goiftop/cmd/goiftop
clean:
	rm -f cmd/goiftop/bindata.go goiftop
