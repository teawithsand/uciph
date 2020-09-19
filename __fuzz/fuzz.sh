export GOPATH=$(realpath ./gopath_dir)
GOPATH=$(realpath ./gopath_dir)
export GO111MODULE=on

go get github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build


(cd $1 && $GOPATH/bin/go-fuzz-build)
(cd $1 && $GOPATH/bin/go-fuzz)


