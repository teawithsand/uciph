export GOPATH=$(realpath ./gopath_dir)
GOPATH=$(realpath ./gopath_dir)
go get github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build

# TODO(teawithand): add support for multiple fuzzers in single shell argument
(cd $1 && $GOPATH/bin/go-fuzz-build)
# (cd $1 && $GOPATH/bin/go-fuzz)


