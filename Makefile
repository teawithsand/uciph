ci:
	go build $(DIRS)
	go test $(DIRS)
	

DIRS = . ./sig ./cutil ./rand ./pad ./enc ./cbench ./kx
FUZZERS = fuzz_stream_decrypt

TEST_TIMEOUT=5m
TEST_PARALELLISM=4
BENCH_TIMEOUT=48h
BENCH_PARALELLISM=1

build:
	go build $(DIRS)

test:
	go test $(DIRS) -timeout $(TEST_TIMEOUT) -parallel $(TEST_PARALELLISM)

bench:
	go test $(DIRS) -timeout $(BENCH_TIMEOUT) -bench=. -parallel $(BENCH_PARALELLISM)

bench_alloc:
	go test $(DIRS) -timeout $(BENCH_TIMEOUT) -bench=. -parallel $(BENCH_PARALELLISM) -benchmem
	
vet: 
	go vet $(DIRS)

fmt:
	go fmt $(DIRS)
