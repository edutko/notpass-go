all: test phrases

clean:
	rm -rf out

test:
	go test ./...

phrases: out/phrases

out/phrases: cmd/phrases pkg/random
	[ -d out ] || mkdir out
	go build -o out/phrases ./cmd/phrases
