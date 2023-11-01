all: test phrases pwsafe

clean:
	rm -rf out

test:
	go test -race ./...

phrases: out/phrases
pwsafe: out/pwsafe

out/phrases: cmd/phrases pkg/random
	[ -d out ] || mkdir out
	go build -o out/phrases ./cmd/phrases

out/pwsafe: cmd/pwsafe pkg/vault internal
	[ -d out ] || mkdir out
	go build -o out/pwsafe ./cmd/pwsafe
