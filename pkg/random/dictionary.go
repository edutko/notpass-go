package random

import (
	"bufio"
	"bytes"
	_ "embed"
	"io"
	"strings"
)

//go:embed "dictionary.txt"
var defaultDictionary []byte
var DefaultDictionary []string

func init() {
	DefaultDictionary = LoadDictionary(bytes.NewReader(defaultDictionary))
}

func LoadDictionary(r io.Reader) []string {
	dictionary := make([]string, 0)
	s := bufio.NewScanner(r)
	s.Split(bufio.ScanLines)
	for s.Scan() {
		w := strings.TrimSpace(s.Text())
		if len(w) > 0 && !strings.HasPrefix(w, "#") {
			dictionary = append(dictionary, w)
		}
	}
	return dictionary
}
