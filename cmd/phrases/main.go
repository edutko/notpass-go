package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"notpass-go/pkg/random"
)

func main() {
	words := flag.Int("words", 3, "number of words")
	digits := flag.Int("digits", 5, "length of suffix")
	howMany := flag.Int("count", 20, "number of passwords to generate")
	base := flag.Int("base", 16, "type of suffix: hexadecimal (base 16) or decimal (base 10)")
	separator := flag.String("separator", "-", "separator string")
	dictionaryFile := flag.String("dictionary", "", "dictionary file")
	verbose := flag.Bool("verbose", false, "print additional information")

	flag.Parse()

	if *base != 16 && *base != 10 {
		fmt.Println("invalid base: expected 10 or 16")
		os.Exit(1)
	}

	if *digits < 0 || *base == 10 && *digits > 19 {
		fmt.Println("invalid number of digits: expected 0 or more (max 19 for base 10)")
		os.Exit(1)
	}

	var dictionary []string
	if *dictionaryFile == "" {
		dictionary = random.DefaultDictionary
	} else {
		f, err := os.Open(*dictionaryFile)
		if err != nil {
			panic(err)
		}
		defer func() {
			err := f.Close()
			if err != nil {
				log.Printf("error: closing file: %v", err)
			}
		}()
		dictionary = random.LoadDictionary(f)
	}

	for i := 0; i < *howMany; i++ {
		p, err := random.Passphrase(dictionary, *words, *digits, *base, *separator)
		if err != nil {
			log.Fatalf("failed to generate passphrase: %v", err)
		}
		if *verbose {
			fmt.Printf("%s\t(%d characters, %0.1f bits of entropy)\n", p.Value, len(p.Value), p.Entropy)
		} else {
			fmt.Printf("%s\n", p.Value)
		}
	}
}
