package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"notpass-go/internal/backend/passwordsafe"
	"notpass-go/internal/cli"
	"notpass-go/internal/io"
	"notpass-go/pkg/vault"
	"notpass-go/pkg/vault/query"
)

func main() {
	vaultFile := flag.String("vault", "", "read vault from this file (required)")
	yubikey := flag.Bool("yubikey", false, "use YubiKey to open safe")
	flag.Parse()

	if *vaultFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	account := ""
	username := ""
	if flag.NArg() > 0 {
		account = flag.Arg(0)
	}
	if flag.NArg() > 1 {
		username = flag.Arg(1)
	}

	p, err := io.ReadPassword("Password: ")
	if err != nil {
		log.Fatal(err)
	}
	password := string(p)

	if *yubikey {
		password, err = passwordsafe.PasswordFromYubikey(string(p))
		if err != nil {
			log.Fatal(err)
		}
	}

	v, err := passwordsafe.OpenVault(*vaultFile, password)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err := v.Close()
		if err != nil {
			log.Printf("error: closing database: %v", err)
		}
	}()

	l := v.Find(query.And(
		query.Or(
			query.Where(vault.GroupField).Contains(account),
			query.Where(vault.NameField).Contains(account),
		),
		query.Where(vault.UsernameField).Contains(username),
	))
	if len(l) == 0 {
		fmt.Printf("No entries matched \"%s\"\n", account)
	} else if len(l) == 1 {
		e, _ := v.Get(l[0].Id())
		fmt.Println(e.Password())
	} else {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Group() == l[j].Group() {
				return l[i].Name() < l[j].Name()
			}
			return l[i].Group() < l[j].Group()
		})
		i, aborted, err := cli.NumberedMenu(l,
			func(i int, e vault.Entry) string {
				return fmt.Sprintf("%d %s/%s\t%s", i, e.Group(), e.Name(), e.Username())
			}, "exit", "exit")
		if err != nil {
			log.Fatalln(err)
		}
		if !aborted {
			e, _ := v.Get(l[i].Id())
			fmt.Println(e.Password().AsString())
		}
	}
}
