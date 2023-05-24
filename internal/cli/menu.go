package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func NumberedMenu[T any](choices []T, format func(int, T) string, defaultChoice, abort string) (int, bool, error) {
	for i, e := range choices {
		fmt.Println(format(i+1, e))
	}
	fmt.Println()
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Selection [%s]: ", defaultChoice)
		resp, err := r.ReadString('\n')
		if err != nil {
			return 0, false, err
		}
		resp = strings.TrimSpace(resp)

		if resp == "" {
			resp = defaultChoice
		}

		if resp == abort {
			return 0, true, nil
		}

		i, err := strconv.Atoi(resp)
		if err == nil && i > 0 && i <= len(choices) {
			return i - 1, false, nil
		}
	}
}
