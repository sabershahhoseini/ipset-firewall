package logger

import "fmt"

func Log(log string, verbose bool) {
	if verbose {
		fmt.Println(log)
	}
}
