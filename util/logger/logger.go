package logger

import (
	"fmt"
	"os"

	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
)

func Log(log string, logFilePath string, verbose bool) {
	if verbose {
		fmt.Println(log)
	}
	if logFilePath != "" {
		WriteLogToFile(logFilePath, log)
	}
}

func WriteLogToFile(path string, message string) {
	f, err := os.OpenFile(path,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	checkerr.Fatal(err)

	defer f.Close()
	_, err = f.WriteString(message + "\n")
	checkerr.Fatal(err)
}
