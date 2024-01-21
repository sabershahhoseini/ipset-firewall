package checkerr

import (
	"log"
)

func Fatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
