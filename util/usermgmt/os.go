package usermgmt

import (
	"fmt"
	"log"
	"os"
	"os/user"
)

func ExitIfNotRoot() {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Unable to get current user: %s", err)
	}
	if currentUser.Username != "root" {
		fmt.Println("You must be root!")
		os.Exit(1)
	}
}
