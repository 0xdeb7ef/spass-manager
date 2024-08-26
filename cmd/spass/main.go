package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
)

func errorPrint(err error) {
	fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
}

func main() {
	// Flag setup
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)

	password := decryptCmd.String("password", "", "the password used to encrypt the .spass file [required]")
	file := decryptCmd.String("file", "", "the .spass file to decrypt [required]")

	cmds := []*flag.FlagSet{decryptCmd, encryptCmd}
	cmds_desc := []string{"decrypt .spass files", "encrypt valid .spass files (not implemented)"}

	for _, c := range cmds {
		c.Usage = func() {
			fmt.Fprintf(c.Output(), "Usage of %s %s:\n\n", os.Args[0], c.Name())
			c.PrintDefaults()
		}
	}

	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprintf(w, "Usage of %s:\n\n", os.Args[0])

		for i, c := range cmds {
			fmt.Fprintf(w, "  %s\t%s\n", c.Name(), cmds_desc[i])
		}
	}

	// Usage handling
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "decrypt":
		decryptCmd.Parse(os.Args[2:])

		if *file == "" || *password == "" {
			decryptCmd.Usage()
			os.Exit(1)
		} else {
			processDecrypt(file, password)
		}

	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		encryptCmd.Usage()
		os.Exit(0)

	default:
		flag.Usage()
		fmt.Fprintf(flag.CommandLine.Output(), "\nno such subcommand %s\n", os.Args[1])
		os.Exit(1)
	}
}

func processDecrypt(file, password *string) {
	data_b64, err := os.ReadFile(*file)
	if err != nil {
		errorPrint(err)
		os.Exit(1)
	}

	data, err := Decrypt(data_b64, *password)
	if err != nil {
		errorPrint(err)
		os.Exit(1)
	}

	// Check that the data is valid
	line := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line++
		if line == 3 {
			if scanner.Text() == "next_table" {
				break
			} else {
				errorPrint(errors.New("invalid password/data"))
				os.Exit(1)
			}
		}
	}

	fmt.Print(string(data))
}
