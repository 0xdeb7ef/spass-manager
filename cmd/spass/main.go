package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
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
	format := decryptCmd.String("format", "", "format to output in, available formats: chrome")

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
		data, err := processDecrypt(file, password, format)
		if err != nil {
			decryptCmd.Usage()
			fmt.Fprintf(decryptCmd.Output(), "\nError: %s\n", err.Error())
			os.Exit(0)
		}
		fmt.Println(string(data))

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

type Format int

const (
	None Format = iota
	Chrome
)

var (
	formatMap = map[string]Format{
		"":       None,
		"chrome": Chrome,
	}
)

func ParseFormat(str string) (Format, bool) {
	c, ok := formatMap[strings.ToLower(str)]
	return c, ok
}

func processDecrypt(file, password, format *string) ([]byte, error) {
	if *file == "" || *password == "" {
		return nil, errors.New("both -file and -password are required")
	}

	// format processor
	f, ok := ParseFormat(*format)
	if !ok {
		return nil, errors.New("invalid format, only supports: chrome")
	}

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

	switch f {
	case Chrome:
		data, err = parseChrome(data)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

func parseChrome(data []byte) ([]byte, error) {
	s := strings.Split(string(data), "next_table")

	r := csv.NewReader(strings.NewReader(s[1]))
	r.Comma = ';'
	r.FieldsPerRecord = 33

	_, err := r.Read()
	if err != nil {
		return nil, err
	}

	header := []string{"url", "username", "password", "name", "note"}

	var final [][]string
	final = append(final, header)

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		var rec []string
		cols_needed := []int{1, 4, 7, 17, 31}
		for i, rr := range record {
			if slices.Contains(cols_needed, i) {

				b, err := base64.StdEncoding.DecodeString(rr)
				if err != nil {
					return nil, err
				}

				rec = append(rec, string(b))
			}
		}

		final = append(final, rec)
	}

	var buff bytes.Buffer

	w := csv.NewWriter(&buff)

	w.WriteAll(final)
	w.Flush()

	return buff.Bytes(), nil
}
