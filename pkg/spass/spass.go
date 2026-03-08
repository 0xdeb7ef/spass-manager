package spass

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"strconv"
	"strings"
)

// Given bytes that represent the decrypted SPASS file,
// parses the data and populates the SPASS object with the
// corresponding entries for passwords, cards, addresses, and notes,
// based on the module flags present in the file.
func (spass *SPASS) Deserialize(data []byte) error {
	line := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var modules [4]bool

	for scanner.Scan() {
		line++

		if line == 1 {
			version, err := strconv.ParseUint(scanner.Text(), 10, 0)
			if err != nil {
				return errors.New("invalid file version")
			}
			spass.Version = uint(version)
		}

		if line == 2 {
			mods := strings.Split(scanner.Text(), ";")

			for i, m := range mods {
				if m == "true" {
					modules[i] = true
				} else {
					modules[i] = false
				}
			}
		}
	}

	s := strings.Split(string(data), "next_table")

	// Passwords
	if modules[0] {
		passwords_data, err := parseData(s[1])
		if err != nil {
			return err
		}

		for _, p := range passwords_data {
			var pass Password
			if err := parseGeneric(p, &pass); err != nil {
				return err
			}

			spass.Passwords = append(spass.Passwords, pass)
		}
	}

	// Cards
	if modules[1] {
		cards_data, err := parseData(s[2])
		if err != nil {
			return err
		}

		for _, c := range cards_data {
			var card Card
			if err := parseGeneric(c, &card); err != nil {
				return err
			}

			spass.Cards = append(spass.Cards, card)
		}
	}

	// Addresses
	if modules[2] {
		addresses_data, err := parseData(s[3])
		if err != nil {
			return err
		}

		for _, a := range addresses_data {
			var address Address
			if err := parseGeneric(a, &address); err != nil {
				return err
			}

			spass.Addresses = append(spass.Addresses, address)
		}
	}

	// Notes
	if modules[3] {
		notes_data, err := parseData(s[4])
		if err != nil {
			return err
		}

		for _, n := range notes_data {
			var note Note
			if err := parseGeneric(n, &note); err != nil {
				return err
			}

			spass.Notes = append(spass.Notes, note)
		}
	}

	return nil
}

func parseData(data string) ([][]string, error) {
	csv := csv.NewReader(strings.NewReader(data))
	csv.Comma = ';'
	csv.FieldsPerRecord = 0

	// ignore header
	_, err := csv.Read()
	if err != nil {
		return nil, err
	}

	// read the rest of the data
	data_csv, err := csv.ReadAll()
	if err != nil {
		return nil, err
	}

	err = decodeB64(&data_csv)
	if err != nil {
		return nil, err
	}

	return data_csv, nil
}

func decodeB64(csv_b64 *[][]string) error {
	for i, rec := range *csv_b64 {
		for j, r := range rec {
			d, err := base64.StdEncoding.DecodeString(r)
			if err != nil {
				return err
			}

			(*csv_b64)[i][j] = string(d)
		}
	}

	return nil
}
