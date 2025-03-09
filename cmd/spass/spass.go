package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ITERATION_COUNT = 70000
	KEY_LENGTH      = 256 / 8
	SALT_BYTES      = 20
)

// type Format int

// const (
// 	None Format = iota
// 	Chrome
// )

func processDecrypt(file, password, format *string) ([]byte, error) {
	data_b64, err := os.ReadFile(*file)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	data, err := Decrypt(data_b64, *password)
	if err != nil {
		fmt.Println(err.Error())
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
				fmt.Println("invalid password/data")
				os.Exit(1)
			}
		}
	}

	if *format == "chrome" {
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

func Decrypt(data_b64 []byte, password string) ([]byte, error) {
	// Decode base64 encoded data
	data, err := base64.StdEncoding.DecodeString(string(data_b64))
	if err != nil {
		return nil, err
	}

	// Extract salt bytes
	salt := data[:SALT_BYTES]

	// Extract IV
	block_size := aes.BlockSize
	iv := data[SALT_BYTES : SALT_BYTES+block_size]

	// Extract encrypted data
	data_enc := data[SALT_BYTES+block_size:]

	// Generate key using PBKDF2 with HMAC SHA256
	key := pbkdf2.Key([]byte(password), salt, ITERATION_COUNT, KEY_LENGTH, sha256.New)

	// Decrypt data using AES CBC mode
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	data_dec := make([]byte, len(data_enc))
	mode.CryptBlocks(data_dec, data_enc)

	// Remove padding (PKCS5)
	data_dec = removePKCS5Padding(data_dec)

	return data_dec, nil
}

// removePKCS5Padding removes padding from decrypted data
func removePKCS5Padding(data []byte) []byte {
	paddingLen := int(data[len(data)-1])
	return data[:len(data)-paddingLen]
}

// Implement the Encrypt() function
// Encrypt csv password file to spass password file

// Add padding to input plaintext data before encryption (as I understand it...)
func addPKSCS5Paddint(data []byte, block_size int) []byte {
	paddingLen := block_size - (len(data) % block_size)
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	// append padding to data to make integral of blockSize and return plaintext data
	return append(data, padding...)
}

func Encrypt(data []byte, password string) ([]byte, error) {

	block_size := aes.BlockSize

	text_to_enc := addPKSCS5Paddint(data, block_size)
	if len(text_to_enc)%block_size != 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	salt := text_to_enc[:SALT_BYTES]
	iv := text_to_enc[SALT_BYTES : SALT_BYTES+block_size]

	enc_key := pbkdf2.Key([]byte(password), salt, ITERATION_COUNT, KEY_LENGTH, sha256.New)

	block, err := aes.NewCipher(enc_key)
	if err != nil {
		return nil, err
	}

	cipher_text := make([]byte, len(text_to_enc))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipher_text, text_to_enc)

	return cipher_text, nil
}

func processEncrypt(file, password *string) ([]byte, error) {

	// parsing plaintext data
	file_to_enc, err := os.ReadFile(*file)
	if err != nil {
		return nil, err

	}
	reader := csv.NewReader(strings.NewReader(string(file_to_enc)))
	reader.Comma = ','

	// Read first line - assuming 1st line will always be a csv header
	// test valid file with 2nd column header containering valid string
	tst, err := reader.Read()
	if err != nil {
		return nil, err
	}

	header := []string{"_id", "origin_url", "action_url", "username_element", "username_value", "id_tz_enc", "password_element",
		"password_value", "pw_tz_enc", "host_url", "ssl_valid", "preferred", "blacklisted_by_user", "use_additional_auth", "cm_api_support",
		"created_time", "modified_time", "title", "favicon", "source_type", "app_name", "package_name", "package_signature", "reserved_1",
		"reserved_2", "reserved_3", "reserved_4", "reserved_5", "reserved_6", "reserved_7", "reserved_8", "credential_memo", "otp"}

	fall_back_header := []string{"url", "username", "password", "name"}
	cols_needed := []int{1, 4, 7, 17, 31}

	//typdef a tuple for data handling
	type index_tuple struct {
		ind_1 int
		ind_2 int
	}
	var index_matcher []index_tuple

	if regexp.MustCompile("[a-z]+").MatchString(tst[1]) {
		//valid file
	} else {
		return nil, fmt.Errorf("invalid file")
	}

	for i, chk := range tst {
		for k, head := range header {
			//match spass header to psswd file header
			if chk == head {
				index_matcher = append(index_matcher, index_tuple{ind_1: i, ind_2: k})
			} else if strings.Contains(head, chk) {
				//TODO: non-lazy check, if multiple substring match... check longer match?
				for j := 0; j < len(index_matcher); j++ {
					if index_matcher[j].ind_2 == k {
						//TODO: optimize check for multiple matches
					} else {
						//if psswd file header substring of spass header - set likely columns with "_value" or "origin_"
						switch k {
						case 0:
							index_matcher = append(index_matcher, index_tuple{ind_1: i, ind_2: 0})
						case 1, 2:
							index_matcher = append(index_matcher, index_tuple{ind_1: i, ind_2: 1})
						case 3, 4:
							index_matcher = append(index_matcher, index_tuple{ind_1: i, ind_2: 4})
						case 6, 7:
							index_matcher = append(index_matcher, index_tuple{ind_1: i, ind_2: 7})
						default:
							//best effort to match other columns
							index_matcher = append(index_matcher, index_tuple{ind_1: i, ind_2: k})
						}
					}
				}
			} else {
				continue
			}
		}
	}
	// ensure required columns are in idex_matcher
	for i := range cols_needed {
		if slices.Contains(cols_needed, index_matcher[i].ind_2) {
			continue
		} else {
			string_needed := fall_back_header[i]
			ind1 := slices.Index(tst, string_needed)
			if ind1 == -1 {
				return nil, fmt.Errorf("Unable to read 'url', 'username', 'password', or 'name' from password .csv file")
			}
			index_matcher = append(index_matcher, index_tuple{ind_1: ind1, ind_2: cols_needed[i]})
		}
	}

	// create spass file to encrypt
	var buff bytes.Buffer
	w := csv.NewWriter(&buff)
	w.Comma = ';'

	var final [][]string
	count_id := 0

	w.Write([]string{"true;true;true;true"})
	w.Write([]string{"next_table"})
	w.Write(header)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		count_id = +1

		var rec []string
		rec = append(rec, strconv.Itoa(count_id))
		for i := range header {
			for r := range index_matcher {
				if index_matcher[r].ind_2 == i {
					data := record[index_matcher[r].ind_1]
					rec = append(rec, base64.StdEncoding.EncodeToString([]byte(data)))
				} else {
					data := ""
					rec = append(rec, base64.StdEncoding.EncodeToString([]byte(data)))
				}
			}
		}
		final = append(final, rec)
	}

	w.WriteAll(final)
	w.Flush()
	err = w.Error()
	if err != nil {
		return nil, err
	}

	return Encrypt(buff.Bytes(), *password)

}
