package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var password string
var file string
var format string

func init() {
	decryptCmd.Flags().StringVarP(&file, "file", "f", "", "the .spass file to decrypt [required]")
	decryptCmd.Flags().StringVarP(&password, "password", "p", "", "the password to decrypt the .spass file [required]")
	decryptCmd.Flags().StringVarP(&format, "format", "t", "", "the format of the .spass file. available formats: \"chrome\" [required]")
	decryptCmd.MarkFlagRequired("file")
	decryptCmd.MarkFlagRequired("password")
	decryptCmd.MarkFlagRequired("format")

	encryptCmd.Flags().StringVarP(&file, "file", "f", "", "the .spass file to encrypt [required]")
	encryptCmd.Flags().StringVarP(&password, "password", "p", "", "the password to encrypt the .spass file [required]")
	encryptCmd.MarkFlagRequired("file")
	encryptCmd.MarkFlagRequired("password")

	rootCmd.AddCommand(encryptCmd, decryptCmd)
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt [-f file] [-p password]",
	Short: "Encrypt .csv password-file to .spass encrypted password-file",
	Long: `Options:
			-f, -file string       the .spass file to encrypt [required]
			-p, -password string   the password to encrypt the .spass file [required]	
	`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// fmt.Println("encrypt succesfful spass is a password manager")
		data, err := processEncrypt(&file, &password)
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		if slices.Contains(os.Args, ">") {
			fmt.Println(string(data))
		} else {
			err = os.WriteFile(file+".spass", data, 0644)
			if err != nil {
				return fmt.Errorf(err.Error())
			}
			fmt.Printf("Successfully created .spass file: %s.spass", file)
		}
		return nil
	},
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt [-f file] [-p password] [-t format]",
	Short: "Decrypt .spass encrypted password-file to .csv password-file",
	Long: `Options
	-f, -file string       the .spass file to decrypt [required]
	-p, -password string   the password to decrypt the .spass file [required]
	-t, -format string   the format of the .spass file. available formats: chrome [required]
	`,
	Example: `
	# Decrypt .spass file
	spass decrypt -file super_secret_password_file.spass -password 'SuperSecretPassword' -format chrome > passwords.csv
	`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.ToLower(format) != "chrome" {
			return fmt.Errorf("invalid format, only supports: chrome")
		}
		// fmt.Println("descrypt succesfful spass is a password manager")
		data, err := processDecrypt(&file, &password, &format)
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		fmt.Println(string(data))
		return nil
	},
}

var rootCmd = &cobra.Command{
	Use:   "spass",
	Short: "decrypt from and encrypt to a .spass password file",
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
