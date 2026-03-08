package spass

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

type Password struct {
	ID                  uint
	Origin_URL          string
	Action_URL          string
	Username_Element    string
	Username_Value      string
	ID_TZ_Enc           string
	Password_Element    string
	Password_Value      string
	PW_TZ_Enc           string
	Host_URL            string
	SSL_Valid           string
	Preferred           string
	Blacklisted_By_User string
	Use_Additional_Auth string
	CM_API_Support      string
	Created_Time        uint
	Modified_Time       uint
	Title               string
	Favicon             []byte
	Source_Type         string
	App_Name            string
	Package_Name        string
	Package_Signature   string
	Reserved_1          string
	Reserved_2          string
	Reserved_3          string
	Reserved_4          string
	Reserved_5          string
	Reserved_6          string
	Reserved_7          string
	Reserved_8          string
	Credential_Memo     string
	OTP                 string
	Root_ID             string
	Parent_ID           string
}

type Card struct {
	ID                    uint
	Card_Number_Encrypted string
	First_Six_Digit       string
	Last_Four_Digit       string
	Name_On_Card          string
	Expiration_Month      string
	Expiration_Year       string
	Billing_Address_ID    uint
	Vault_Status          string
	Date_Modified         uint
	Reserved_4            string
	Reserved_5            string
	Reserved_6            string
	Is_Encrypted          string
}

type Address struct {
	ID             uint
	Full_Name      string
	Company_Name   string
	Street_Address string
	City           string
	State          string
	Zipcode        string
	Country_Code   string
	Phone_Number   string
	Email          string
	Date_Modified  uint
	Reserved_4     string
	Reserved_5     string
	Reserved_6     string
}

type Note struct {
	ID            uint
	Note_Title    string
	Note_Details  string
	Date_Modified uint
}

// Struct that represents the .spass data.
type SPASS struct {
	Version   uint
	Passwords []Password
	Cards     []Card
	Addresses []Address
	Notes     []Note
}

func parseGeneric(data []string, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("v must be a non-nil pointer")
	}

	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return errors.New("v must point to a struct")
	}

	num_fields := rv.NumField()
	if num_fields != len(data) {
		return fmt.Errorf("data length %d doesn't match struct fields %d", len(data), num_fields)
	}

	for i := range num_fields {
		field := rv.Field(i)
		field_type := field.Type()
		field_name := rv.Type().Field(i).Name
		data_val := data[i]

		switch field_type.Kind() {
		case reflect.String:
			field.SetString(data_val)
		case reflect.Uint:
			num, err := strconv.ParseUint(data_val, 10, 0)
			if err != nil {
				return fmt.Errorf("unable to parse uint in field: %v", field_name)
			}
			field.SetUint(num)
		case reflect.Slice:
			if field.Type() == reflect.TypeOf([]byte{}) {
				field.SetBytes([]byte(data_val))
			} else {
				return fmt.Errorf("unsupported slice type: %v in field: %v", field.Type(), field_name)
			}
		default:
			return fmt.Errorf("unsupported field type: %v in field: %v", field_type, field_name)
		}
	}
	return nil
}
