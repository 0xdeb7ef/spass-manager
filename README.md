# SPass Manager
A program (and library) to decrypt .spass files.

## Installation
`go install github.com/0xdeb7ef/spass-manager@latest`

## Building from Source
1. `git clone https://github.com/0xdeb7ef/spass-manager.git`
2. `cd spass-manager`
3. `go build .`

Congratulations, you are now the owner of a brand new `spass-manager` binary!

## Usage
You can simply call `spass-manager` and it will print the usage.

```console
$ spass-manager decrypt -i super_secret_password_file.spass -o passwords.csv -p SuperSecretPassword1! -f chrome
```

The above example decrypts and writes your exported passwords into passwords.csv that Chrome can happily read.
Make sure to escape certain special characters you may have in your password.

## Formats

- `chrome`: The format that is chosen by default when you don't pass the format flag. Contains `name, url, username, password, notes`
- `csv`: Generic csv format, outputs `url, username, password, otp, notes`
- `raw`: Special format that simply decrypts the .spass file and dumps the contents as-is.

## Library Usage

There's not a lot going on with this library, it provides a `SPASS` struct with a single `Deserialize` method.
It also provides a `Decrypt` function.

`go get -u github.com/0xdeb7ef/spass-manager/pkg/spass@latest`


```go
import "github.com/0xdeb7ef/spass-manager/pkg/spass"

...

data, err := spass.Decrypt(file_bytes)
if err != nil {
	// handle error
}

var spass spass.SPASS
err = spass.Deserialize(data)
if err != nil {
	// handle error
}

...

```

(see [cmd/decrypt.go](https://github.com/0xdeb7ef/spass-manager/blob/master/cmd/decrypt.go) for a better example)

## Why?
I was looking for a way to move my passwords to and from Samsung Pass, but could not find anything online. Everywhere I looked, it said that Samsung uses a custom format.

## How?
Simple, really. Just had a look at what the app does internally. Turns out, it was just AES, it's always AES.

## What?
A .spass file is just a custom .csv file with semicolons as delimiters, encrypted with AES.

The first line appears to indicate the file format version.

The second line lists which types of data you have exported (passwords, cards, addresses, notes), as booleans.

The third line, I have no idea, this is a new addition (since version 25 of the format, from what I can tell), it just says `false` for now.

The fourth line should say `next_table` and this specific keyword is used to delimit the different data types (passwords, cards, addresses, notes).

The lines following `next_table` are the actual data. The headers are in plain text, but the data itself is base64 encoded.

## TODO
- [ ] Rewrite `spass_model.go`:
  - [ ] Use struct field tags, perhaps
  - [ ] Redo the types
  - [ ] Rewrite the `parseGeneric` function: 
    - [ ] Handle more types
    - [ ] Ignore missing fields, should future-proof the library

- [ ] Add more output formats (`decrypt.go`)
