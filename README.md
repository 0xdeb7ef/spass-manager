# SPass Manager
A program to decrypt .spass files, and maybe encrypt to .spass in the future.

## Installation
`go install github.com/0xdeb7ef/spass-manager/cmd/spass@latest`

## Building from Source
1. `git clone https://github.com/0xdeb7ef/spass-manager.git`
2. `cd spass-manager`
3. `go build ./cmd/spass`

Congratulations, you are now the owner of a brand new `spass` binary!

## Usage
You can simply call `spass` and it will print the usage.

```console
$ spass decrypt -file super_secret_password_file.spass -password 'SuperSecretPassword' -format chrome > passwords.csv
```

The above example decrypts and writes your exported passwords into passwords.csv that Chrome can happily read.

## Why?
I was looking for a way to move my passwords to and from Samsung Pass, but could not find anything online. Everywhere I looked, it said that Samsung uses a custom format.

What we end up with is a hastily written program that can only decrypt .spass files for now.

## How?
Simple, really. Just had a look at what the app does internally. Turns out, it was just AES, it's always AES.

## What?
A .spass file is just a custom .csv file with semicolons as delimiters, encrypted with AES.

The first line appears to indicate the file format version.

The second line lists which types of data you have exported (passwords, cards, addresses, notes), as booleans.

The third line should say `next_table` and this specific keyword is used to delimit the different data types (passwords, cards, addresses, notes).

The lines following `next_table` is the actual data. The data itself is also base64 encoded, `spass` makes no effort to actually sanitize this output (PRs are welcome, obviously).
