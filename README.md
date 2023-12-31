[![golangci-lint](https://github.com/everstake/bip39/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/everstake/bip39/actions/workflows/golangci-lint.yaml)    [![CodeQL](https://github.com/everstake/bip39/actions/workflows/codeql.yml/badge.svg)](https://github.com/everstake/bip39/actions/workflows/codeql.yml)    [![Run Gosec](https://github.com/everstake/bip39/actions/workflows/gosec.yml/badge.svg)](https://github.com/everstake/bip39/actions/workflows/gosec.yml)    [![Go Build](https://github.com/everstake/bip39/actions/workflows/go.yml/badge.svg)](https://github.com/everstake/bip39/actions/workflows/go.yml)    [![goreleaser](https://github.com/everstake/bip39/actions/workflows/goreleaser.yml/badge.svg)](https://github.com/everstake/bip39/actions/workflows/goreleaser.yml)

# Generation, verification of mnemonics in BIP39 standard and obtaining their hash in Argon2id format

### Fork: https://github.com/tyler-smith/go-bip39

## Build
    go build cmd/cli/bip39.go

## Install
    sudo install -t /usr/local/bin bip39

## BIP39 mnemonic generation
    bip39 generate

    --words value   Word count (default: 24)
    --color value   First and last word color highlighting (default: green,blue)
                    Allowed colors: black, red, green, yellow, blue, magenta, cyan, white
    --save value    Save to file [yes/no] (default: yes)
                    File name format: <Argon2idHash>_<TimestampUnixNano>.bip39
    --dir value     Save file to directory (default: ~/bip39/mnemonics)


## Check existing BIP39 mnemonic
    bip39 existing

    --color value   First and last word color highlighting (default: green,blue)
                    Allowed colors: black, red, green, yellow, blue, magenta, cyan, white
    --save value    Save to file [yes/no] (default: no)
                    File name format: <Argon2idHash>_<TimestampUnixNano>.bip39
    --dir value     Save file to directory (default: ~/bip39/mnemonics)
