# Console utility: bip39
    go build cmd/cli/bip39.go

## BIP39 mnemonic generation
    bip39 generate

    --words value         Word count
    --words-color value   First and last word color highlighting
                          Allowed colors: default, black, red, green, yellow, blue, magenta, cyan, white,
                          light-gray, light-red, light-green, light-yellow, light-blue, light-magenta, light-cyan, light-white
    --save value          Save to file (yes/no)
                          File name format: <Argon2 Hash>_<Timestamp UnixNano>.bip39
    --save-dir value      Save file to directory


## Check existing BIP39 mnemonic
    bip39 existing

    --words-color value   First and last word color highlighting
                          Allowed colors: default, black, red, green, yellow, blue, magenta, cyan, white,
                          light-gray, light-red, light-green, light-yellow, light-blue, light-magenta, light-cyan, light-white
    --save value          Save to file (yes/no)
                          File name format: <Argon2 Hash>_<Timestamp UnixNano>.bip39
    --save-dir value      Save file to directory

### Fork: https://github.com/tyler-smith/go-bip39