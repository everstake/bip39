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

  --words value         Word count
  --words-color value   First and last word color highlighting
                        Allowed colors: default, black, red, green, yellow, blue, magenta, cyan, white,
                        light-gray, light-red, light-green, light-yellow, light-blue, light-magenta, light-cyan, light-white
  --save value          Save to file (yes/no)
                        File name format: <Argon2 Hash>_<Timestamp UnixNano>.bip39
  --save-dir value      Save file to directory

# Example of library usage: go-bip39

Fork: https://github.com/tyler-smith/go-bip39

```go
package main

import (
  "fmt"
  "go-bip39"
)

func main(){
  // Generate a mnemonic for memorization or user-friendly seeds
  entropy, _ := bip39.NewEntropy(256)
  mnemonic, _ := bip39.NewMnemonic(entropy)

  // Generate a Bip32 HD wallet for the mnemonic and a user supplied password
  seed := bip39.NewSeed(mnemonic, "Secret Passphrase")

  // Display mnemonic and keys
  fmt.Println("Mnemonic: ", mnemonic)
  fmt.Println("Seed: ", seed)
}
```
