# Console utility: bip39
    go build cmd/cli/bip39.go

## Generation of Seed and Argon2 Hash using random mnemonics and salt
    bip39 g
    [OR]
    bip39 g -w 24
    [OR]
    bip39 g -w 24 -c gren,blue
    [OR]
    bip39 g -w 24 -c gren,blue -s yes

## Seed and Argon2 Hash generation using existing mnemonics and salt
    bip39 e
    [OR]
    bip39 e -c gren,blue
    [OR]
    bip39 e -c gren,blue -s yes

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
