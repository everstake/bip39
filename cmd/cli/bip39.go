package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/urfave/cli/v2"
	"go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
	"log"
	"math/rand"
	"os"
	"strings"
	"syscall"
	"time"
)

func wordsToEntropyBits(wordCount int) (int, error) {
	switch wordCount {
	case 12:
		return 128, nil
	//case 15:
	//	return 160, nil
	//case 18:
	//	return 192, nil
	//case 21:
	//	return 224, nil
	case 24:
		return 256, nil
	default:
		return 0, fmt.Errorf("unsupported word count")
	}
}

func wordColor(word string, color string) string {
	colors := map[string]int{
		"black":         40,
		"red":           41,
		"green":         42,
		"yellow":        43,
		"blue":          44,
		"magenta":       45,
		"cyan":          46,
		"white":         47,
		"default":       49,
		"light-gray":    100,
		"light-red":     101,
		"light-green":   102,
		"light-yellow":  103,
		"light-blue":    104,
		"light-magenta": 105,
		"light-cyan":    106,
		"light-white":   107,
	}

	if colors[color] != 0 {
		return fmt.Sprintf("\x1b[%dm", colors[color]) + word + "\x1b[0m"
	} else {
		return word
	}
}

func randomCharset(length int) string {
	rCharset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = rCharset[r.Intn(len(rCharset))]
	}
	return string(b)
}

type hashParams struct {
	hashTime    uint32
	hashMemory  uint32
	hashThreads uint8
	hashKeyLen  uint32
}

func argon2Encode(data string, salt string) (string, string) {
	p := &hashParams{
		hashTime:    1,
		hashMemory:  64 * 1024,
		hashThreads: 4,
		hashKeyLen:  32,
	}

	hash := argon2.IDKey([]byte(data), []byte(salt), p.hashTime, p.hashMemory, p.hashThreads, p.hashKeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString([]byte(salt))
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	argon2output := []string{
		"Argon2 Hash\n---",
		"Type:\t\tArgon2id",
		fmt.Sprintf("Iterations:\t%d", p.hashTime),
		fmt.Sprintf("Memory:\t\t%d KiB", p.hashMemory),
		fmt.Sprintf("Parallelism:\t%d", p.hashThreads),
		fmt.Sprintf("Hash:\t\t%x", hash),
		fmt.Sprintf("Salt:\t\t%s", salt),
		fmt.Sprintf("Encoded:\t$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.hashMemory, p.hashTime, p.hashThreads, b64Salt, b64Hash),
	}

	output := fmt.Sprintf("\n%s\n", strings.Join(argon2output, "\n"))

	return output, hex.EncodeToString(hash)
}

func saveToFile(filePath string, data string) {
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	defer file.Close()

	_, err = file.WriteString(data)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func confirmSaveToFile(filePath string, data string) {
	if _, err := os.Stat(filePath); err == nil {
		fmt.Println("The file already exists. Do you want to overwrite it? (yes/no):")

		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)

		if answer == "yes" {
			saveToFile(filePath, data)
		} else {
			fmt.Print("File will not be overwritten.\n\n")
		}
	} else if os.IsNotExist(err) {
		saveToFile(filePath, data)
	} else {
		fmt.Println("Error during file check:", err)
	}
}

func outputMnemonic(mnemonic string, salt string, seed []byte, colorWord string, save string) string {
	var outColorBuffer bytes.Buffer

	mnemonicList := strings.Split(mnemonic, " ")
	mnemonicLastIndex := len(mnemonicList) - 1
	encodedHash, hash := argon2Encode(mnemonic, salt)
	colors := strings.Split(colorWord, ",")

	firstWordColor, lastWordColor := "default", "default"
	if len(colors) == 2 {
		firstWordColor, lastWordColor = colors[0], colors[1]
	}

	outMnemonic := fmt.Sprintf("Mnemonic:\n%s\n", strings.Join(mnemonicList, " "))
	outColorBuffer.WriteString(fmt.Sprintf("Mnemonic:\n%s ", wordColor(mnemonicList[0], firstWordColor)))
	for i := 1; i < mnemonicLastIndex; i++ {
		outColorBuffer.WriteString(fmt.Sprintf("%s ", mnemonicList[i]))
	}
	outColorBuffer.WriteString(fmt.Sprintf("%s\n", wordColor(mnemonicList[mnemonicLastIndex], lastWordColor)))
	outSeed := fmt.Sprintf("Seed:\n%s\n", hex.EncodeToString(seed))

	output := fmt.Sprintf("%s%s", outSeed, encodedHash)

	if save == "yes" {
		fmt.Print("File saved: " + hash + ".bip39\n\n")
		confirmSaveToFile(hash+".pib39", outMnemonic+output)
	}

	if save == "no" {
		fmt.Print("File not saved. Only output.\n\n")
	}

	return outColorBuffer.String() + output
}

func generateMnemonic(bitSize int, colorWord string, save string) {
	salt := randomCharset(24)
	entropy, _ := bip39.NewEntropy(bitSize)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, salt)
	output := outputMnemonic(mnemonic, salt, seed, colorWord, save)

	fmt.Print(output)
}

func clearInput(input string) {
	cursorPosition := len(input)
	fmt.Print("\r")
	for i := 0; i < cursorPosition; i++ {
		fmt.Print(" ")
	}
	fmt.Print("\r")
}

func existingMnemonic(colorWord string, save string) {
	fmt.Print("Enter Mnemonic: ")
	mnemonic, err := term.ReadPassword(syscall.Stdin)
	trimMnemonic := strings.TrimSpace(string(mnemonic))
	if len(trimMnemonic) == 0 {
		err = fmt.Errorf("mnemonic can't be empty %v", string(mnemonic))
	}
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if bip39.IsMnemonicValid(trimMnemonic) == false {
		fmt.Println("mnemonic is not valid")
		os.Exit(1)
	}
	clearInput(string(mnemonic))

	fmt.Print("Enter Salt: ")
	salt, err := term.ReadPassword(syscall.Stdin)
	trimSalt := strings.TrimSpace(string(salt))
	if len(trimSalt) == 0 {
		err = fmt.Errorf("salt can't be empty %v", salt)
	}
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	clearInput(string(salt))

	seed := bip39.NewSeed(trimMnemonic, trimSalt)
	output := outputMnemonic(trimMnemonic, trimSalt, seed, colorWord, save)

	fmt.Print(output)
}

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "generate",
				Aliases: []string{"g"},
				Usage:   "BIP39 generator",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "words", Aliases: []string{"w"}, Value: 24},
					&cli.StringFlag{
						Name:    "words-color",
						Aliases: []string{"c"},
						Value:   "green,blue",
						Usage: "First and last word color highlighting\n" +
							"Allowed colors: default, black, red, green, yellow, blue, magenta, cyan, white," +
							"light-gray, light-red,\nlight-green, light-yellow, light-blue, light-magenta," +
							"light-cyan, light-white",
					},
					&cli.StringFlag{
						Name:    "save",
						Aliases: []string{"s"},
						Value:   "yes",
						Usage:   "Save to file (yes/no): <Argon2 Hash>.bip39",
					},
				},
				Action: func(cCtx *cli.Context) error {
					words, err := wordsToEntropyBits(cCtx.Int("words"))
					if err != nil {
						fmt.Println("Error:", err)
					} else {
						generateMnemonic(words, cCtx.String("words-color"), cCtx.String("save"))
					}
					return nil
				},
			},
			{
				Name:    "existing-mnemonic",
				Aliases: []string{"e"},
				Usage:   "Check existing BIP39 mnemonic",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "words-color",
						Aliases: []string{"c"},
						Value:   "green,blue",
						Usage: "First and last word color highlighting\n" +
							"Allowed colors: default, black, red, green, yellow, blue, magenta, cyan, white," +
							"light-gray, light-red,\nlight-green, light-yellow, light-blue, light-magenta," +
							"light-cyan, light-white",
					},
					&cli.StringFlag{
						Name:    "save",
						Aliases: []string{"s"},
						Value:   "no",
						Usage:   "Save to file (yes/no): <Argon2 Hash>.bip39",
					},
				},
				Action: func(cCtx *cli.Context) error {
					existingMnemonic(cCtx.String("words-color"), cCtx.String("save"))
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
