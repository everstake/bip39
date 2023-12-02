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
	"math/rand"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

var (
	t = time.Now().UnixNano()
	r = rand.New(rand.NewSource(t))
)

type hashParams struct {
	hashTime    uint32
	hashMemory  uint32
	hashThreads uint8
	hashKeyLen  uint32
}

func clearInput(input string) {
	cursorPosition := len(input)
	fmt.Print("\r")
	for i := 0; i < cursorPosition; i++ {
		fmt.Print(" ")
	}
	fmt.Print("\r")
}

func randomCharset(length int) string {
	rCharset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = rCharset[r.Intn(len(rCharset))]
	}
	return string(b)
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

	code, exists := colors[color]
	if exists {
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", code, word)
	}

	return word
}

func wordsToEntropyBits(wordCount int) (int, error) {
	wordToBits := map[int]int{
		12: 128,
		24: 256,
	}

	bits, ok := wordToBits[wordCount]
	if !ok {
		return 0, fmt.Errorf("unsupported word count")
	}
	return bits, nil
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

func saveToFile(filePath string, data string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("cannot create file: %w", err)
	}

	defer file.Close()

	_, err = file.WriteString(data)
	if err != nil {
		return fmt.Errorf("cannot write to file: %w", err)
	}

	err = file.Chmod(0400)
	if err != nil {
		return fmt.Errorf("cannot set permission to file: %w", err)
	}

	return nil
}

func confirmSaveToFile(filePath string, data string) {
	if _, err := os.Stat(filePath); err == nil {
		fmt.Printf("The file already exists: %s\n", filePath)
		defaultAnswer := "no"
		for {
			fmt.Printf("Do you want to overwrite it? (yes/no): [%s]\n", defaultAnswer)

			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(answer)

			if answer == "" {
				answer = defaultAnswer
			}

			if answer == "yes" || answer == "no" {
				if answer == "yes" {
					if err := saveToFile(filePath, data); err == nil {
						fmt.Printf("File saved: %s\n\n", filePath)
					} else {
						fmt.Printf("Error while saving the file: %s\n\n", err)
					}
				}
				if answer == "no" {
					fmt.Print("File will not be overwritten.\n\n")
				}
				break
			} else {
				fmt.Println("Invalid value. Please enter 'yes' or 'no'.")
			}
		}
	} else if os.IsNotExist(err) {
		if err := saveToFile(filePath, data); err == nil {
			fmt.Printf("File saved: %s\n\n", filePath)
		} else {
			fmt.Printf("Error while saving the file: %s\n\n", err)
		}
	} else {
		fmt.Printf("Error during file check: %s\n\n", err)
	}
}

func outputInfo(mnemonic string, salt string, colorWord string, save string, savePath string) string {
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

	if save == "yes" {
		confirmSaveToFile(fmt.Sprintf("%s/%s_%d.%s", path.Join(savePath), hash, t, "bip39"), outMnemonic+encodedHash)
	}

	if save == "no" {
		fmt.Print("File not saved. Only output.\n\n")
	}

	return outColorBuffer.String() + encodedHash
}

func generateMnemonic(bitSize int, colorWord string, save string, savePath string) string {
	salt := randomCharset(24)
	entropy, _ := bip39.NewEntropy(bitSize)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	output := outputInfo(mnemonic, salt, colorWord, save, savePath)
	return output
}

func existingMnemonic(colorWord string, save string, savePath string) string {
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

	output := outputInfo(trimMnemonic, trimSalt, colorWord, save, savePath)

	return output
}

func main() {
	colorUsage := "First and last word color highlighting\n" +
		"\tAllowed colors: default, black, red, green, yellow, blue, magenta, cyan, white,\n" +
		"\tlight-gray, light-red, light-green, light-yellow, light-blue, light-magenta, light-cyan, light-white"

	mainUsage := "--words-color value\t" + colorUsage + "\n" +
		"--save value\tSave to file (yes/no)\n\tFile name format: <Argon2 Hash>_<Timestamp UnixNano>.bip39\n" +
		"--save-dir value\tSave file to directory"

	app := &cli.App{
		Usage: "Generation, verification of mnemonics and obtaining their hash in Argon2 format",
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate mnemonic\n--words value\tWord count\n" + mainUsage,
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "words", Value: 24},
					&cli.StringFlag{
						Name:  "words-color",
						Value: "green,blue",
					},
					&cli.StringFlag{
						Name:  "save",
						Value: "yes",
					},
					&cli.StringFlag{
						Name:  "save-dir",
						Value: ".",
					},
				},
				Action: func(cCtx *cli.Context) error {
					words, _ := wordsToEntropyBits(cCtx.Int("words"))
					wordsColorFlag := strings.TrimSpace(cCtx.String("words-color"))
					saveFlag := strings.TrimSpace(cCtx.String("save"))
					saveDirFlag := strings.TrimSpace(cCtx.String("save-dir"))
					if saveFlag == "yes" || saveFlag == "no" {
						fmt.Print(generateMnemonic(words, wordsColorFlag, saveFlag, saveDirFlag))
					} else {
						return cli.Exit("Invalid value. Please enter 'yes' or 'no'.", 1)
					}
					return nil
				},
			},
			{
				Name:  "existing",
				Usage: "Check existing BIP39 mnemonic\n" + mainUsage,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "words-color",
						Value: "green,blue",
					},
					&cli.StringFlag{
						Name:  "save",
						Value: "no",
					},
					&cli.StringFlag{
						Name:  "save-dir",
						Value: ".",
					},
				},
				Action: func(cCtx *cli.Context) error {
					wordsColorFlag := strings.TrimSpace(cCtx.String("words-color"))
					saveFlag := strings.TrimSpace(cCtx.String("save"))
					saveDirFlag := strings.TrimSpace(cCtx.String("save-dir"))
					if saveFlag == "yes" || saveFlag == "no" {
						fmt.Print(existingMnemonic(wordsColorFlag, saveFlag, saveDirFlag))
					} else {
						return cli.Exit("Invalid value. Please enter 'yes' or 'no'.", 1)
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
