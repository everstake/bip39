package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go-bip39"
	"log"
	"math/big"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
)

// Is a struct that defines parameters for Argon2 hashing algorithm.
type hashParams struct {
	hashTime    uint32
	hashMemory  uint32
	hashThreads uint8
	hashKeyLen  uint32
}

func randomCharset(length int) string {
	// Predefined character set containing letters (both cases) and digits
	rCharset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Create a byte slice of the specified length
	b := make([]byte, length)

	// Length of the character set
	charsetLen := big.NewInt(int64(len(rCharset)))

	for i := range b {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			log.Fatalf("error: reading random numbers: %s", err)
		}
		b[i] = rCharset[randomIndex.Int64()]
	}

	// Convert the byte slice to a string and return the generated random string
	return string(b)
}

func wordColor(word string, color string) string {
	// Map containing color names and their corresponding ANSI color codes
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

	// Check if the provided color string exists in the 'colors' map
	code, exists := colors[color]
	if exists {
		// Apply the ANSI color code to the word and return the formatted word
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", code, word)
	}

	// Return the word with color formatting if the provided color is supported
	return word
}

func wordsToEntropyBits(wordCount int) int {
	// Map specifying supported word counts and their equivalent entropy bits
	wordToBits := map[int]int{
		12: 128,
		24: 256,
	}

	// Retrieve the entropy bits for the given word count from the map
	bits, ok := wordToBits[wordCount]
	if !ok {
		var allowedWords []string
		for key := range wordToBits {
			allowedWords = append(allowedWords, strconv.Itoa(key))
		}
		sort.Strings(allowedWords)

		// If the word count is not supported, return an error
		fmt.Println("Unsupported word count.", fmt.Sprintf("Allowed words: %s", strings.Join(allowedWords, ", ")))
		os.Exit(1)
	}

	// Return the corresponding entropy bits for the provided word count
	return bits
}

func argon2Encode(data string, salt string) (output string, hashHex string) {
	// Define hashing parameters for Argon2
	p := &hashParams{
		hashTime:    4,
		hashMemory:  64 * 1024,
		hashThreads: 4,
		hashKeyLen:  32,
	}

	// Generate the Argon2 hash using IDKey function
	hash := argon2.IDKey([]byte(data), []byte(salt), p.hashTime, p.hashMemory, p.hashThreads, p.hashKeyLen)

	// Encode the salt and hash into base64 format
	b64Salt := base64.RawStdEncoding.EncodeToString([]byte(salt))

	// Construct information about the Argon2 hash and its parameters
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

	// Construct the output string containing Argon2 hash information
	output = fmt.Sprintf("\n%s\n", strings.Join(argon2output, "\n"))

	// Return the constructed output string and the hash in hexadecimal format
	return output, hex.EncodeToString(hash)
}

func constructHomeBip39Dir(dir string) string {
	// Get information about the current user
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	// Create the full path by joining the home directory path with the new directory name
	return filepath.Join(currentUser.HomeDir, dir)
}

func checkAndCreateDir(dir string) {
	// Use os.Stat to get information about the directory
	_, err := os.Stat(dir)

	if os.IsNotExist(err) {
		// Create the directory with 0755 permissions
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			log.Fatalf("error: %s", err)
		}
	}

	if err != nil {
		log.Fatalf("error: %s", err)
	}
}

func saveToFile(filePath string, data string) error {
	// Open the file at the specified filePath in write-only mode, create if it doesn't exist,
	// and set file permissions to 0400 (read-only for owner)
	fd, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return fmt.Errorf("cannot create and set permission to file: %w", err)
	}
	defer fd.Close()

	// Write the data to the file
	n, err := fd.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("cannot write to file: %w", err)
	}

	// Check if the number of bytes written doesn't match the length of the data
	if n != len(data) {
		return fmt.Errorf("incomplete write: %d/%d bytes written", n, len(data))
	}

	return nil
}

func outputMnemonic(mnemonic string, salt string, colorWord string, save string, savePath string) string {
	mnemonicList := strings.Split(mnemonic, " ")
	encodedHash, hash := argon2Encode(mnemonic, salt)
	outMnemonic := fmt.Sprintf("Mnemonic:\n%s\n", strings.Join(mnemonicList, " "))
	outColorMnemonic := outputColoredMnemonic(mnemonicList, colorWord)
	outFileMnemonic := outMnemonic + encodedHash

	// If save is set to "yes", save the outFileMnemonic to a file
	if save == "yes" {
		filePath := fmt.Sprintf("%s/%s_%d.%s", savePath, hash, time.Now().UnixNano(), "bip39")
		if err := saveToFile(filePath, outFileMnemonic); err == nil {
			fmt.Printf("File saved: %s\n\n", filePath)
		} else {
			log.Fatalf("error: while saving the file: %s\n\n", err)
		}
	} else if save == "no" {
		fmt.Print("File not saved. Only output.\n\n")
	}

	return outColorMnemonic + encodedHash
}

func outputColoredMnemonic(mnemonicList []string, colorWord string) string {
	var outColorBuffer bytes.Buffer

	colors := strings.Split(colorWord, ",")

	// Set default colors for the first and last words
	firstWordColor, lastWordColor := "default", "default"
	if len(colors) == 2 {
		firstWordColor = colors[0]
		lastWordColor = colors[1]
	}

	// Calculate the last index of the mnemonicList
	mnemonicLastIndex := len(mnemonicList) - 1

	// Construct the formatted string with colored first and last words
	outColorBuffer.WriteString(fmt.Sprintf("Mnemonic:\n%s ", wordColor(mnemonicList[0], firstWordColor)))
	for i := 1; i < mnemonicLastIndex; i++ {
		outColorBuffer.WriteString(fmt.Sprintf("%s ", mnemonicList[i]))
	}
	outColorBuffer.WriteString(fmt.Sprintf("%s\n", wordColor(mnemonicList[mnemonicLastIndex], lastWordColor)))

	return outColorBuffer.String()
}

func generateMnemonic(bitSize int, colorWord string, save string, savePath string) string {
	salt := randomCharset(24)
	entropy, _ := bip39.NewEntropy(bitSize)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	// Generate and output mnemonic information
	return outputMnemonic(mnemonic, salt, colorWord, save, savePath)
}

func existingMnemonic(colorWord string, save string, savePath string) string {
	// Prompt for and validate mnemonic
	fmt.Print("Enter Mnemonic: ")
	mnemonic, err := promptAndValidateMnemonic()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	// Prompt for and validate salt
	fmt.Print("Enter Salt: ")
	salt, err := promptAndValidateSalt()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	// Generate and output mnemonic information
	return outputMnemonic(mnemonic, salt, colorWord, save, savePath)
}

func promptAndValidateMnemonic() (trimMnemonic string, err error) {
	inputReader := bufio.NewReader(os.Stdin)
	input, _ := inputReader.ReadString('\n')
	trimMnemonic = strings.TrimSpace(input)

	if len(trimMnemonic) == 0 {
		return "", fmt.Errorf("mnemonic can't be empty")
	}

	if !bip39.IsMnemonicValid(trimMnemonic) {
		return "", fmt.Errorf("mnemonic is not valid")
	}

	return trimMnemonic, nil
}

func promptAndValidateSalt() (trimSalt string, err error) {
	inputReader := bufio.NewReader(os.Stdin)
	input, _ := inputReader.ReadString('\n')
	trimSalt = strings.TrimSpace(input)

	if len(trimSalt) == 0 {
		return "", fmt.Errorf("salt can't be empty")
	}

	return trimSalt, nil
}

func generateAction(cCtx *cli.Context) error {
	words := wordsToEntropyBits(cCtx.Int("words"))
	wordsColorFlag := strings.TrimSpace(cCtx.String("words-color"))
	saveFlag := strings.TrimSpace(cCtx.String("save"))
	saveDirFlag := path.Join(strings.TrimSpace(cCtx.String("save-dir")))

	if saveFlag == "yes" || saveFlag == "no" {
		if (saveFlag == "yes") && (saveDirFlag == saveDirFlag) {
			// Checking and create default directory to save mnemonic files
			checkAndCreateDir(saveDirFlag)
		}
		fmt.Print(generateMnemonic(words, wordsColorFlag, saveFlag, saveDirFlag))
	} else {
		return cli.Exit("Invalid value. Please enter 'yes' or 'no'.", 1)
	}

	return nil
}

func existingAction(cCtx *cli.Context) error {
	wordsColorFlag := strings.TrimSpace(cCtx.String("words-color"))
	saveFlag := strings.TrimSpace(cCtx.String("save"))
	saveDirFlag := path.Join(strings.TrimSpace(cCtx.String("save-dir")))

	if saveFlag == "yes" || saveFlag == "no" {
		if (saveFlag == "yes") && (saveDirFlag == saveDirFlag) {
			// Checking and create default directory to save mnemonic files
			checkAndCreateDir(saveDirFlag)
		}
		fmt.Print(existingMnemonic(wordsColorFlag, saveFlag, saveDirFlag))
	} else {
		return cli.Exit("Invalid value. Please enter 'yes' or 'no'.", 1)
	}

	return nil
}

func main() {
	colorUsage := "First and last word color highlighting\n" +
		"\tAllowed colors: default, black, red, green, yellow, blue, magenta, cyan, white,\n" +
		"\tlight-gray, light-red, light-green, light-yellow, light-blue, light-magenta, light-cyan, light-white"

	mainUsage := "--words-color value\t" + colorUsage + "\n" +
		"--save value\tSave to file (yes/no)\n\tFile name format: <Argon2 Hash>_<Timestamp UnixNano>.bip39\n" +
		"--save-dir value\tSave file to directory"

	defaultMnemonicsDir := constructHomeBip39Dir("bip39/mnemonics")

	app := &cli.App{
		Usage: "Generation, verification of mnemonics and obtaining their hash in Argon2 format",
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "BIP39 mnemonic generation\n--words value\tWord count\n" + mainUsage,
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
						Value: defaultMnemonicsDir,
					},
				},
				Action: func(cCtx *cli.Context) error {
					err := generateAction(cCtx)
					if err != nil {
						return err
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
						Value: defaultMnemonicsDir,
					},
				},
				Action: func(cCtx *cli.Context) error {
					err := existingAction(cCtx)
					if err != nil {
						return err
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("error: %s", err)
	}
}
