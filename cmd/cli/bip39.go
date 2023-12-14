package main

import (
	"bip39"
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
)

const Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Argon2EncodeParams is a struct that defines parameters for Argon2Id hashing algorithm.
type argon2EncodeParams struct {
	hashTime    uint32
	hashMemory  uint32
	hashThreads uint8
	hashKeyLen  uint32
}

type defaultFlags struct {
	words      int
	wordsColor string
	save       string
	saveDir    string
}

func charsetValidate(data string) bool {
	regex := regexp.MustCompile("^[a-zA-Z0-9]+$")

	return regex.MatchString(data)
}

func generateRandomCharset(length int) (randomCharset string, err error) {
	var randomIndex *big.Int

	// Create a byte slice of the specified length
	randomBytes := make([]byte, length)

	// Length of the character set
	charsetLen := big.NewInt(int64(len(Charset)))

	for i := range randomBytes {
		randomIndex, err = rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("reading random numbers: %s", err)
		}

		randomBytes[i] = Charset[randomIndex.Int64()]
	}

	// Convert the byte slice to a string and return the generated random string
	return string(randomBytes), nil
}

func wordHighlighting(word string, color string) string {
	// Map containing color names and their corresponding ANSI color codes
	ansiColors := map[string]int{
		"black":   40,
		"red":     41,
		"green":   42,
		"yellow":  43,
		"blue":    44,
		"magenta": 45,
		"cyan":    46,
		"white":   47,
		// "default":       49, // currently specified color in your terminal
		// "light-gray":    100,
		// "light-red":     101,
		// "light-green":   102,
		// "light-yellow":  103,
		// "light-blue":    104,
		// "light-magenta": 105,
		// "light-cyan":    106,
		// "light-white":   107,
	}

	// Check if the provided color string exists in the 'colors' map
	if code, exists := ansiColors[color]; exists {
		// Apply the ANSI color code to the word and return the formatted word
		return fmt.Sprintf("\x1b[%dm%s\x1b[0m", code, word)
	}

	// Returns a word with no color formatting if the specified color is not supported
	return word
}

func wordsToEntropyBits(wordCount int) (entropyBits int, err error) {
	var exists bool

	// Map specifying supported word counts and their equivalent entropy bits
	wordToBits := map[int]int{
		12: 128,
		24: 256,
	}

	// Retrieve the entropy bits for the given word count from the map
	entropyBits, exists = wordToBits[wordCount]
	if !exists {
		var allowedWords []string
		for key := range wordToBits {
			allowedWords = append(allowedWords, strconv.Itoa(key))
		}

		sort.Strings(allowedWords)

		// If the word count is not supported, return an error
		return 0, fmt.Errorf("unsupported word count. Allowed words: %s", strings.Join(allowedWords, ", "))
	}

	// Return the corresponding entropy bits for the provided word count
	return entropyBits, nil
}

func argon2Encode(data string, salt string) (hashInfo string, hashHex string) {
	// Define hashing parameters for Argon2Id
	p := &argon2EncodeParams{
		hashTime:    4,
		hashMemory:  64 * 1024,
		hashThreads: 4,
		hashKeyLen:  32,
	}

	// Generate the Argon2Id hash using IDKey function
	hash := argon2.IDKey([]byte(data), []byte(salt), p.hashTime, p.hashMemory, p.hashThreads, p.hashKeyLen)

	// Encode the salt and hash into base64 format
	b64Salt := base64.RawStdEncoding.EncodeToString([]byte(salt))

	// Construct information about the Argon2Id hash and its parameters
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

	// Construct the output string containing Argon2Id hash information
	hashInfo = strings.Join(argon2output, "\n")

	// Return the constructed output string and the hash in hexadecimal format
	return hashInfo, hex.EncodeToString(hash)
}

func defaultHomeDirConstruct(dir string) (constructDir string, err error) {
	var currentUser *user.User

	// Get information about the current user
	currentUser, err = user.Current()
	if err != nil {
		return "", err
	}

	// Create the full path by joining the home directory path with the new directory name
	return path.Join(currentUser.HomeDir, dir), nil
}

func checkAndCreateDir(dir string) error {
	// Use os.Stat to get information about the directory
	_, err := os.Stat(dir)

	if os.IsNotExist(err) {
		// Create the directory with 0755 permissions
		if err = os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if err != nil {
		return err
	}

	return nil
}

func saveToFile(fileDir string, fileName string, data string) error {
	// Check directory and create if not exists
	if err := checkAndCreateDir(fileDir); err != nil {
		return err
	}

	// Open the file at the specified filePath in write-only mode, create if it doesn't exist,
	// and set file permissions to 0400 (read-only for owner)
	fd, err := os.OpenFile(path.Join(fileDir, fileName), os.O_WRONLY|os.O_CREATE, 0400)
	if err != nil {
		return fmt.Errorf("cannot create and set permission to file: %s", err)
	}
	defer fd.Close()

	// Write the data to the file
	n, err := fd.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("cannot write to file: %s", err)
	}

	// Check if the number of bytes written doesn't match the length of the data
	if n != len(data) {
		return fmt.Errorf("incomplete write: %d/%d bytes written", n, len(data))
	}

	return nil
}

func inputData() (trimData string, err error) {
	inputReader := bufio.NewReader(os.Stdin)
	input, err := inputReader.ReadString('\n')
	trimData = strings.TrimSpace(input)

	if err != nil {
		return "", err
	}

	if len(trimData) == 0 {
		return "", fmt.Errorf("%s", "input data can't be empty")
	}

	return trimData, nil
}

func mnemonicHighlighting(mnemonicList []string, wordsColor string) string {
	var outColorBuffer bytes.Buffer

	colors := strings.Split(wordsColor, ",")

	// Calculate the last index of the mnemonicList
	mnemonicLastIndex := len(mnemonicList) - 1

	// Construct the formatted string with colored first and last words
	outColorBuffer.WriteString(fmt.Sprintf("%s ", wordHighlighting(mnemonicList[0], colors[0])))

	for i := 1; i < mnemonicLastIndex; i++ {
		outColorBuffer.WriteString(fmt.Sprintf("%s ", mnemonicList[i]))
	}
	outColorBuffer.WriteString(wordHighlighting(mnemonicList[mnemonicLastIndex], colors[1]))

	return outColorBuffer.String()
}

func mnemonicConstructAndSave(mnemonic string, salt string, wordsColor string, save string, saveDir string) (outputMnemonic string, err error) {
	hashInfo, hashHex := argon2Encode(mnemonic, salt)
	mnemonicList := strings.Split(mnemonic, " ")
	outMnemonicHighlighting := mnemonicHighlighting(mnemonicList, wordsColor)

	// If save is set to "yes", also save the mnemonic + hashInfo to a file
	if save == "yes" {
		outputMnemonic = fmt.Sprintf("Mnemonic:\n%s\n\n%s", mnemonic, hashInfo)
		filePath := fmt.Sprintf("%s_%d.%s", hashHex, time.Now().UnixNano(), "bip39")

		if err = saveToFile(saveDir, filePath, outputMnemonic); err == nil {
			fmt.Printf("File saved: %s\n\n", path.Join(saveDir, filePath))
		} else {
			return "", fmt.Errorf("while saving the file: %s", err)
		}
	} else if save == "no" {
		fmt.Print("Only console output, file NOT saved.\n\n")
	}

	outputMnemonic = fmt.Sprintf("Mnemonic:\n%s\n\n%s", outMnemonicHighlighting, hashInfo)

	return outputMnemonic, nil
}

func generateMnemonicAction(cCtx *cli.Context) error {
	bitSize, err := wordsToEntropyBits(cCtx.Int("words"))
	if err != nil {
		return err
	}

	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}

	salt, err := generateRandomCharset(24)
	if err != nil {
		return err
	}

	wordsColor := strings.TrimSpace(cCtx.String("color"))
	save := strings.TrimSpace(cCtx.String("save"))
	saveDir := strings.TrimSpace(cCtx.String("dir"))

	construct, err := mnemonicConstructAndSave(mnemonic, salt, wordsColor, save, saveDir)
	if err != nil {
		return err
	}

	fmt.Println(construct)

	return nil
}

func existingMnemonicAction(cCtx *cli.Context) error {
	// Prompt for and validate mnemonic
	fmt.Print("Enter Mnemonic: ")

	mnemonic, err := inputData()
	if err != nil {
		return err
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("%s", "mnemonic is not valid")
	}

	// Prompt for and validate salt
	fmt.Print("Enter Argon2 Salt: ")

	salt, err := inputData()
	if err != nil {
		return err
	}

	fmt.Print("\n")

	if !charsetValidate(salt) {
		return fmt.Errorf("%s", "the salt includes characters that are not allowed")
	}

	wordsColor := strings.TrimSpace(cCtx.String("color"))
	save := strings.TrimSpace(cCtx.String("save"))
	saveDir := strings.TrimSpace(cCtx.String("dir"))

	construct, err := mnemonicConstructAndSave(mnemonic, salt, wordsColor, save, saveDir)
	if err == nil {
		fmt.Println(construct)
	} else {
		return err
	}

	return nil
}

func main() {
	defaultFlagWords := 24
	defaultFlagWordsColor := "green,blue"
	defaultFlagSaveDir, _ := defaultHomeDirConstruct("bip39/mnemonics") // This wil save to: ~/bip39/mnemonics

	mainUsage := func(f *defaultFlags) string {
		usage := "--color value\tFirst and last word color highlighting (default: " + f.wordsColor + ")\n" +
			"\tAllowed colors: black, red, green, yellow, blue, magenta, cyan, white\n" +
			"--save value\tSave to file [yes/no] (default: " + f.save + ")\n" +
			"\tFile name format: <Argon2idHash>_<TimestampUnixNano>.bip39\n" +
			"--dir value\tSave file to directory (default: " + f.saveDir + ")\n"

		if f.words != 0 {
			return "--words value\tWord count (default: " + strconv.Itoa(f.words) + ")\n" + usage
		}

		return usage
	}

	generateUsage := mainUsage(&defaultFlags{words: defaultFlagWords, wordsColor: defaultFlagWordsColor, save: "yes", saveDir: defaultFlagSaveDir})

	existingUsage := mainUsage(&defaultFlags{wordsColor: defaultFlagWordsColor, save: "no", saveDir: defaultFlagSaveDir})

	saveFlagValidate := func(cCtx *cli.Context, value string) error {
		if value != "yes" && value != "no" {
			return fmt.Errorf("%s", "invalid value. Please enter 'yes' or 'no'")
		}

		return nil
	}

	app := &cli.App{
		Usage: "Generation, verification of mnemonics in BIP39 standard and obtaining their hash in Argon2id format",
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: fmt.Sprintf("BIP39 mnemonic generation\n%s", generateUsage),
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "words", Value: defaultFlagWords},
					&cli.StringFlag{
						Name:  "color",
						Value: defaultFlagWordsColor,
					},
					&cli.StringFlag{
						Name:   "save",
						Value:  "yes",
						Action: saveFlagValidate,
					},
					&cli.StringFlag{
						Name:  "dir",
						Value: defaultFlagSaveDir,
					},
				},
				Action: func(cCtx *cli.Context) error {
					if err := generateMnemonicAction(cCtx); err != nil {
						return err
					}

					return nil
				},
			},
			{
				Name:  "existing",
				Usage: fmt.Sprintf("Check existing BIP39 mnemonic\n%s", existingUsage),
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "color",
						Value: defaultFlagWordsColor,
					},
					&cli.StringFlag{
						Name:   "save",
						Value:  "no",
						Action: saveFlagValidate,
					},
					&cli.StringFlag{
						Name:  "dir",
						Value: defaultFlagSaveDir,
					},
				},
				Action: func(cCtx *cli.Context) error {
					if err := existingMnemonicAction(cCtx); err != nil {
						return err
					}

					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
