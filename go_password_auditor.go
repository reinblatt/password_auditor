package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	filePath := "passwords.txt"
	absolutePath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Printf("Error resolving file path: %s\n", err.Error())
		return
	}

	passwords, err := readPasswordsFromFile(absolutePath)
	if err != nil {
		fmt.Printf("Error reading passwords from file: %s\n", err.Error())
		return
	}

	for _, password := range passwords {
		hashedPassword := hashPassword(password)
		isPwned, err := checkPasswordPwned(hashedPassword)
		if err != nil {
			fmt.Printf("Error checking password against Have I Been Pwned API: %s\n", err.Error())
			return
		}

		if isPwned {
			fmt.Printf("Password '%s' has been pwned!\n", password)
		} else {
			fmt.Printf("Password '%s' has not been recorded as pwned.\n", password)
		}
	}
}

func readPasswordsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()
		passwords = append(passwords, password)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return passwords, nil
}

func hashPassword(password string) string {
	hash := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

func checkPasswordPwned(hashedPassword string) (bool, error) {
	apiURL := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", hashedPassword[:5])

	resp, err := http.Get(apiURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	responseBody := string(body)
	pwnedPasswords := strings.Split(responseBody, "\n")

	for _, pwnedPassword := range pwnedPasswords {
		parts := strings.Split(pwnedPassword, ":")
		if len(parts) == 2 && parts[0] == hashedPassword[5:] {
			return true, nil
		}
	}

	return false, nil
}
