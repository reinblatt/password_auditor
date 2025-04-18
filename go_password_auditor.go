package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout     = 10 * time.Second
	defaultDelay      = 2 * time.Second
	defaultMaxWorkers = 5
)

// Config holds the application configuration
type Config struct {
	FilePath    string
	Timeout     time.Duration
	Delay       time.Duration
	MaxWorkers  int
	BaseURL     string
}

// PasswordChecker handles password checking operations
type PasswordChecker struct {
	client  *http.Client
	baseURL string
	delay   time.Duration
}

// NewPasswordChecker creates a new PasswordChecker instance
func NewPasswordChecker(config Config) *PasswordChecker {
	return &PasswordChecker{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		baseURL: config.BaseURL,
		delay:   config.Delay,
	}
}

func main() {
	// Parse command line arguments
	config := parseFlags()

	// Resolve absolute path
	absolutePath, err := filepath.Abs(config.FilePath)
	if err != nil {
		log.Fatalf("Error resolving file path: %v", err)
	}

	// Read passwords from file
	passwords, err := readPasswordsFromFile(absolutePath)
	if err != nil {
		log.Fatalf("Error reading passwords from file: %v", err)
	}

	// Create password checker
	checker := NewPasswordChecker(config)

	// Process passwords concurrently
	processPasswords(passwords, checker, config.MaxWorkers)
}

// parseFlags parses command line flags and returns a Config
func parseFlags() Config {
	filePath := flag.String("file", "passwords.txt", "Path to the password file")
	timeout := flag.Duration("timeout", defaultTimeout, "HTTP request timeout")
	delay := flag.Duration("delay", defaultDelay, "Delay between API requests")
	maxWorkers := flag.Int("workers", defaultMaxWorkers, "Maximum number of concurrent workers")
	baseURL := flag.String("api-url", "https://api.pwnedpasswords.com/range/", "Base URL for the Have I Been Pwned API")

	flag.Parse()

	return Config{
		FilePath:    *filePath,
		Timeout:     *timeout,
		Delay:       *delay,
		MaxWorkers:  *maxWorkers,
		BaseURL:     *baseURL,
	}
}

// processPasswords processes passwords concurrently using a worker pool
func processPasswords(passwords []string, checker *PasswordChecker, maxWorkers int) {
	var wg sync.WaitGroup
	passwordChan := make(chan string, maxWorkers)

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range passwordChan {
				checkPassword(password, checker)
			}
		}()
	}

	// Send passwords to workers
	for _, password := range passwords {
		passwordChan <- password
	}
	close(passwordChan)

	// Wait for all workers to finish
	wg.Wait()
}

// checkPassword checks a single password and logs the result
func checkPassword(password string, checker *PasswordChecker) {
	hashedPassword := hashPassword(password)
	isPwned, err := checker.checkPasswordPwned(hashedPassword)
	if err != nil {
		log.Printf("Error checking password '%s': %v", password, err)
		return
	}

	if isPwned {
		log.Printf("Password '%s' has been pwned!", password)
	} else {
		log.Printf("Password '%s' has not been recorded as pwned.", password)
	}
}

// readPasswordsFromFile reads passwords from a file
func readPasswordsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()
		passwords = append(passwords, password)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning file: %w", err)
	}

	return passwords, nil
}

// hashPassword hashes a password using SHA-1
func hashPassword(password string) string {
	hash := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// checkPasswordPwned checks if a password has been pwned using the Have I Been Pwned API
func (pc *PasswordChecker) checkPasswordPwned(hashedPassword string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pc.client.Timeout)
	defer cancel()

	apiURL := fmt.Sprintf("%s%s", pc.baseURL, hashedPassword[:5])

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := pc.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	responseBody := string(body)
	pwnedPasswords := strings.Split(responseBody, "\n")

	for _, pwnedPassword := range pwnedPasswords {
		parts := strings.Split(pwnedPassword, ":")
		if len(parts) == 2 && parts[0] == hashedPassword[5:] {
			return true, nil
		}
	}

	// Add delay between requests to be respectful to the API
	time.Sleep(pc.delay)

	return false, nil
}
