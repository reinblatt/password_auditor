# Password Auditor

A Go-based tool to check if passwords have been compromised using the Have I Been Pwned API.

## Features

- Check multiple passwords from a file
- Concurrent processing with configurable worker count
- Rate limiting to respect API limits
- Configurable timeouts and delays
- Detailed error reporting

## Installation

```bash
go get github.com/yourusername/password_auditor
```

## Usage

### Basic Usage

```bash
go run go_password_auditor.go -file passwords.txt
```

### Command Line Options

- `-file`: Path to the password file (default: "passwords.txt")
- `-timeout`: HTTP request timeout (default: 10s)
- `-delay`: Delay between API requests (default: 2s)
- `-workers`: Maximum number of concurrent workers (default: 5)
- `-api-url`: Base URL for the Have I Been Pwned API (default: "https://api.pwnedpasswords.com/range/")

### Example

```bash
go run go_password_auditor.go -file passwords.txt -workers 10 -delay 1s
```

## Password File Format

The password file should contain one password per line. For example:

```
password123
qwerty
letmein
```

## Security Considerations

- The tool uses SHA-1 hashing for passwords
- Only the first 5 characters of the hash are sent to the API
- The full password is never transmitted
- Rate limiting is implemented to respect API limits

## Testing

### Running Tests

The project includes unit tests in `go_password_auditor_test.go`. To run the tests:

```bash
# Run all tests
go test -v

# Run a specific test
go test -v -run TestHashPassword
go test -v -run TestCheckPasswordPwned

# Run tests with coverage
go test -cover
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test Structure

The test suite includes:

1. `TestHashPassword`: Tests the password hashing function with various inputs
   - Tests simple password hashing
   - Tests empty password handling

2. `TestCheckPasswordPwned`: Tests the password checking functionality
   - Tests with a mock HTTP server
   - Tests both pwned and non-pwned password scenarios
   - Tests error handling

### Test Output

When running tests with `-v` flag, you'll see detailed output for each test case:

```
=== RUN   TestHashPassword
=== RUN   TestHashPassword/simple_password
=== RUN   TestHashPassword/empty_password
--- PASS: TestHashPassword (0.00s)
    --- PASS: TestHashPassword/simple_password (0.00s)
    --- PASS: TestHashPassword/empty_password (0.00s)
=== RUN   TestCheckPasswordPwned
=== RUN   TestCheckPasswordPwned/pwned_password
=== RUN   TestCheckPasswordPwned/not_pwned_password
--- PASS: TestCheckPasswordPwned (0.01s)
    --- PASS: TestCheckPasswordPwned/pwned_password (0.00s)
    --- PASS: TestCheckPasswordPwned/not_pwned_password (0.00s)
PASS
```

## License

MIT License
