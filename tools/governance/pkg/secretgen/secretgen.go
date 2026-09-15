// Package secretgen generates random secrets satisfying a caller-specified mix of character
// classes. Refer to docs/secretrotate-design.md for the design.
package secretgen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// CharClass is a named set of characters from which a generated secret may draw.
type CharClass struct {
	Name    string
	Charset string
}

var (
	Upper   = CharClass{"upper", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
	Lower   = CharClass{"lower", "abcdefghijklmnopqrstuvwxyz"}
	Digit   = CharClass{"digit", "0123456789"}
	Special = CharClass{"special", "!@#$%^&*-_=+"}
)

func pickRandomChar(charset string) (byte, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, fmt.Errorf("secretgen: pick random character: %w", err)
	}
	return charset[idx.Int64()], nil
}

// Generate returns a random string satisfying every given class.
func Generate(length int, classes ...CharClass) (string, error) {
	if len(classes) == 0 {
		return "", fmt.Errorf("secretgen: at least one character class is required")
	}
	if length < len(classes) {
		length = len(classes)
	}
	buf := make([]byte, length)

	var allChars string
	for i, class := range classes {
		allChars += class.Charset
		c, err := pickRandomChar(class.Charset)
		if err != nil {
			return "", err
		}
		buf[i] = c
	}
	for i := len(classes); i < length; i++ {
		c, err := pickRandomChar(allChars)
		if err != nil {
			return "", err
		}
		buf[i] = c
	}

	for i := length - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("secretgen: shuffle secret: %w", err)
		}
		j := jBig.Int64()
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf), nil
}
