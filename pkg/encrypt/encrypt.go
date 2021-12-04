package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/tyler-smith/go-bip39"
)

type Account struct {
	encryptedMnemonic string
}

func New() *Account {
	return &Account{}
}

func (a *Account) GetMnemonic() string {
	return a.encryptedMnemonic
}

func (a *Account) CreateMnemonic(passPhrase string) (string, string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", "", err
	}

	aesKey := sha256.Sum256([]byte(passPhrase))

	// encrypt the mnemonic
	encryptedMessage, err := encrypt(aesKey[:], mnemonic)
	if err != nil {
		return "", "", fmt.Errorf("load mnemonic: %w", err)
	}
	a.encryptedMnemonic = encryptedMessage
	return mnemonic, encryptedMessage, nil
}

func (a *Account) LoadMnemonic(mnemonic string) {
	a.encryptedMnemonic = mnemonic
}

func (a *Account) decryptMnemonic(password string) (string, error) {
	aesKey := sha256.Sum256([]byte(password))

	//decrypt the message
	mnemonic, err := decrypt(aesKey[:], a.encryptedMnemonic)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}
