package encrypt

import (
	"crypto/sha256"
	"fmt"
)

func (a *Account) EncryptContent(password, content string) (string, error) {
	mnemonic, err := a.decryptMnemonic(password)
	if err != nil {
		return "", fmt.Errorf("load mnemonic: %w", err)
	}
	aesKey := sha256.Sum256([]byte(mnemonic))

	// encrypt the mnemonic
	encryptedContent, err := encrypt(aesKey[:], content)
	if err != nil {
		return "", fmt.Errorf("load mnemonic: %w", err)
	}

	return encryptedContent, nil
}

func (a *Account) DecryptContent(password, content string) (string, error) {
	mnemonic, err := a.decryptMnemonic(password)
	if err != nil {
		return "", fmt.Errorf("load mnemonic: %w", err)
	}
	aesKey := sha256.Sum256([]byte(mnemonic))

	//decrypt the message
	decryptedContent, err := decrypt(aesKey[:], content)
	if err != nil {
		return "", err
	}

	return decryptedContent, nil
}
