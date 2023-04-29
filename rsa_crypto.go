package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func (s *RSA) Encrypt(plainText string) (string, error) {
	if s.PublicKey == nil {
		return "", errors.New("PublicKey is nil")
	}

	hash := sha256.New()
	cipherText, err := rsa.EncryptOAEP(hash, rand.Reader, s.PublicKey, []byte(plainText), []byte(""))
	decoded := base64.StdEncoding.EncodeToString(cipherText)
	return decoded, err
}

func (s *RSA) Decrypt(ciphertext string) (string, error) {
	if s.PrivateKey == nil {
		return "", errors.New("PrivateKey is nil")
	}

	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	decrypted, err := rsa.DecryptOAEP(hash, rand.Reader, s.PrivateKey, decoded, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// Sign is
func (s *RSA) Sign(src []byte) (string, error) {
	if s.PrivateKey == nil {
		return "", errors.New("PrivateKey is nil")
	}

	h := crypto.SHA256.New()
	h.Write(src)
	signBytes, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA256, h.Sum(nil))
	sign := base64.StdEncoding.EncodeToString(signBytes)
	return sign, err
}

// Verify is
func (s *RSA) Verify(src []byte, sign []byte) error {
	if s.PublicKey == nil {
		return errors.New("PublicKey is nil")
	}

	h := crypto.SHA256.New()
	h.Write(src)
	return rsa.VerifyPKCS1v15(s.PublicKey, crypto.SHA256, h.Sum(nil), sign)
}
