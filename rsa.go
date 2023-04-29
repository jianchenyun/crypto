package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

type RSA struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// GenerateKey RSA private/public key
func (s *RSA) GenerateKey() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	s.PrivateKey = priv
	s.PublicKey = &priv.PublicKey

	return nil
}

// GenerateKeyFile generate RSA key file
func (s *RSA) GenerateKeyFile(privFileName, pubFileName string) error {
	s.GenerateKey()
	err := s.GenerateKey()
	if err != nil {
		return err
	}
	err = s.saveKeyFile(s.privBytes(s.PrivateKey), privFileName, true)
	if err != nil {
		return err
	}
	pubBytes, err := s.pubBytes(s.PublicKey)
	if err != nil {
		return err
	}
	err = s.saveKeyFile(pubBytes, pubFileName, false)
	if err != nil {
		return err
	}
	return nil
}

// saveKeyFile save RSA key into file
// keyType if true then private key else public key
func (s *RSA) saveKeyFile(keyBytes []byte, filename string, keyType bool) error {
	var block *pem.Block
	if keyType {
		block = s.privBlock(keyBytes)
	} else {
		block = s.pubBlock(keyBytes)
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

// GenerateKeyBuffer generate RSA key to Memory
func (s *RSA) GenerateKeyBuffer(priv *rsa.PrivateKey, pub *rsa.PublicKey) (string, string, error) {
	privStr := s.toKeyMemory(s.privBytes(priv), true)
	if privStr == "" {
		return "", "", errors.New("GenerateKeyBuffer RSA private key fail")
	}
	pubBytes, e := s.pubBytes(pub)
	if e != nil {
		return "", "", e
	}
	pubStr := s.toKeyMemory(pubBytes, false)
	if pubStr == "" {
		return "", "", errors.New("GenerateKeyBuffer RSA public key fail")
	}
	return privStr, pubStr, nil
}

func (s *RSA) toKeyMemory(keyBytes []byte, keyType bool) string {
	var block *pem.Block
	if keyType {
		block = s.privBlock(keyBytes)
	} else {
		block = s.pubBlock(keyBytes)
	}
	return string(pem.EncodeToMemory(block))
}

// GenerateKeyBase64 generate RSA key to string
// Compared with GenerateKeyBuffer this output:
//  1. Have no header/tailer line
//  2. Key content is merged into one-line format
func (s *RSA) GenerateKeyBase64(priv *rsa.PrivateKey, pub *rsa.PublicKey) (string, string, error) {
	privStr, err := s.GenerateKeyPrivBase64(priv)
	if err != nil {
		return "", "", err
	}
	pubStr, err := s.GenerateKeyPubBase64(pub)
	if err != nil {
		return "", "", err
	}
	return privStr, pubStr, nil
}

func (s *RSA) GenerateKeyPrivBase64(priv *rsa.PrivateKey) (string, error) {
	privStr := s.toKeyBase64(s.privBytes(priv))
	if privStr == "" {
		return "", errors.New("GenerateKeyBase64 RSA private key fail")
	}
	return privStr, nil
}

func (s *RSA) GenerateKeyPubBase64(pub *rsa.PublicKey) (string, error) {
	pubBytes, err := s.pubBytes(pub)
	if err != nil {
		return "", err
	}
	pubStr := s.toKeyBase64(pubBytes)
	if pubStr == "" {
		return "", errors.New("GenerateKeyBase64 RSA public key fail")
	}
	return pubStr, nil
}

func (s *RSA) toKeyBase64(keyBytes []byte) string {
	return base64.StdEncoding.EncodeToString(keyBytes)
}

func (s *RSA) privBlock(keyBytes []byte) *pem.Block {
	return &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
}

func (s *RSA) pubBlock(keyBytes []byte) *pem.Block {
	return &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}
}

func (s *RSA) privBytes(priv *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(priv)
}

func (s *RSA) pubBytes(pub *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
