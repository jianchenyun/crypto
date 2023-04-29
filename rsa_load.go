package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// LoadkeyFile from file load key
func (s *RSA) LoadkeyFile(privFileName string) error {
	priv, err := s.loadkeyPrivFile(privFileName)
	if err != nil {
		return err
	}

	s.PrivateKey = priv
	s.PublicKey = &priv.PublicKey

	return nil
}

// loadkeyPrivFile from privfile load key
func (s *RSA) loadkeyPrivFile(privFileName string) (*rsa.PrivateKey, error) {

	block, err := s.loadBlock(privFileName)
	if err != nil {
		return nil, err
	}
	priv, err := s.parsePriv(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func (s *RSA) loadBlock(keyFileName string) (*pem.Block, error) {
	keyBuffer, err := ioutil.ReadFile(keyFileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBuffer)
	if block == nil {
		return nil, errors.New("load " + keyFileName + " block fail")
	}
	return block, nil
}

// LoadKeyBase64 from string load key
func (s *RSA) LoadKeyBase64(privString string) error {

	priv, err := s.loadPrivKey(privString)
	if err != nil {
		return err
	}

	s.PrivateKey = priv
	s.PublicKey = &priv.PublicKey

	return nil
}

// LoadPrivKey PrivateKey from string
func (s *RSA) loadPrivKey(privString string) (*rsa.PrivateKey, error) {
	keyBytes, err := s.loadKeyBytes(privString)
	if err != nil {
		return nil, err
	}
	priv, e := s.parsePriv(keyBytes)
	if e != nil {
		return nil, e
	}
	return priv, nil
}

func (s *RSA) loadKeyBytes(base64Key string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64Key)
}

func (s *RSA) parsePriv(blockBytes []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(blockBytes)
}
