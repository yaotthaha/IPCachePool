package tool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/wumansgy/goEncrypt"
)

func Sha256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func ECCKeyGen() ([]byte, []byte, error) {
	priKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	x509priKey, err := x509.MarshalECPrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	priKeyBlock := pem.Block{
		Type:  "Yaott ECC PRIVATE KEY",
		Bytes: x509priKey,
	}
	ECCPriKeyBuf := bytes.NewBuffer(nil)
	err = pem.Encode(ECCPriKeyBuf, &priKeyBlock)
	if err != nil {
		return nil, nil, err
	}
	x509pubKey, err := x509.MarshalPKIXPublicKey(&priKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubKeyBlock := pem.Block{
		Type:  "Yaott ECC PUBLIC KEY",
		Bytes: x509pubKey,
	}
	ECCPubKeyBuf := bytes.NewBuffer(nil)
	err = pem.Encode(ECCPubKeyBuf, &pubKeyBlock)
	if err != nil {
		return nil, nil, err
	}
	ECCPrivateKeyBytes := ECCPriKeyBuf.Bytes()
	ECCPublicKeyBytes := ECCPubKeyBuf.Bytes()
	ECCPriKeyBase64 := base64.StdEncoding.EncodeToString(ECCPrivateKeyBytes)
	ECCPubKeyBase64 := base64.StdEncoding.EncodeToString(ECCPublicKeyBytes)
	return []byte(ECCPriKeyBase64), []byte(ECCPubKeyBase64), nil
}

func ECCEncrypt(data []byte, pubKey []byte) ([]byte, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(string(pubKey))
	if err != nil {
		return nil, err
	}
	pubKeyBlock, _ := pem.Decode(pubKeyBytes)
	if pubKeyBlock == nil {
		return nil, errors.New("pubKeyBlock is nil")
	}
	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pubKeyECC := pubKeyInterface.(*ecdsa.PublicKey)
	ECCpubKey := goEncrypt.ImportECDSAPublic(pubKeyECC)
	cryptData, err := goEncrypt.Encrypt(rand.Reader, ECCpubKey, data, nil, nil)
	if err != nil {
		return nil, err
	}
	return cryptData, nil
}

func ECCDecrypt(data []byte, priKey []byte) ([]byte, error) {
	priKeyBytes, err := base64.StdEncoding.DecodeString(string(priKey))
	if err != nil {
		return nil, err
	}
	priKeyBlock, _ := pem.Decode(priKeyBytes)
	if priKeyBlock == nil {
		return nil, errors.New("priKeyBlock is nil")
	}
	x509priKey, err := x509.ParseECPrivateKey(priKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	ECCpriKey := goEncrypt.ImportECDSA(x509priKey)
	decryptData, err := ECCpriKey.Decrypt(data, nil, nil)
	if err != nil {
		return nil, err
	}
	return decryptData, nil
}

func Base64Encode(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}
