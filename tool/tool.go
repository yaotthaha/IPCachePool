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
	"github.com/google/uuid"
	"math/big"
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
		Type:  "ECC PRIVATE KEY",
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
		Type:  "ECC PUBLIC KEY",
		Bytes: x509pubKey,
	}
	ECCPubKeyBuf := bytes.NewBuffer(nil)
	err = pem.Encode(ECCPubKeyBuf, &pubKeyBlock)
	if err != nil {
		return nil, nil, err
	}
	ECCPrivateKeyBytes := ECCPriKeyBuf.Bytes()
	ECCPublicKeyBytes := ECCPubKeyBuf.Bytes()
	ECCPriKeyBase64 := Base64Encode(ECCPrivateKeyBytes)
	ECCPubKeyBase64 := Base64Encode(ECCPublicKeyBytes)
	return ECCPriKeyBase64, ECCPubKeyBase64, nil
}

func ECCSign(data []byte, priKey []byte) ([]byte, error) {
	priKeyBytes, err := Base64Decode(priKey)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(priKeyBytes)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	Bytes := Sha256(data)
	//对哈希值生成数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, Bytes)
	if err != nil {
		return nil, err
	}
	rtext, _ := r.MarshalText()
	stext, _ := s.MarshalText()
	return append(rtext, append([]byte("0xff"), stext...)...), nil
}

func ECCVerifySign(data []byte, Sign string, pubKey []byte) (bool, error) {
	pubKeyBytes, err := Base64Decode(pubKey)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(pubKeyBytes)
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	publicKey := publicInterface.(*ecdsa.PublicKey)
	Bytes := Sha256(data)
	text := bytes.Split([]byte(Sign), []byte("0xff"))
	var r, s big.Int
	err = r.UnmarshalText(text[0])
	if err != nil {
		return false, err
	}
	err = s.UnmarshalText(text[1])
	if err != nil {
		return false, err
	}
	verify := ecdsa.Verify(publicKey, Bytes, &r, &s)
	return verify, nil
}

func Base64Encode(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}

func Base64Decode(data []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(data))
}

func UUIDGen() string {
	return uuid.New().String()
}
