
package main

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "errors"
    "fmt"
    "os"
)

func ComputeHash(data interface{}) []byte {
    b, _ := json.Marshal(data)
    h := sha256.Sum256(b)
    return h[:]
}

func SignData(priv *ecdsa.PrivateKey, data interface{}) ([]byte, error) {
    hash := ComputeHash(data)
    return ecdsa.SignASN1(rand.Reader, priv, hash)
}

func LoadPublicKeyFromCert(certPath string) (*ecdsa.PublicKey, error) {
    certBytes, err := os.ReadFile(certPath)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(certBytes)
    if block == nil {
        return nil, errors.New("failed to decode certificate PEM")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, err
    }
    pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
    if !ok {
        return nil, errors.New("not ECDSA public key")
    }
    return pubKey, nil
}

func VerifySignature(data interface{}, signature []byte, pub *ecdsa.PublicKey) bool {
    hash := ComputeHash(data)
    return ecdsa.VerifyASN1(pub, hash, signature)
}

func VerifyIntegrity(contract ContractData) bool {
    copyData := contract
    copyData.Integrity = Integrity{}
    hash := ComputeHash(copyData)
    return fmt.Sprintf("%x", hash) == contract.Integrity.DataHash
}
