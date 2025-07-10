package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Estrutura dos atributos ABAC usados na sessão
type ABACAttributes struct {
    Subject     SA   `json:"SA"`
    Object      OA   `json:"OA"`
    Policy      int  `json:"PA"`
    Environment EA   `json:"EA"`
}


type Session struct {
    Token       string
    Attributes  ABACAttributes
    ExpiresAt   time.Time
    SignatureR  *big.Int
    SignatureS  *big.Int
    PublicKey   *ecdsa.PublicKey
}

var (
    sessionStore = make(map[string]Session)
    mu           sync.Mutex
    sessionTTL   = 15 * time.Minute
)

// Cria uma sessão com assinatura ECDSA dos dados ABAC
func CreateSignedSession(attr ABACAttributes) (string, error) {
    mu.Lock()
    defer mu.Unlock()

    token := uuid.New().String()
    dataBytes, _ := json.Marshal(attr)

    // Gerar chave temporária ECDSA para assinar atributos
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return "", err
    }

    r, s, err := ecdsa.Sign(rand.Reader, privKey, dataBytes)
    if err != nil {
        return "", err
    }

    session := Session{
        Token:      token,
        Attributes: attr,
        ExpiresAt:  time.Now().Add(sessionTTL),
        SignatureR: r,
        SignatureS: s,
        PublicKey:  &privKey.PublicKey,
    }

    sessionStore[token] = session
    return token, nil
}

// Valida a sessão e a assinatura ECDSA dos atributos
func ValidateSignedSession(token string) bool {
    mu.Lock()
    defer mu.Unlock()

    sess, exists := sessionStore[token]
    if !exists {
        return false
    }

    if time.Now().After(sess.ExpiresAt) {
        delete(sessionStore, token)
        return false
    }

    dataBytes, _ := json.Marshal(sess.Attributes)
    valid := ecdsa.Verify(sess.PublicKey, dataBytes, sess.SignatureR, sess.SignatureS)

    return valid
}
