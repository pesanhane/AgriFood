
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "time"
)

func GenerateCertificate(sa SA, oa OA, pa int, ea EA) (*ecdsa.PrivateKey, error) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }

    abacData := map[string]interface{}{
        "SA": sa,
        "OA": oa,
        "PA": pa,
        "EA": ea,
    }
    abacBytes, _ := json.Marshal(abacData)

    abacExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1},
        Critical: false,
        Value:    abacBytes,
    }

    template := x509.Certificate{
        SerialNumber: big.NewInt(2025),
        Subject: pkix.Name{
            CommonName:   sa.DeviceID,
            Organization: []string{"AgroDevice Co"},
        },
        NotBefore:       time.Now(),
        NotAfter:        time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtraExtensions: []pkix.Extension{abacExtension},
    }

    certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil {
        return nil, err
    }

    certOut, _ := os.Create("device_cert.pem")
    defer certOut.Close()
    pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

    keyOut, _ := os.Create("device_key.pem")
    defer keyOut.Close()
    privBytes, _ := x509.MarshalECPrivateKey(priv)
    pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

    fmt.Println("✔ Certificado e chave privada salvos")
    return priv, nil
}
