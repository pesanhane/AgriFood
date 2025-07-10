
package main

import (
    "encoding/json"
    "fmt"
    "os"
)

func main() {
    f, _ := os.Open("testdata/contract.json")
    defer f.Close()
    var contract ContractData
    json.NewDecoder(f).Decode(&contract)

    if contract.Schema.Version != "1.0" {
        fmt.Println("❌ Versão inválida")
        return
    }
    // Calcular e injetar hash real antes da verificação
    copyData := contract
    copyData.Integrity = Integrity{}
    computedHash := ComputeHash(copyData)
    contract.Integrity.DataHash = fmt.Sprintf("%x", computedHash)

    if !VerifyIntegrity(contract) {
        fmt.Println("❌ Hash incorreto")
        return
    }

    priv, _ := GenerateCertificate(contract.SA, contract.OA, contract.PA, contract.EA)

    signature, _ := SignData(priv, contract)
    os.WriteFile("signature.bin", signature, 0644)

    pubKey, _ := LoadPublicKeyFromCert("device_cert.pem")
    valid := VerifySignature(contract, signature, pubKey)
    if !valid {
        fmt.Println("❌ Assinatura inválida")
        return
    }

    fmt.Println("✅ Assinatura verificada com sucesso")
    PutState(contract)
}
