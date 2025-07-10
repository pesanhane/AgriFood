package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
    // ⚙️ Carrega o contrato
    f, _ := os.Open("testdata/contract.json")
    defer f.Close()
    var contract ContractData
    json.NewDecoder(f).Decode(&contract)

    // Verificação de versão
    if contract.Schema.Version != "1.0" {
        fmt.Println("❌ Versão inválida")
        return
    }

    // Hash de integridade
    copyData := contract
    copyData.Integrity = Integrity{}
    computedHash := ComputeHash(copyData)
    contract.Integrity.DataHash = fmt.Sprintf("%x", computedHash)

    if !VerifyIntegrity(contract) {
        fmt.Println("❌ Hash incorreto")
        return
    }

    // Verifica se já existe um token válido em cache
    tokenBytes, err := os.ReadFile("session_token.txt")
    var token string
    if err == nil {
        token = string(tokenBytes)
        if ValidateSignedSession(token) {
            fmt.Println("✅ Token válido encontrado. Usando para autenticação.")
            PutState(contract)
            return
        } else {
            fmt.Println("⚠️ Token expirado ou inválido. Renovando via certificado.")
        }
    }

    // 🔐 Autenticação com certificado + geração de token
    priv, _ := GenerateCertificate(contract.SA, contract.OA, contract.PA, contract.EA)
    signature, _ := SignData(priv, contract)
    os.WriteFile("signature.bin", signature, 0644)

    pubKey, _ := LoadPublicKeyFromCert("device_cert.pem")
    if !VerifySignature(contract, signature, pubKey) {
        fmt.Println("❌ Assinatura inválida")
        return
    }
    fmt.Println("✅ Assinatura verificada com sucesso")

    // Criar sessão e gerar novo token
    abacAttrs := ABACAttributes{
        Subject:     contract.SA,
        Object:      contract.OA,
        Policy:      contract.PA,
        Environment: contract.EA,
    }

    token, err = CreateSignedSession(abacAttrs)
    if err != nil {
        fmt.Println("❌ Erro ao criar sessão:", err)
        return
    }

    // Cacheia o token localmente
    os.WriteFile("session_token.txt", []byte(token), 0644)
    fmt.Println("✅ Novo token gerado:", token)

    // Envio de dados com token válido
    PutState(contract)
}
