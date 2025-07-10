
package main

import (
    "encoding/json"
    "fmt"
    "os"
)

func PutState(contract ContractData) error {
    f, err := os.Create("blockchain.json")
    if err != nil {
        return err
    }
    defer f.Close()
    json.NewEncoder(f).Encode(contract)
    fmt.Println("✔ Contrato armazenado em blockchain.json")
    return nil
}
