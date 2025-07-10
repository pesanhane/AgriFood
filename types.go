
package main

import "time"

type Unit struct {
    Symbol, Name, SIEquivalent string
}

type Range struct {
    MinValue, MaxValue float64
}

type Metric struct {
    MetricID, PhysicalQuantity string
    Unit                       Unit
    Range                      Range
}

type Material struct {
    Name, Description string
}

type SA struct {
    OwnerID, DeviceID, MACAddress, ContactType, Type           string
    OwnerPublicKey, DevicePublicKey, DeviceCertificateID       string
    Material                                                   Material
    Metric                                                     Metric
}

type BodyType struct {
    Type     string
    MaxDepth int
}

type OA struct {
    BodyID, Name, Description, Location string
    BodyType                            BodyType
}

type Coordinates struct {
    Latitude, Longitude float64
}

type EA struct {
    StartDateTime, EndDateTime time.Time
    TimeZone                   string
    LimitDistance              int
    SamplingRate               string
    ReferenceCoordinates       Coordinates
}

type Integrity struct {
    HashAlgorithm, DataHash string
}

type Audit struct {
    TimestampCreated, TimestampUpdated time.Time
    ModifiedBy                         string
}

type Signatures struct {
    OwnerSignature, DeviceSignature string
}

type Contract struct {
    ContractID, RequestID string
}

type Schema struct {
    Name, Version, Uri string
}

type ContractData struct {
    Schema     Schema
    SA         SA
    OA         OA
    PA         int
    EA         EA
    Integrity  Integrity
    Audit      Audit
    Signatures Signatures
    Contract   Contract
    Scope      struct {
        Region, Environment string
    }
    Purpose string
}
