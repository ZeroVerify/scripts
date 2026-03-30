// verify-credential verifies the BabyJubJub field signatures on a ZeroVerify
// credential. It fetches the issuer public key from S3 and checks every field
// signature in the credential's proof.
//
// Usage:
//
//	go run . --credential credential.json
//	cat credential.json | go run . --credential -
//	go run . --credential credential.json --public-key-hex <hex>
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

type credential struct {
	Proof struct {
		FieldSignatures map[string]string `json:"fieldSignatures"`
	} `json:"proof"`
	CredentialSubject map[string]any `json:"credentialSubject"`
}

type response struct {
	Credential credential `json:"credential"`
}

func main() {
	credFile := flag.String("credential", "", "path to credential JSON file, or - for stdin")
	pubKeyHex := flag.String("public-key-hex", "", "issuer public key hex (from s3://zeroverify-artifacts/issuer/public-key.json)")
	flag.Parse()

	if *credFile == "" || *pubKeyHex == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Read credential
	var r io.Reader
	if *credFile == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(*credFile)
		if err != nil {
			log.Fatalf("opening credential: %v", err)
		}
		defer f.Close()
		r = f
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		log.Fatalf("parsing credential: %v", err)
	}

	var cred credential
	src := raw["credential"]
	if src == nil {
		// bare credential object (no wrapper)
		b, _ := json.Marshal(raw)
		src = b
	}
	if err := json.Unmarshal(src, &cred); err != nil {
		log.Fatalf("parsing credential object: %v", err)
	}

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(*pubKeyHex)
	if err != nil {
		log.Fatalf("decoding public key hex: %v", err)
	}
	if len(pubKeyBytes) != 32 {
		log.Fatalf("public key must be 32 bytes, got %d", len(pubKeyBytes))
	}
	var comp babyjub.PublicKeyComp
	copy(comp[:], pubKeyBytes)
	pubKey, err := comp.Decompress()
	if err != nil {
		log.Fatalf("decompressing public key: %v", err)
	}

	// Verify each field signature
	allOK := true
	for field, sigB64 := range cred.Proof.FieldSignatures {
		value, ok := fieldValue(cred.CredentialSubject, field)
		if !ok {
			fmt.Printf("  %-20s MISSING in credentialSubject\n", field)
			allOK = false
			continue
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			fmt.Printf("  %-20s INVALID base64: %v\n", field, err)
			allOK = false
			continue
		}
		if len(sigBytes) != 64 {
			fmt.Printf("  %-20s INVALID signature length: %d\n", field, len(sigBytes))
			allOK = false
			continue
		}

		var sigComp babyjub.SignatureComp
		copy(sigComp[:], sigBytes)
		sig, err := sigComp.Decompress()
		if err != nil {
			fmt.Printf("  %-20s INVALID signature: %v\n", field, err)
			allOK = false
			continue
		}

		msg := fieldElement(value)
		if pubKey.VerifyPoseidon(msg, sig) {
			fmt.Printf("  %-20s OK\n", field)
		} else {
			fmt.Printf("  %-20s FAIL\n", field)
			allOK = false
		}
	}

	fmt.Println()
	if allOK {
		fmt.Println("All signatures valid.")
	} else {
		fmt.Println("One or more signatures failed.")
		os.Exit(1)
	}
}

func fieldElement(value string) *big.Int {
	h := sha256.Sum256([]byte(value))
	n := new(big.Int).SetBytes(h[:])
	n.Mod(n, babyjub.SubOrder)
	return n
}

func fieldValue(subject map[string]any, field string) (string, bool) {
	v, ok := subject[field]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
