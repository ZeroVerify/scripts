// generate-issuer-keys generates a BabyJubJub key pair and an HMAC key,
// stores the private keys in AWS Secrets Manager, and publishes the
// BabyJubJub public key to the S3 artifacts bucket.
//
// Usage:
//
//	go run ./scripts/generate-issuer-keys \
//	  --region us-east-1 \
//	  --bucket zeroverify-artifacts \
//	  --hmac-secret zeroverify/hmac-key \
//	  --eddsa-secret zeroverify/baby-jubjub-private-key
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

func main() {
	region := flag.String("region", "us-east-1", "AWS region")
	bucket := flag.String("bucket", "zeroverify-artifacts", "S3 artifacts bucket name")
	hmacSecret := flag.String("hmac-secret", "zeroverify/hmac-key", "Secrets Manager secret name for HMAC key")
	eddsaSecret := flag.String("eddsa-secret", "zeroverify/baby-jubjub-private-key", "Secrets Manager secret name for BabyJubJub private key")
	flag.Parse()

	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(*region))
	if err != nil {
		log.Fatalf("loading AWS config: %v", err)
	}

	// Generate BabyJubJub key pair
	log.Println("Generating BabyJubJub key pair...")
	privKey := babyjub.NewRandPrivKey()
	pubKey := privKey.Public()
	compressed := pubKey.Compress()

	// Generate HMAC key (32 random bytes)
	log.Println("Generating HMAC key...")
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		log.Fatalf("generating HMAC key: %v", err)
	}

	// Store private keys in Secrets Manager
	sm := secretsmanager.NewFromConfig(cfg)

	log.Printf("Storing HMAC key in Secrets Manager (%s)...", *hmacSecret)
	if err := putSecret(ctx, sm, *hmacSecret, hmacKey); err != nil {
		log.Fatalf("storing HMAC key: %v", err)
	}

	log.Printf("Storing BabyJubJub private key in Secrets Manager (%s)...", *eddsaSecret)
	if err := putSecret(ctx, sm, *eddsaSecret, privKey[:]); err != nil {
		log.Fatalf("storing BabyJubJub private key: %v", err)
	}

	// Publish public key to S3
	pubKeyJSON, err := json.MarshalIndent(map[string]string{
		"type":         "BabyJubJub",
		"publicKeyHex": fmt.Sprintf("%x", compressed[:]),
	}, "", "  ")
	if err != nil {
		log.Fatalf("marshalling public key: %v", err)
	}

	log.Printf("Publishing public key to s3://%s/issuer/public-key.json...", *bucket)
	s3Client := s3.NewFromConfig(cfg)
	if _, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(*bucket),
		Key:         aws.String("issuer/public-key.json"),
		Body:        bytes.NewReader(pubKeyJSON),
		ContentType: aws.String("application/json"),
	}); err != nil {
		log.Fatalf("uploading public key to S3: %v", err)
	}

	fmt.Println()
	fmt.Println("Done.")
	fmt.Printf("  HMAC key:        Secrets Manager → %s\n", *hmacSecret)
	fmt.Printf("  EdDSA key:       Secrets Manager → %s\n", *eddsaSecret)
	fmt.Printf("  Public key:      s3://%s/issuer/public-key.json\n", *bucket)
	fmt.Printf("  Public key hex:  %x\n", compressed[:])

	// Warn if stdout is a terminal — private key material was never written to disk
	if fi, _ := os.Stdout.Stat(); fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Println()
		fmt.Println("Private key material was never written to disk.")
	}
}

func putSecret(ctx context.Context, sm *secretsmanager.Client, name string, value []byte) error {
	_, err := sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(name),
		SecretBinary: value,
	})
	return err
}
