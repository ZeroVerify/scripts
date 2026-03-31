REGION  ?= us-east-1
BUCKET  ?= zeroverify-artifacts

.PHONY: issue-credential verify-credential inspect-bitstring

generate-issuer-keys:
	@echo "WARNING: This will overwrite existing private keys in Secrets Manager."
	@echo "Type 'yes' to continue: "; read ans; [ "$$ans" = "yes" ] || (echo "Aborted."; exit 1)
	cd scripts/generate-issuer-keys && go run . \
		--region $(REGION) \
		--bucket $(BUCKET)

inspect-bitstring:
	./scripts/inspect-bitstring.sh s3://$(BUCKET)/bitstring/v1/bitstring.gz

issue-credential:
	./scripts/issue-credential.sh | tee /tmp/credential.json | jq .

verify-credential:
	cd scripts/verify-credential && go run . \
		--credential $(CREDENTIAL) \
		--public-key-hex $(PUBLIC_KEY_HEX)

.PHONY: test
test:
	./scripts/issue-credential.sh | tee /tmp/credential.json | jq .
	cd scripts/verify-credential && go run . \
		--credential /tmp/credential.json \
		--public-key-hex $$(aws s3 cp s3://$(BUCKET)/issuer/public-key.json - | jq -r .publicKeyHex)
