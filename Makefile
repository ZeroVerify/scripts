REGION       ?= us-east-1
BUCKET       ?= zeroverify-artifacts
ARTIFACTS_URL ?= https://artifacts.api.zeroverify.net

.PHONY: issue-credential verify-credential inspect-bitstring revoke-credential

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
		--public-key-hex $$(curl -sf $(ARTIFACTS_URL)/issuer/public-key.json | jq -r .publicKeyHex)

revoke-credential:
	cd scripts/revoke-credential && npm run revoke -- $(CREDENTIAL)

.PHONY: test
test:
	./scripts/issue-credential.sh | tee /tmp/credential.json | jq .
	cd scripts/verify-credential && go run . \
		--credential /tmp/credential.json \
		--public-key-hex $$(curl -sf $(ARTIFACTS_URL)/issuer/public-key.json | jq -r .publicKeyHex)
	@echo ""
	@printf "Credential issued and verified. Press Enter to revoke..."; read ans < /dev/tty
	@echo ""
	cd scripts/revoke-credential && npm run revoke
