import { createHash } from "crypto";
import { readFileSync } from "fs";
import { buildEddsa } from "circomlibjs";
import { groth16 } from "snarkjs";

const ARTIFACTS_BASE = "https://artifacts.api.zeroverify.net";
const API_BASE = process.env.REVOCATION_API ?? "https://gw.api.zeroverify.net";
const CIRCUIT = "credential_revocation";
const BABY_JUB_SUB_ORDER = BigInt(
  "2736030358979909402780800718157159386076813972158567259200215660948447373041"
);

function fieldElement(value: string): bigint {
  const hash = createHash("sha256").update(value, "utf8").digest();
  return BigInt("0x" + hash.toString("hex")) % BABY_JUB_SUB_ORDER;
}

async function fetchBytes(url: string): Promise<Uint8Array> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function fetchJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return res.json();
}

function loadCredential(path: string) {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  return raw.credential ?? raw;
}

async function main() {
  const credPath = process.argv[2] ?? "/tmp/credential.json";
  const cred = loadCredential(credPath);

  const credentialID = (cred.id as string).replace("urn:uuid:", "");
  const subjectID = cred.credentialSubject.id as string;
  const revocationSigB64 = cred.proof.circuitSignatures?.credential_revocation as string;

  if (!credentialID || !subjectID || !revocationSigB64) {
    throw new Error("credential missing required fields");
  }

  const { publicKeyHex } = await fetchJSON<{ publicKeyHex: string }>(
    `${ARTIFACTS_BASE}/issuer/public-key.json`
  );

  const eddsa = await buildEddsa();
  const F = eddsa.F;

  const pubKeyBytes = Buffer.from(publicKeyHex, "hex");
  const pubKey = eddsa.babyJub.unpackPoint(pubKeyBytes);
  const ax = F.toObject(pubKey[0]).toString();
  const ay = F.toObject(pubKey[1]).toString();

  const sig = eddsa.unpackSignature(Buffer.from(revocationSigB64, "base64"));
  const r8x = F.toObject(sig.R8[0]).toString();
  const r8y = F.toObject(sig.R8[1]).toString();
  const s = sig.S.toString();

  const credentialIDFE = fieldElement(credentialID).toString();

  const inputs = {
    credential_id: credentialIDFE,
    Ax: ax,
    Ay: ay,
    field_hash: credentialIDFE,
    R8x: r8x,
    R8y: r8y,
    S: s,
  };

  console.error("==> Downloading circuit artifacts...");
  const wasm = await fetchBytes(`${ARTIFACTS_BASE}/circuit/${CIRCUIT}/circuit.wasm`);
  const zkey = await fetchBytes(`${ARTIFACTS_BASE}/circuit/${CIRCUIT}/proving_key.zkey`);

  console.error("==> Generating ZK proof...");
  const { proof } = await groth16.fullProve(
    inputs,
    { type: "mem", data: wasm },
    { type: "mem", data: zkey }
  );

  console.error("==> Revoking credential...");
  const res = await fetch(`${API_BASE}/api/v1/credentials/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      credentialId: credentialID,
      subjectId: subjectID,
      proofJson: proof,
    }),
  });

  if (res.status !== 202) {
    const body = await res.text();
    throw new Error(`API returned ${res.status}: ${body}`);
  }

  console.log("Credential revoked successfully.");
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
