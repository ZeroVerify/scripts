declare module "circomlibjs" {
  interface Eddsa {
    F: {
      toObject(x: unknown): bigint;
    };
    babyJub: {
      unpackPoint(buf: Buffer): [unknown, unknown];
    };
    unpackSignature(buf: Buffer): { R8: [unknown, unknown]; S: bigint };
  }
  export function buildEddsa(): Promise<Eddsa>;
}

declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: Record<string, string>,
      wasm: { type: "mem"; data: Uint8Array } | string,
      zkey: { type: "mem"; data: Uint8Array } | string
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
  };
}
