import { createHash } from "node:crypto";

export type AuthorizationStatus = "created" | "pending" | "verified" | "failed";

export type PrivateAuthorizationRequestModel = {
  requestKey: Uint8Array;
  requestId: bigint;
  authorityCommitment: Uint8Array;
  actionHash: Uint8Array;
  expectedDomain: bigint;
  computationOffset: bigint;
  status: AuthorizationStatus;
};

export type PrivateAuthorizationReceiptModel = {
  requestId: bigint;
  authorizationHash: Uint8Array;
  authorized: boolean;
  status: AuthorizationStatus;
};

export function bindingDigest32(value: Uint8Array): bigint {
  assertLength(value, 32, "binding value");
  let result = 0n;
  for (let index = 15; index >= 0; index -= 1) {
    result = (result << 8n) + BigInt(value[index]);
  }
  return result;
}

export function u64Le(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`u64 value out of range: ${value}`);
  }
  const bytes = new Uint8Array(8);
  let remaining = value;
  for (let index = 0; index < 8; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

export function authorizationHash(input: {
  requestKey: Uint8Array;
  requestId: bigint;
  authorityCommitment: Uint8Array;
  actionHash: Uint8Array;
  expectedDomain: bigint;
  computationOffset: bigint;
  authorized: boolean;
}): Uint8Array {
  assertLength(input.requestKey, 32, "request key");
  assertLength(input.authorityCommitment, 32, "authority commitment");
  assertLength(input.actionHash, 32, "action hash");

  return createHash("sha256")
    .update("privacy-pump-private-authorization")
    .update(input.requestKey)
    .update(u64Le(input.requestId))
    .update(input.authorityCommitment)
    .update(input.actionHash)
    .update(u64Le(input.expectedDomain))
    .update(u64Le(input.computationOffset))
    .update(Uint8Array.of(input.authorized ? 1 : 0))
    .digest();
}

export function applyCallbackResult(
  request: PrivateAuthorizationRequestModel,
  result: {
    authorized: boolean;
    requestId: bigint;
    authorityCommitmentDigest: bigint;
    actionHashDigest: bigint;
    expectedDomain: bigint;
  },
): PrivateAuthorizationReceiptModel {
  if (request.status !== "pending") {
    throw new Error("private authorization request is not pending");
  }
  if (result.requestId !== request.requestId) {
    throw new Error("request binding mismatch");
  }
  if (
    result.authorityCommitmentDigest !==
    bindingDigest32(request.authorityCommitment)
  ) {
    throw new Error("authority binding mismatch");
  }
  if (result.actionHashDigest !== bindingDigest32(request.actionHash)) {
    throw new Error("action binding mismatch");
  }
  if (result.expectedDomain !== request.expectedDomain) {
    throw new Error("domain binding mismatch");
  }

  return {
    requestId: request.requestId,
    authorizationHash: authorizationHash({
      requestKey: request.requestKey,
      requestId: request.requestId,
      authorityCommitment: request.authorityCommitment,
      actionHash: request.actionHash,
      expectedDomain: request.expectedDomain,
      computationOffset: request.computationOffset,
      authorized: result.authorized,
    }),
    authorized: result.authorized,
    status: result.authorized ? "verified" : "failed",
  };
}

export function bytes32(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

function assertLength(
  value: Uint8Array,
  expected: number,
  label: string,
): void {
  if (value.length !== expected) {
    throw new Error(`${label} must be ${expected} bytes, got ${value.length}`);
  }
}
