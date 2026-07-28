import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  applyCallbackResult,
  authorizationHash,
  bindingDigest32,
  bytes32,
  type PrivateAuthorizationRequestModel,
} from "../client/proof-bindings.ts";

function pendingRequest(): PrivateAuthorizationRequestModel {
  return {
    requestKey: bytes32(9),
    requestId: 42n,
    authorityCommitment: bytes32(7),
    actionHash: bytes32(3),
    expectedDomain: 1n,
    computationOffset: 99n,
    status: "pending",
  };
}

describe("Privacy Pump private authorization bindings", () => {
  it("creates stable binding digests from 32 byte values", () => {
    const value = Uint8Array.from(
      Array.from({ length: 32 }, (_, index) => index),
    );

    assert.equal(bindingDigest32(value), 0x0f0e0d0c0b0a09080706050403020100n);
  });

  it("writes a verified receipt after a valid authorized callback result", () => {
    const request = pendingRequest();
    const receipt = applyCallbackResult(request, {
      authorized: true,
      requestId: request.requestId,
      authorityCommitmentDigest: bindingDigest32(request.authorityCommitment),
      actionHashDigest: bindingDigest32(request.actionHash),
      expectedDomain: request.expectedDomain,
    });

    assert.equal(receipt.status, "verified");
    assert.equal(receipt.authorized, true);
    assert.deepEqual(
      receipt.authorizationHash,
      authorizationHash({
        requestKey: request.requestKey,
        requestId: request.requestId,
        authorityCommitment: request.authorityCommitment,
        actionHash: request.actionHash,
        expectedDomain: request.expectedDomain,
        computationOffset: request.computationOffset,
        authorized: true,
      }),
    );
  });

  it("does not mark unauthorized result as verified", () => {
    const request = pendingRequest();
    const receipt = applyCallbackResult(request, {
      authorized: false,
      requestId: request.requestId,
      authorityCommitmentDigest: bindingDigest32(request.authorityCommitment),
      actionHashDigest: bindingDigest32(request.actionHash),
      expectedDomain: request.expectedDomain,
    });

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.authorized, false);
  });

  it("rejects callback for wrong request binding", () => {
    assert.throws(
      () =>
        applyCallbackResult(pendingRequest(), {
          authorized: true,
          requestId: 41n,
          authorityCommitmentDigest: bindingDigest32(bytes32(7)),
          actionHashDigest: bindingDigest32(bytes32(3)),
          expectedDomain: 1n,
        }),
      /request binding mismatch/,
    );
  });

  it("rejects callback for wrong action hash binding", () => {
    const request = pendingRequest();
    assert.throws(
      () =>
        applyCallbackResult(request, {
          authorized: true,
          requestId: request.requestId,
          authorityCommitmentDigest: bindingDigest32(
            request.authorityCommitment,
          ),
          actionHashDigest: bindingDigest32(bytes32(4)),
          expectedDomain: request.expectedDomain,
        }),
      /action binding mismatch/,
    );
  });

  it("rejects callback for wrong authority commitment binding", () => {
    const request = pendingRequest();
    assert.throws(
      () =>
        applyCallbackResult(request, {
          authorized: true,
          requestId: request.requestId,
          authorityCommitmentDigest: bindingDigest32(bytes32(8)),
          actionHashDigest: bindingDigest32(request.actionHash),
          expectedDomain: request.expectedDomain,
        }),
      /authority binding mismatch/,
    );
  });

  it("rejects callback for wrong domain binding", () => {
    const request = pendingRequest();
    assert.throws(
      () =>
        applyCallbackResult(request, {
          authorized: true,
          requestId: request.requestId,
          authorityCommitmentDigest: bindingDigest32(
            request.authorityCommitment,
          ),
          actionHashDigest: bindingDigest32(request.actionHash),
          expectedDomain: 2n,
        }),
      /domain binding mismatch/,
    );
  });

  it("documents pending state if compute is not finalized", () => {
    const request = pendingRequest();

    assert.equal(request.status, "pending");
  });
});
