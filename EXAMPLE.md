# Example lifecycle

1. Create a request bound to deterministic test commitments and an action hash.
2. Model an encrypted boolean computation result.
3. Apply the callback result to the pending request.
4. Validate request, commitment, action, domain, and result bindings.

The checked-in TypeScript binding model can be tested without a network. The initial public release deliberately omits the on-chain workspace because compiling it requires generated confidential-instruction artifacts. A future reviewed release may restore the Rust example with a reproducible, public-safe generator.
