# privacy-pump-arcium-example

> **Maturity:** Educational devnet example  
> **Supported network:** Localnet and devnet  
> **Audit status:** Publication is not an audit. No external audit is claimed.

Minimal educational Arcium private-authorization example for Solana developers.

## Purpose

Demonstrates the deterministic bindings required around an isolated Arcium authorization computation, callback, and receipt lifecycle without production operator dependencies.

## Scope

- Pure TypeScript request and receipt model
- Arcium queue and callback binding model
- Deterministic authorized, unauthorized, mismatch, and domain tests

## Architecture

```mermaid
flowchart LR
  User[Wallet or integrator] --> Interface[Public interface]
  Interface --> Boundary[Privacy Pump trust boundary]
  Boundary --> Chain[Solana or local reference]
  Boundary -. metadata exposure .-> Limits[Documented limitations]
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for component boundaries and assumptions.

## Current security status

- Experimental or reference material; not mainnet-ready.
- The inspected devnet programs are upgradeable and shared one upgrade authority at the publication audit date.
- Factory and relayer are distinct protocol roles, but a deployment may configure one signer for both.
- Production signer topology is intentionally not published.
- The ZK Pool vault-creation fee receipt does not independently bind its signer named `factory` to the Private Vault config factory; that boundary is under review.
- The ZK verifier path is fail-closed by default and is not a complete production privacy system.
- Browser, RPC, relayer, database, Waku/Logos, and Arcium metadata each have separate privacy limitations.
- Custom cryptographic glue is not described as audited.

Read [SECURITY.md](SECURITY.md) before using any material.

## Dependencies

- Node.js
- TypeScript test tooling

## Local setup

Use deterministic fixtures and ephemeral local keys only. No production credentials, cloud accounts, private RPC endpoints, or real wallet relationships are required.

```text
node scripts/policy-scan.mjs

```

```text
npm install
npm test
npm run typecheck
```

The on-chain Rust example is intentionally not included in this initial release because it requires generated confidential-instruction artifacts to compile independently.

## Roadmap

- [ ] Keep bindings aligned with public vectors
- [ ] Add localnet-first walkthrough
- [ ] Document Arcium trust assumptions

## Related Privacy Pump repositories

- No public runtime repository dependency.

## Known limitations

- Public content omits production relayer, access-control, KMS, Supabase service-role, keeper-signing, monitoring, and deployment implementations.
- Privacy depends on more than user-interface masking; metadata visible to wallets, RPCs, relayers, transports, and infrastructure remains relevant.
- Interfaces may change while the devnet architecture is stabilized.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensing is under review; see [LICENSE_STATUS.md](LICENSE_STATUS.md).
