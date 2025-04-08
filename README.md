# DrainGuardRugpullDetector 
> Custom Detector for Venn Network — designed to flag smart contracts with high rugpull potential at the moment of deployment.

## Overview
Rugpulls remain one of the most devastating and common scams in Web3 — often hidden in plain sight through centralized withdrawals, emergency stops, or even literal `rug()` functions. This detector provides **preemptive protection** by analyzing deployed smart contracts for high-risk behaviors and design patterns before users interact with them.

## What It Detects
This detector scans contract creation transactions and flags any that include:

| Suspicious Behavior                  | Description |
|-------------------------------------|-------------|
| `withdrawAll()`, `emergencyWithdraw()` | Centralized access to user funds |
| `selfdestruct(address)`         | Potential for contract deletion by dev |
| `emergencyStop()`               | Admin-controlled fund freezing |
| `owner()` / `onlyOwner` patterns | Single-actor fund access |
| `rug()` or similar-named functions | Literal rugpull intent |

## How It Works
1. Listens for new contract deployment transactions.
2. Analyzes the raw bytecode and input data of the transaction.
3. Matches known suspicious function selectors (hex-encoded).
4. If one or more are detected, generates a high-severity alert.

## Tech Stack
- `forta-agent`
- `ethers.js`
- Venn `venn-custom-detection` framework

## Testing
Includes a full suite of unit tests covering:
- Normal contract creation (no false positives)
- Detection of single and multiple suspicious functions
- Contract creations with embedded `rug()` calls
- Ignores non-contract txs

To run tests: 
```bash
npm run test
```
![Alt text](https://github.com/GarbhitSh/DrainGuardRugpullDetector/blob/main/djb.png)
## Example Alert
```json
{
  "name": "Rugpull Risk Detected",
  "description": "Contract creation includes suspicious functions: rug(), selfdestruct(address)",
  "alertId": "VENN-RUGPULL-1",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "creator": "0x123...",
    "contractAddress": "0xabc...",
    "suspiciousFunctions": "rug(), selfdestruct(address)"
  }
}
```

## Real-World Impact
This detector could have pre-flagged several major rugpulls in DeFi history:
- Squid Game Token: had withdrawal gating + centralized kill switch
- FegX, YAM V1: included destructible logic paths
- Countless meme rugpulls that embed rug() directly

## Why It Matters
- Prevents user damage before it happens
- Low compute cost, high risk-reduction impact
- Can be extended with on-chain simulation and ML for deeper detection

## Project Structure
```bash
venn-custom-detection/
├── src/
│   └── DrainGuardRugpullDetector.ts
├── tests/
│   └── DrainGuardRugpullDetector.test.ts
├── README.md
└── submit_build.md
```
