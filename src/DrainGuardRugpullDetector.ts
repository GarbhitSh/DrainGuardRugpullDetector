import {
    Finding,
    FindingSeverity,
    FindingType,
    HandleTransaction,
    TransactionEvent,
    getEthersProvider,
  } from "forta-agent";
  import { ethers } from "ethers";
  
  // Common suspicious function signatures (hex encoded)
  const suspiciousSignatures = [
    ethers.utils.id("rug()").slice(0, 10),                      // rug()
    ethers.utils.id("withdrawAll()").slice(0, 10),              // withdrawAll()
    ethers.utils.id("emergencyWithdraw()").slice(0, 10),        // emergencyWithdraw()
    ethers.utils.id("selfdestruct(address)").slice(0, 10),      // selfdestruct
    ethers.utils.id("emergencyStop()").slice(0, 10),            // emergency stop
    ethers.utils.id("owner()").slice(0, 10),                    // owner function
  ];
  
  const handleTransaction: HandleTransaction = async (
    txEvent: TransactionEvent
  ) => {
    const findings: Finding[] = [];
  
    // Only monitor contract creations
    if (!txEvent.to) {
      const code = await getEthersProvider().getCode(txEvent.transaction.creates!);
  
      // Basic heuristic: check if any known rugpull function signatures exist in input data
      const detected = suspiciousSignatures.filter(sig =>
        txEvent.transaction.data.includes(sig)
      );
  
      if (detected.length > 0) {
        findings.push(
          Finding.fromObject({
            name: "Rugpull Risk Detected",
            description: `Contract creation includes suspicious functions: ${detected.join(", ")}`,
            alertId: "VENN-RUGPULL-1",
            type: FindingType.Suspicious,
            severity: FindingSeverity.High,
            protocol: "ethereum",
            metadata: {
              creator: txEvent.from,
              contractAddress: txEvent.transaction.creates || "unknown",
              suspiciousFunctions: detected.join(", "),
            },
          })
        );
      }
    }
  
    return findings;
  };
  
  export default {
    handleTransaction,
  };
  