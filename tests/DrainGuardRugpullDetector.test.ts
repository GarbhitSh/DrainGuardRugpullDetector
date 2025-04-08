import { createTransactionEvent, TestTransactionEvent } from "forta-agent-tools/lib/tests";
import { FindingSeverity, FindingType } from "forta-agent";
import { ethers } from "ethers";
import detector from "../src/DrainGuardRugpullDetector";

describe("DrainGuardRugpullDetector", () => {
  it("should not return any findings for normal contract creation", async () => {
    const txEvent: TestTransactionEvent = new TestTransactionEvent()
      .setFrom("0xcreator")
      .setTo(null) // Indicates contract creation
      .setTransaction({
        data: "0x6080604052", // Generic bytecode prefix
        creates: "0xcontract",
        from: "0xcreator",
        to: null,
      });

    const findings = await detector.handleTransaction(txEvent);
    expect(findings).toEqual([]);
  });

  it("should trigger for contract with suspicious function: rug()", async () => {
    const rugSelector = ethers.utils.id("rug()").slice(0, 10);
    const txEvent: TestTransactionEvent = new TestTransactionEvent()
      .setFrom("0xcreator")
      .setTo(null)
      .setTransaction({
        data: "0x6080604052" + rugSelector + "abcdef", // Contains rug()
        creates: "0xcontract",
        from: "0xcreator",
        to: null,
      });

    const findings = await detector.handleTransaction(txEvent);
    expect(findings.length).toBe(1);
    expect(findings[0].alertId).toBe("VENN-RUGPULL-1");
    expect(findings[0].metadata.suspiciousFunctions).toContain(rugSelector);
  });

  it("should trigger for multiple suspicious signatures", async () => {
    const selector1 = ethers.utils.id("rug()").slice(0, 10);
    const selector2 = ethers.utils.id("withdrawAll()").slice(0, 10);
    const txEvent: TestTransactionEvent = new TestTransactionEvent()
      .setFrom("0xcreator")
      .setTo(null)
      .setTransaction({
        data: "0x" + selector1.slice(2) + selector2.slice(2),
        creates: "0xcontract",
        from: "0xcreator",
        to: null,
      });

    const findings = await detector.handleTransaction(txEvent);
    expect(findings.length).toBe(1);
    expect(findings[0].metadata.suspiciousFunctions).toContain(selector1);
    expect(findings[0].metadata.suspiciousFunctions).toContain(selector2);
  });

  it("should ignore non-contract-creation txs", async () => {
    const txEvent: TestTransactionEvent = new TestTransactionEvent()
      .setFrom("0xsender")
      .setTo("0xreceiver")
      .setTransaction({
        data: "0x",
        from: "0xsender",
        to: "0xreceiver",
      });

    const findings = await detector.handleTransaction(txEvent);
    expect(findings).toEqual([]);
  });
});
