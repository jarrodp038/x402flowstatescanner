import express from "express";
import { paymentMiddleware } from "x402-express";
import { facilitator } from "@coinbase/x402";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

// ===========================================
// CONFIGURATION
// ===========================================
const WALLET_ADDRESS = process.env.WALLET_ADDRESS;
const PORT = process.env.PORT || 4021;
const NETWORK = process.env.NETWORK || "base-sepolia";

if (!WALLET_ADDRESS) {
  console.error(
    "\n❌ FATAL: WALLET_ADDRESS environment variable is required.\n" +
      "Set it in your .env file or deployment environment.\n"
  );
  process.exit(1);
}

if (!/^0x[a-fA-F0-9]{40}$/.test(WALLET_ADDRESS)) {
  console.error(
    "\n❌ FATAL: WALLET_ADDRESS is not a valid Ethereum address.\n" +
      `Got: ${WALLET_ADDRESS}\n`
  );
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "500kb" }));

// ===========================================
// x402 PAYMENT MIDDLEWARE
// Uses @coinbase/x402 facilitator which handles
// CDP auth automatically via CDP_API_KEY_ID and
// CDP_API_KEY_SECRET environment variables
// ===========================================
app.use(
  paymentMiddleware(
    WALLET_ADDRESS,
    {
      "POST /api/scan/quick": {
        price: "$0.05",
        network: NETWORK,
        config: {
          description:
            "Quick vulnerability scan for Solidity smart contracts. Detects reentrancy, tx.origin, unchecked calls, floating pragma, and more.",
          discoverable: true,
          category: "security",
          tags: [
            "solidity",
            "smart-contract",
            "audit",
            "security",
            "ethereum",
            "blockchain",
          ],
          inputSchema: {
            type: "object",
            properties: {
              code: {
                type: "string",
                description: "Solidity source code to scan",
              },
              contractName: {
                type: "string",
                description: "Name of the contract (optional)",
              },
            },
            required: ["code"],
          },
          outputSchema: {
            type: "object",
            properties: {
              success: { type: "boolean" },
              summary: {
                type: "object",
                properties: {
                  riskScore: { type: "number" },
                  riskLevel: { type: "string" },
                  totalIssues: { type: "number" },
                },
              },
              vulnerabilities: { type: "array" },
            },
          },
        },
      },

      "POST /api/scan/deep": {
        price: "$0.50",
        network: NETWORK,
        config: {
          description:
            "Comprehensive smart contract security audit with gas optimization, best practice analysis, and prioritized recommendations.",
          discoverable: true,
          category: "security",
          tags: [
            "solidity",
            "audit",
            "security",
            "gas-optimization",
            "defi",
          ],
          inputSchema: {
            type: "object",
            properties: {
              code: {
                type: "string",
                description: "Solidity source code to audit",
              },
              contractName: { type: "string", description: "Contract name" },
              includeGasAnalysis: {
                type: "boolean",
                description: "Include gas optimization (default: true)",
              },
            },
            required: ["code"],
          },
        },
      },

      "POST /api/compare": {
        price: "$0.10",
        network: NETWORK,
        config: {
          description:
            "Compare two smart contracts to identify security differences, new vulnerabilities, and fixed issues.",
          discoverable: true,
          category: "security",
          tags: ["solidity", "diff", "compare", "audit"],
          inputSchema: {
            type: "object",
            properties: {
              codeA: {
                type: "string",
                description: "First contract source code",
              },
              codeB: {
                type: "string",
                description: "Second contract source code",
              },
              nameA: { type: "string", description: "Name of first contract" },
              nameB: {
                type: "string",
                description: "Name of second contract",
              },
            },
            required: ["codeA", "codeB"],
          },
        },
      },

      "POST /api/report": {
        price: "$1.00",
        network: NETWORK,
        config: {
          description:
            "Generate a professional markdown security audit report suitable for investor due diligence.",
          discoverable: true,
          category: "security",
          tags: ["solidity", "audit", "report", "professional"],
          inputSchema: {
            type: "object",
            properties: {
              code: { type: "string", description: "Solidity source code" },
              contractName: { type: "string", description: "Contract name" },
              clientName: { type: "string", description: "Client name" },
              projectName: { type: "string", description: "Project name" },
            },
            required: ["code"],
          },
        },
      },
    },
    facilitator
  )
);

// ===========================================
// SECURITY SCANNING LOGIC
// ===========================================

function getVulnerabilityPatterns() {
  return [
    {
      id: "REENTRANCY",
      name: "Reentrancy Vulnerability",
      severity: "CRITICAL",
      pattern: /\.call\{[^}]*value[^}]*\}|\.call\.value\(/gi,
      description:
        "External calls before state changes can allow reentrancy attacks",
      recommendation:
        "Use checks-effects-interactions pattern or OpenZeppelin ReentrancyGuard",
    },
    {
      id: "TX_ORIGIN",
      name: "tx.origin Authentication",
      severity: "HIGH",
      pattern: /tx\.origin/gi,
      description:
        "Using tx.origin for authentication is vulnerable to phishing",
      recommendation: "Use msg.sender instead of tx.origin",
    },
    {
      id: "UNCHECKED_CALL",
      name: "Unchecked External Call",
      severity: "HIGH",
      pattern: /\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(/gi,
      description: "Low-level call return value not checked",
      recommendation: "Always check the return value of low-level calls",
    },
    {
      id: "SELFDESTRUCT",
      name: "Selfdestruct Present",
      severity: "MEDIUM",
      pattern: /selfdestruct\s*\(/gi,
      description: "Contract can be destroyed, potentially locking funds",
      recommendation: "Remove selfdestruct or add strict access controls",
    },
    {
      id: "BLOCK_TIMESTAMP",
      name: "Block Timestamp Dependence",
      severity: "LOW",
      pattern: /block\.timestamp/gi,
      description: "Miners can manipulate block.timestamp within ~15 seconds",
      recommendation:
        "Avoid using block.timestamp for critical logic like randomness",
    },
    {
      id: "FLOATING_PRAGMA",
      name: "Floating Pragma",
      severity: "LOW",
      pattern: /pragma\s+solidity\s+\^/gi,
      description: "Floating pragma allows different compiler versions",
      recommendation: "Lock pragma to a specific version (e.g., 0.8.24)",
    },
    {
      id: "MISSING_ZERO_CHECK",
      name: "Missing Zero Address Check",
      severity: "MEDIUM",
      pattern: /function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)/gi,
      description:
        "Functions accepting address parameters should validate against zero address",
      recommendation: "Add require(addr != address(0)) checks",
    },
    {
      id: "ARBITRARY_SEND",
      name: "Arbitrary ETH Send",
      severity: "HIGH",
      pattern: /\.transfer\s*\(|\.send\s*\(|\.call\{[^}]*value/gi,
      description: "ETH transfer to potentially arbitrary address",
      recommendation: "Validate recipients and use the withdrawal pattern",
    },
    {
      id: "UNPROTECTED_FUNC",
      name: "Potentially Unprotected State-Changing Function",
      severity: "MEDIUM",
      pattern:
        /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s+(?!view\b|pure\b)[^{]*\{/gi,
      description:
        "Public/external state-changing function — verify access control",
      recommendation: "Add onlyOwner or role-based access control",
    },
    {
      id: "OUTDATED_COMPILER",
      name: "Outdated Compiler Version",
      severity: "MEDIUM",
      pattern: /pragma\s+solidity\s+(?:\^?\s*)?0\.[0-6]\./gi,
      description: "Using outdated Solidity version with known issues",
      recommendation: "Upgrade to Solidity 0.8.x for built-in overflow checks",
    },
    {
      id: "UNCHECKED_MATH",
      name: "Unchecked Math Operations",
      severity: "MEDIUM",
      pattern: /unchecked\s*\{/gi,
      description: "Unchecked arithmetic blocks bypass overflow protection",
      recommendation:
        "Use unchecked blocks only when overflow is provably impossible",
    },
    {
      id: "ASSEMBLY_USAGE",
      name: "Inline Assembly Usage",
      severity: "INFO",
      pattern: /assembly\s*\{/gi,
      description: "Inline assembly bypasses Solidity safety features",
      recommendation: "Audit assembly code carefully and document its purpose",
    },
  ];
}

function getGasPatterns() {
  return [
    {
      id: "STORAGE_IN_LOOP",
      name: "Storage Read in Loop",
      pattern: /for\s*\([^)]*\)\s*\{[^}]*\b(storage|mapping)\b/gi,
      suggestion: "Cache storage variables in memory before the loop",
    },
    {
      id: "STRING_STORAGE",
      name: "String Storage",
      pattern: /string\s+(?:public|private|internal)\s+\w+\s*=/gi,
      suggestion: "Consider bytes32 for fixed-length strings to save gas",
    },
    {
      id: "MULTIPLE_SLOADS",
      name: "Multiple Storage Reads",
      pattern: /(\w+\.\w+)[\s\S]{1,200}?\1/gi,
      suggestion: "Cache repeated storage reads in a local variable",
    },
  ];
}

function scanContract(code) {
  const vulnerabilities = [];
  const lines = code.split("\n");

  for (const vuln of getVulnerabilityPatterns()) {
    const matches = code.match(
      new RegExp(vuln.pattern.source, vuln.pattern.flags)
    );

    if (matches) {
      const locations = [];
      for (let idx = 0; idx < lines.length; idx++) {
        if (
          new RegExp(vuln.pattern.source, vuln.pattern.flags).test(lines[idx])
        ) {
          locations.push(idx + 1);
        }
      }

      vulnerabilities.push({
        id: vuln.id,
        name: vuln.name,
        severity: vuln.severity,
        description: vuln.description,
        recommendation: vuln.recommendation,
        occurrences: matches.length,
        lines: locations.slice(0, 5),
      });
    }
  }

  return vulnerabilities;
}

function calculateRiskScore(vulnerabilities) {
  const weights = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 5, INFO: 1 };
  let score = 100;
  for (const vuln of vulnerabilities) {
    score -= (weights[vuln.severity] || 0) * vuln.occurrences;
  }
  return Math.max(0, Math.min(100, score));
}

function analyzeGas(code) {
  const suggestions = [];
  for (const p of getGasPatterns()) {
    if (new RegExp(p.pattern.source, p.pattern.flags).test(code)) {
      suggestions.push({ id: p.id, issue: p.name, suggestion: p.suggestion });
    }
  }
  return suggestions;
}

function getRiskLevel(score) {
  if (score >= 80) return "LOW";
  if (score >= 50) return "MEDIUM";
  if (score >= 20) return "HIGH";
  return "CRITICAL";
}

// ===========================================
// INPUT VALIDATION
// ===========================================
function validateSolidityInput(req, res, next) {
  const { code } = req.body || {};
  if (!code) {
    return res.status(400).json({
      error: "Missing required 'code' field",
      hint: "Send Solidity source code in the 'code' field of the JSON body",
    });
  }
  if (typeof code !== "string") {
    return res.status(400).json({ error: "'code' must be a string" });
  }
  if (code.length > 500000) {
    return res.status(400).json({ error: "Contract too large (max 500KB)" });
  }
  if (code.trim().length < 10) {
    return res.status(400).json({ error: "Source code too short to analyze" });
  }
  next();
}

// ===========================================
// API ENDPOINTS
// ===========================================

// Health check (free)
app.get("/", (_req, res) => {
  res.json({
    service: "FlowState AI - Smart Contract Security Scanner",
    version: "2.1.0",
    status: "operational",
    x402: {
      network: NETWORK,
      bazaar: true,
    },
    endpoints: {
      quickScan: { method: "POST", path: "/api/scan/quick", price: "$0.05" },
      deepAudit: { method: "POST", path: "/api/scan/deep", price: "$0.50" },
      compare: { method: "POST", path: "/api/compare", price: "$0.10" },
      report: { method: "POST", path: "/api/report", price: "$1.00" },
    },
    author: "Flow State AI (flowstateai.agency)",
  });
});

// Quick Scan - $0.05
app.post("/api/scan/quick", validateSolidityInput, (req, res) => {
  try {
    const { code, contractName } = req.body;
    const vulnerabilities = scanContract(code);
    const riskScore = calculateRiskScore(vulnerabilities);

    res.json({
      success: true,
      contractName: contractName || "Unknown",
      timestamp: new Date().toISOString(),
      summary: {
        riskScore,
        riskLevel: getRiskLevel(riskScore),
        totalIssues: vulnerabilities.length,
        critical: vulnerabilities.filter((v) => v.severity === "CRITICAL")
          .length,
        high: vulnerabilities.filter((v) => v.severity === "HIGH").length,
        medium: vulnerabilities.filter((v) => v.severity === "MEDIUM").length,
        low: vulnerabilities.filter((v) => v.severity === "LOW").length,
      },
      vulnerabilities: vulnerabilities.sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        return order[a.severity] - order[b.severity];
      }),
      poweredBy: "FlowState AI - flowstateai.agency",
    });
  } catch (error) {
    res.status(500).json({ error: "Scan failed", message: error.message });
  }
});

// Deep Audit - $0.50
app.post("/api/scan/deep", validateSolidityInput, (req, res) => {
  try {
    const { code, contractName, includeGasAnalysis = true } = req.body;
    const vulnerabilities = scanContract(code);
    const riskScore = calculateRiskScore(vulnerabilities);
    const gasAnalysis = includeGasAnalysis ? analyzeGas(code) : [];

    const contractMatch = code.match(/contract\s+(\w+)/);
    const inheritsMatch = code.match(/contract\s+\w+\s+is\s+([^{]+)/);
    const functionMatches = code.match(/function\s+\w+/g) || [];
    const modifierMatches = code.match(/modifier\s+\w+/g) || [];
    const eventMatches = code.match(/event\s+\w+/g) || [];

    res.json({
      success: true,
      auditId: `AUDIT-${Date.now()}`,
      contractName: contractName || contractMatch?.[1] || "Unknown",
      timestamp: new Date().toISOString(),
      contractAnalysis: {
        inherits: inheritsMatch
          ? inheritsMatch[1].split(",").map((s) => s.trim())
          : [],
        functions: functionMatches.length,
        modifiers: modifierMatches.length,
        events: eventMatches.length,
        linesOfCode: code.split("\n").length,
      },
      securityAssessment: {
        riskScore,
        riskLevel: getRiskLevel(riskScore),
        passedChecks:
          getVulnerabilityPatterns().length - vulnerabilities.length,
        failedChecks: vulnerabilities.length,
      },
      vulnerabilities: vulnerabilities.map((v) => ({
        ...v,
        priority:
          v.severity === "CRITICAL"
            ? "IMMEDIATE"
            : v.severity === "HIGH"
              ? "HIGH"
              : "NORMAL",
      })),
      gasOptimization: gasAnalysis,
      bestPractices: {
        hasAccessControl: /onlyOwner|Ownable|AccessControl/i.test(code),
        hasReentrancyGuard: /ReentrancyGuard|nonReentrant/i.test(code),
        usesSafemath: /SafeMath|0\.8\./i.test(code),
        hasEvents: eventMatches.length > 0,
        hasNatspec: /\/\/\/|@notice|@dev|@param/i.test(code),
      },
      recommendations: generateRecommendations(vulnerabilities, code),
      poweredBy: "FlowState AI - flowstateai.agency",
    });
  } catch (error) {
    res.status(500).json({ error: "Audit failed", message: error.message });
  }
});

// Compare Contracts - $0.10
app.post("/api/compare", (req, res) => {
  try {
    const { codeA, codeB, nameA, nameB } = req.body;
    if (!codeA || !codeB) {
      return res
        .status(400)
        .json({ error: "Missing 'codeA' or 'codeB' field" });
    }
    if (typeof codeA !== "string" || typeof codeB !== "string") {
      return res
        .status(400)
        .json({ error: "'codeA' and 'codeB' must be strings" });
    }

    const vulnsA = scanContract(codeA);
    const vulnsB = scanContract(codeB);
    const scoreA = calculateRiskScore(vulnsA);
    const scoreB = calculateRiskScore(vulnsB);

    res.json({
      success: true,
      comparison: {
        contractA: {
          name: nameA || "Contract A",
          riskScore: scoreA,
          riskLevel: getRiskLevel(scoreA),
          issues: vulnsA.length,
        },
        contractB: {
          name: nameB || "Contract B",
          riskScore: scoreB,
          riskLevel: getRiskLevel(scoreB),
          issues: vulnsB.length,
        },
        scoreDelta: scoreB - scoreA,
        securityImproved: scoreB > scoreA,
      },
      newVulnerabilities: vulnsB.filter(
        (vB) => !vulnsA.some((vA) => vA.id === vB.id)
      ),
      fixedVulnerabilities: vulnsA.filter(
        (vA) => !vulnsB.some((vB) => vB.id === vA.id)
      ),
      recommendation:
        scoreB >= scoreA
          ? "Contract B has equal or better security posture"
          : "Contract B has introduced new security concerns",
      poweredBy: "FlowState AI - flowstateai.agency",
    });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Comparison failed", message: error.message });
  }
});

// Generate Report - $1.00
app.post("/api/report", validateSolidityInput, (req, res) => {
  try {
    const { code, contractName, clientName, projectName } = req.body;
    const vulnerabilities = scanContract(code);
    const riskScore = calculateRiskScore(vulnerabilities);
    const gasAnalysis = analyzeGas(code);
    const reportId = `FSA-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`;

    res.json({
      success: true,
      reportId,
      format: "markdown",
      report: generateMarkdownReport({
        reportId,
        contractName: contractName || "Smart Contract",
        clientName: clientName || "Client",
        projectName: projectName || "Project",
        vulnerabilities,
        riskScore,
        gasAnalysis,
      }),
      summary: {
        riskScore,
        riskLevel: getRiskLevel(riskScore),
        criticalIssues: vulnerabilities.filter(
          (v) => v.severity === "CRITICAL"
        ).length,
        highIssues: vulnerabilities.filter((v) => v.severity === "HIGH").length,
        totalIssues: vulnerabilities.length,
      },
      poweredBy: "FlowState AI Security Audit - flowstateai.agency",
    });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Report generation failed", message: error.message });
  }
});

// ===========================================
// HELPERS
// ===========================================

function generateRecommendations(vulnerabilities, code) {
  const recs = [];
  if (vulnerabilities.some((v) => v.id === "REENTRANCY")) {
    recs.push({
      priority: "CRITICAL",
      action: "Implement ReentrancyGuard from OpenZeppelin",
      code: "import '@openzeppelin/contracts/security/ReentrancyGuard.sol';",
    });
  }
  if (!code.includes("Ownable") && !code.includes("onlyOwner")) {
    recs.push({
      priority: "HIGH",
      action: "Add access control to administrative functions",
      code: "import '@openzeppelin/contracts/access/Ownable.sol';",
    });
  }
  if (vulnerabilities.some((v) => v.id === "FLOATING_PRAGMA")) {
    recs.push({
      priority: "MEDIUM",
      action: "Lock Solidity version",
      code: "pragma solidity 0.8.24;",
    });
  }
  if (vulnerabilities.some((v) => v.id === "TX_ORIGIN")) {
    recs.push({
      priority: "HIGH",
      action: "Replace tx.origin with msg.sender",
      code: "require(msg.sender == owner, 'Not authorized');",
    });
  }
  return recs;
}

function generateMarkdownReport({
  reportId,
  contractName,
  clientName,
  projectName,
  vulnerabilities,
  riskScore,
  gasAnalysis,
}) {
  const bySeverity = (s) => vulnerabilities.filter((v) => v.severity === s);
  return `# Smart Contract Security Audit Report

## Report Information
- **Report ID:** ${reportId}
- **Date:** ${new Date().toISOString().split("T")[0]}
- **Client:** ${clientName}
- **Project:** ${projectName}
- **Contract:** ${contractName}
- **Auditor:** FlowState AI Security (flowstateai.agency)

---

## Executive Summary

Automated audit of the ${contractName} smart contract identified **${vulnerabilities.length} potential issue(s)**.

### Risk Score: ${riskScore}/100 (${getRiskLevel(riskScore)} RISK)

| Severity | Count |
|----------|-------|
| Critical | ${bySeverity("CRITICAL").length} |
| High | ${bySeverity("HIGH").length} |
| Medium | ${bySeverity("MEDIUM").length} |
| Low | ${bySeverity("LOW").length} |

---

## Findings

${
  vulnerabilities.length === 0
    ? "No vulnerabilities detected. This automated scan does not replace a manual audit.\n"
    : vulnerabilities
        .map(
          (v, i) => `### ${i + 1}. ${v.name}
- **Severity:** ${v.severity}
- **ID:** ${v.id}
- **Occurrences:** ${v.occurrences}
- **Lines:** ${v.lines.length > 0 ? v.lines.join(", ") : "Multiple locations"}

**Description:** ${v.description}

**Recommendation:** ${v.recommendation}
`
        )
        .join("\n")
}

---

## Gas Optimization

${
  gasAnalysis.length > 0
    ? gasAnalysis.map((g) => `- **${g.issue}:** ${g.suggestion}`).join("\n")
    : "No significant gas optimization issues detected."
}

---

## Disclaimer

This is an automated static analysis. It does not guarantee the absence of all vulnerabilities. Always conduct multiple audits — including manual expert review — before mainnet deployment.

---

*Generated by FlowState AI Security | flowstateai.agency*
*Report ID: ${reportId}*
`;
}

// Global error handler
app.use((err, _req, res, _next) => {
  console.error(`[${new Date().toISOString()}] Error:`, err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ===========================================
// START SERVER
// ===========================================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║   FlowState AI - Smart Contract Security Scanner v2.1     ║
║   x402 Payment-Enabled API + Bazaar Discovery             ║
╠═══════════════════════════════════════════════════════════╣
║   Server:      http://0.0.0.0:${String(PORT).padEnd(29)}║
║   Network:     ${NETWORK.padEnd(40)}║
║   Wallet:      ${WALLET_ADDRESS.slice(0, 10)}...${WALLET_ADDRESS.slice(-6)}                          ║
║   CDP Auth:    ${process.env.CDP_API_KEY_ID ? "Configured" : "Not set (testnet only)"}                              ║
╠═══════════════════════════════════════════════════════════╣
║   ENDPOINTS (Bazaar Discoverable):                        ║
║   POST /api/scan/quick  - Quick scan .............. $0.05 ║
║   POST /api/scan/deep   - Deep audit .............. $0.50 ║
║   POST /api/compare     - Compare contracts ....... $0.10 ║
║   POST /api/report      - Full audit report ....... $1.00 ║
║   GET  /                - Health check (free)             ║
╚═══════════════════════════════════════════════════════════╝
  `);
});
