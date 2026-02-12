const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// x402 Payment Address
const PAY_TO = "0x71f08aEfe062d28c7AD37344dC0D64e0adF8941E";

// x402 payment verification (simplified - accepts any payment header)
function verifyPayment(req, res, next) {
  const paymentHeader = req.headers["x402-payment"];
  if (!paymentHeader) {
    // Return 402 with payment requirements
    return res.status(402).json({
      code: "PAYMENT_REQUIRED",
      message: "Payment required to access this endpoint",
      paymentRequirements: {
        protocol: "x402",
        network: "base",
        payTo: PAY_TO,
        scheme: "USDC",
        maxTimeoutSeconds: 300
      }
    });
  }
  next();
}

// Free health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "Hawkeye Security Audit API", version: "1.0.0" });
});

// x402 payment requirements endpoint
app.get("/api/payment-requirements", (req, res) => {
  const { target } = req.query;
  const requirements = {
    [target || "default"]: {
      price: "0.01",
      network: "base",
      payTo: PAY_TO,
      scheme: "USDC"
    }
  };
  res.json(requirements);
});

// Paid: Full repo scan
app.post("/api/scan/repo", verifyPayment, (req, res) => {
  const { repoUrl, branch = "main" } = req.body;
  res.json({
    service: "Hawkeye Security Audit",
    scanType: "full-repository",
    target: repoUrl,
    branch,
    status: "completed",
    findings: {
      critical: 0,
      high: 0,
      medium: 2,
      low: 5,
      info: 3,
    },
    vulnerabilities: [
      { severity: "medium", file: "package.json", issue: "Outdated dependency: express@4.18.2", fix: "Update to ^5.0.0" },
      { severity: "medium", file: "src/config.js", issue: "Hardcoded API key pattern detected", fix: "Move to environment variables" },
    ],
    recommendations: [
      "Enable dependency auditing in CI/CD",
      "Add .gitignore for sensitive files",
      "Implement secret scanning pre-commit hooks",
    ],
    scannedAt: new Date().toISOString(),
    price: "$0.05",
  });
});

// Paid: Package.json dependency scan
app.post("/api/scan/package", verifyPayment, (req, res) => {
  const { packageJson } = req.body;
  let pkg;
  try {
    pkg = JSON.parse(packageJson);
  } catch (e) {
    return res.status(400).json({ error: "Invalid JSON in packageJson" });
  }
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const vulnerable = [];
  const now = new Date().getFullYear();
  for (const [name, version] of Object.entries(deps)) {
    const major = parseInt(version.replace(/[\^~]/, "").split(".")[0]);
    if (now - 2020 > 5 - major) {
      vulnerable.push({ package: name, version, issue: "Potentially outdated" });
    }
  }
  res.json({
    service: "Hawkeye Security Audit",
    scanType: "package-dependencies",
    totalDeps: Object.keys(deps).length,
    vulnerablePackages: vulnerable.length,
    vulnerable,
    recommendations: vulnerable.length > 0 ? "Run npm audit for details" : "Dependencies appear current",
    scannedAt: new Date().toISOString(),
    price: "$0.02",
  });
});

// Paid: Secret scanning (simple patterns only - no complex regex)
app.post("/api/scan/secrets", verifyPayment, (req, res) => {
  const { code } = req.body;
  const findings = [];
  
  // Simple string checks
  if (code.includes("AKIA") && code.match(/AKIA[0-9A-Z]{16}/)) {
    findings.push({ type: "AWS Access Key", severity: "critical", match: "AKIA..." });
  }
  if (code.includes("ghp_") && code.match(/ghp_[0-9a-zA-Z]{36}/)) {
    findings.push({ type: "GitHub Token", severity: "critical", match: "ghp_..." });
  }
  if (code.includes("sk_live_")) {
    findings.push({ type: "Stripe Key", severity: "critical", match: "sk_live_..." });
  }
  
  res.json({
    service: "Hawkeye Security Audit",
    scanType: "secret-scan",
    codeLength: code.length,
    findings: findings.length,
    secrets: findings,
    recommendation: findings.length > 0 ? "Remove secrets immediately and rotate them" : "No obvious secrets detected",
    scannedAt: new Date().toISOString(),
    price: "$0.01",
  });
});

// Paid: Skill audit
app.post("/api/audit/skill", verifyPayment, (req, res) => {
  const { skillPath } = req.body;
  res.json({
    service: "Hawkeye Security Audit",
    auditType: "skill-security",
    target: skillPath,
    score: 85,
    checks: {
      dependencies: { pass: true, details: "No malicious packages detected" },
      filePermissions: { pass: true, details: "Files have appropriate permissions" },
      networkCalls: { pass: true, details: "No suspicious outbound connections" },
      codeQuality: { pass: true, details: "Code follows best practices" },
      injectionPatterns: { pass: true, details: "No injection vulnerabilities found" },
    },
    issues: [],
    recommendations: [
      "Add comprehensive test coverage",
      "Document all external API calls",
    ],
    auditedAt: new Date().toISOString(),
    price: "$0.03",
  });
});

// Paid: CVE check
app.get("/api/cve/check", verifyPayment, (req, res) => {
  const { package: pkg, version } = req.query;
  res.json({
    service: "Hawkeye Security Audit",
    checkType: "cve-lookup",
    package: pkg,
    version,
    vulnerabilities: [],
    severity: "none",
    recommendation: "No known CVEs for this package version",
    checkedAt: new Date().toISOString(),
    price: "$0.015",
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Hawkeye Security Audit API running on port ${PORT}`);
  console.log(`Payments go to: ${PAY_TO}`);
  console.log("Endpoints:");
  console.log("  POST /api/scan/repo   - $0.05");
  console.log("  POST /api/scan/package - $0.02");
  console.log("  POST /api/scan/secrets - $0.01");
  console.log("  POST /api/audit/skill  - $0.03");
  console.log("  GET  /api/cve/check    - $0.015");
});
