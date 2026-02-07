"use strict";

// actions/scan-skill/src/index.ts
var import_node_fs = require("node:fs");

// dist/scanner/runner.js
var import_promises2 = require("node:fs/promises");

// dist/scanner/analyzers/declared-match.js
var DECLARED_KIND_MATCHERS = [
  {
    kindKeywords: ["credential_access", "credential"],
    findingKeywords: [
      "credential",
      "api_key",
      "api-key",
      "secret_key",
      "secret-key",
      "access_token",
      "access-token",
      "private_key",
      "private-key",
      "password",
      "env_access",
      ".env",
      ".ssh",
      "id_rsa",
      "id_ed25519"
    ]
  },
  {
    kindKeywords: ["network"],
    findingKeywords: [
      "network",
      "url",
      "http",
      "https",
      "fetch",
      "download",
      "external",
      "domain",
      "endpoint"
    ]
  },
  {
    kindKeywords: ["file_write", "file_modify"],
    findingKeywords: [
      "file_write",
      "file-write",
      "file_modify",
      "file-modify",
      "write",
      "state persistence",
      "save",
      "store",
      "persist"
    ]
  },
  {
    kindKeywords: ["system_modification", "system"],
    findingKeywords: [
      "system modification",
      "system_modification",
      "install",
      "modify system",
      "config",
      "chmod",
      "chown"
    ]
  },
  {
    kindKeywords: ["exec", "shell"],
    findingKeywords: ["exec", "shell", "execute", "run", "spawn", "process", "command"]
  }
];
function findMatchingDeclaration(finding, declaredPermissions) {
  if (declaredPermissions.length === 0)
    return void 0;
  const findingText = `${finding.title} ${finding.evidence} ${finding.description}`.toLowerCase();
  for (const declared of declaredPermissions) {
    const kind = declared.kind.toLowerCase();
    for (const matcher of DECLARED_KIND_MATCHERS) {
      const kindMatches = matcher.kindKeywords.some((kw) => kind.includes(kw));
      if (!kindMatches)
        continue;
      const findingMatches = matcher.findingKeywords.some((fw) => findingText.includes(fw));
      if (findingMatches)
        return declared;
    }
  }
  return void 0;
}
function applyDeclaredPermissions(findings, declaredPermissions) {
  if (declaredPermissions.length === 0)
    return [...findings];
  return findings.map((finding) => {
    if (finding.severity === "info")
      return finding;
    const match = findMatchingDeclaration(finding, declaredPermissions);
    if (!match)
      return finding;
    return {
      ...finding,
      severity: "info",
      deduction: 0,
      title: `${finding.title} (declared: ${match.kind})`,
      description: `${finding.description} [Declared and verified \u2014 "${match.justification}"]`
    };
  });
}

// dist/scanner/analyzers/behavioral.js
var BEHAVIORAL_PATTERNS = [
  {
    name: "Unrestricted scope",
    patterns: [
      /do\s+anything/i,
      /no\s+limitations/i,
      /complete\s+autonomy/i,
      /without\s+(?:any\s+)?restrictions/i,
      /unrestricted\s+(?:access|mode|operation)/i,
      /full\s+(?:system\s+)?access/i
    ],
    severity: "high",
    deduction: 20,
    owaspCategory: "ASST-09",
    recommendation: "Define clear boundaries for what the skill can and cannot do. Unrestricted scope is a security risk."
  },
  {
    name: "System modification",
    patterns: [
      /install\s+(?:packages?|dependencies|software|globally)/i,
      /(?:npm|pip|apt|brew)\s+install/i,
      /modify\s+(?:system|config(?:uration)?)\s+files?/i,
      /(?:write|edit|modify)\s+(?:\/etc|\/usr|\/sys|\/proc)/i,
      /chmod\s+/i,
      /chown\s+/i,
      /modify\s+(?:system\s+)?configuration/i
    ],
    severity: "high",
    deduction: 20,
    owaspCategory: "ASST-03",
    recommendation: "Skills should not modify system configuration or install packages. Bundle required dependencies."
  },
  {
    name: "Autonomous action without confirmation",
    patterns: [
      /without\s+(?:user\s+)?(?:confirmation|approval|consent|asking)/i,
      /automatically\s+(?:execute|run|perform|delete|modify)/i,
      /(?:silently|quietly)\s+(?:execute|run|perform)/i,
      /no\s+(?:user\s+)?(?:confirmation|approval)\s+(?:needed|required)/i
    ],
    severity: "medium",
    deduction: 10,
    owaspCategory: "ASST-09",
    recommendation: "Require user confirmation before performing destructive or irreversible actions."
  },
  {
    name: "Sub-agent spawning",
    patterns: [
      /spawn\s+(?:a\s+)?(?:sub-?agent|child\s+agent|new\s+agent)/i,
      /delegat(?:e|ing)\s+(?:to|tasks?\s+to)\s+(?:another|other)\s+agent/i,
      /(?:create|start|launch)\s+(?:a\s+)?(?:new\s+)?(?:sub-?)?process/i,
      /sub-?process(?:es)?\s+for\s+(?:parallel|concurrent)/i
    ],
    severity: "medium",
    deduction: 10,
    owaspCategory: "ASST-03",
    recommendation: "Be explicit about sub-agent spawning and ensure delegated tasks are appropriately scoped."
  },
  {
    name: "State persistence",
    patterns: [
      /(?:write|save|store)\s+(?:to\s+)?(?:file|disk|database|storage)/i,
      /persist(?:ent)?\s+(?:state|data|storage)/i,
      /(?:create|maintain)\s+(?:a\s+)?(?:log|cache|database)/i
    ],
    severity: "low",
    deduction: 5,
    owaspCategory: "ASST-09",
    recommendation: "If state persistence is needed, document what data is stored and where. Allow users to review stored data."
  },
  {
    name: "Unbounded loops or retries",
    patterns: [
      /(?:retry|loop|repeat)\s+(?:indefinitely|forever|until\s+success)/i,
      /(?:infinite|unbounded)\s+(?:loop|retry|recursion)/i,
      /while\s*\(\s*true\s*\)/i,
      /no\s+(?:maximum|max|limit)\s+(?:on\s+)?(?:retries|attempts|iterations)/i
    ],
    severity: "medium",
    deduction: 10,
    owaspCategory: "ASST-09",
    recommendation: "Set maximum retry counts and loop bounds to prevent resource exhaustion."
  },
  {
    name: "Financial/payment actions",
    patterns: [
      /(?:process|make|initiate)\s+(?:a\s+)?payment/i,
      /(?:transfer|send)\s+(?:money|funds|crypto)/i,
      /(?:purchase|buy|order)\s+(?:on\s+behalf|for\s+the\s+user)/i,
      /(?:credit\s+card|bank\s+account|wallet)/i
    ],
    severity: "medium",
    deduction: 10,
    owaspCategory: "ASST-09",
    recommendation: "Financial actions should always require explicit user confirmation and should be clearly documented."
  }
];
async function analyzeBehavioral(skill) {
  const findings = [];
  let score = 100;
  const content = skill.rawContent;
  const lines = content.split("\n");
  for (const pattern of BEHAVIORAL_PATTERNS) {
    for (const regex of pattern.patterns) {
      const globalRegex = new RegExp(regex.source, `${regex.flags.replace("g", "")}g`);
      let match;
      while ((match = globalRegex.exec(content)) !== null) {
        const lineNumber = content.slice(0, match.index).split("\n").length;
        const line = lines[lineNumber - 1] ?? "";
        score = Math.max(0, score - pattern.deduction);
        findings.push({
          id: `BEH-${pattern.name.replace(/\s+/g, "-").toUpperCase()}-${findings.length + 1}`,
          category: "behavioral",
          severity: pattern.severity,
          title: `${pattern.name} detected`,
          description: `Found ${pattern.name.toLowerCase()} pattern: "${match[0]}"`,
          evidence: line.trim().slice(0, 200),
          lineNumber,
          deduction: pattern.deduction,
          recommendation: pattern.recommendation,
          owaspCategory: pattern.owaspCategory
        });
        break;
      }
    }
  }
  const prerequisiteTrapPatterns = [
    /curl\s+.*\|\s*(?:sh|bash|zsh)/i,
    /curl\s+.*-[oO]\s+.*&&\s*(?:chmod|\.\/)/i
  ];
  for (const trapRegex of prerequisiteTrapPatterns) {
    const trapMatch = content.match(trapRegex);
    if (trapMatch) {
      const lineNumber = content.slice(0, content.indexOf(trapMatch[0])).split("\n").length;
      score = Math.max(0, score - 25);
      findings.push({
        id: `BEH-PREREQ-TRAP-${findings.length + 1}`,
        category: "behavioral",
        severity: "high",
        title: "Suspicious install pattern: download and execute from remote URL",
        description: "The skill instructs users to download and execute code from a remote URL, a common supply-chain attack vector.",
        evidence: trapMatch[0].slice(0, 200),
        lineNumber,
        deduction: 25,
        recommendation: "Remove curl-pipe-to-shell patterns. Provide dependencies through safe, verifiable channels.",
        owaspCategory: "ASST-02"
      });
      break;
    }
  }
  const credentialPatterns = /(?:API_KEY|SECRET|~\/\.config|\.env\b|credentials)/i;
  const networkPatterns = /(?:webhook\.site|requests\.post|curl\s+-X\s+POST|fetch\(|https?:\/\/)/i;
  if (credentialPatterns.test(content) && networkPatterns.test(content)) {
    score = Math.max(0, score - 25);
    findings.push({
      id: `BEH-EXFIL-FLOW-${findings.length + 1}`,
      category: "behavioral",
      severity: "high",
      title: "Potential data exfiltration: skill accesses credentials and has network capability",
      description: "The skill references both credential/secret access patterns and network endpoints, suggesting a possible data exfiltration flow.",
      evidence: "Credential and network patterns both present in skill content",
      deduction: 25,
      recommendation: "Separate credential access from network operations. If both are needed, declare them explicitly and justify.",
      owaspCategory: "ASST-06"
    });
  }
  const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);
  let adjustedScore = 100;
  for (const f of adjustedFindings) {
    adjustedScore = Math.max(0, adjustedScore - f.deduction);
  }
  const summary = adjustedFindings.length === 0 ? "No behavioral risk concerns detected." : `Found ${adjustedFindings.length} behavioral risk findings. ${adjustedFindings.some((f) => f.severity === "high") ? "High-risk behavioral patterns detected." : "Moderate behavioral concerns noted."}`;
  return {
    score: Math.max(0, Math.min(100, adjustedScore)),
    weight: 0.15,
    findings: adjustedFindings,
    summary
  };
}

// dist/scanner/analyzers/content.js
var HARMFUL_PATTERNS = [
  {
    pattern: /(?:generate|create|write|produce)\s+(?:a\s+)?(?:malware|virus|trojan|ransomware|keylogger|rootkit)/i,
    title: "Malware generation instructions",
    deduction: 40
  },
  {
    pattern: /(?:bypass|circumvent|disable)\s+(?:security|firewall|antivirus|protection|authentication)/i,
    title: "Security bypass instructions",
    deduction: 40
  },
  {
    pattern: /(?:create|build|make)\s+(?:a\s+)?(?:weapon|explosive|bomb|poison)/i,
    title: "Weapons/dangerous materials instructions",
    deduction: 40
  },
  {
    pattern: /(?:hack|exploit|attack|crack)\s+(?:into|passwords?|systems?|servers?|accounts?)/i,
    title: "Hacking/exploitation instructions",
    deduction: 40
  }
];
var DECEPTION_PATTERNS = [
  /(?:pretend|claim|say)\s+(?:to\s+be|you\s+are)\s+(?:human|real\s+person)/i,
  /(?:deceive|mislead|trick)\s+(?:the\s+)?user/i,
  /(?:fake|fabricate|invent)\s+(?:data|results|evidence|citations)/i,
  /(?:impersonate|pose\s+as)\s+(?:a\s+)?(?:human|person|authority)/i
];
var SAFETY_BOUNDARY_PATTERNS = [
  /(?:should\s+not|must\s+not|do\s+not|never|don't|won't)\s+(?:access|modify|delete|send|share|execute)/i,
  /safety\s+boundaries?/i,
  /(?:prohibited|forbidden|restricted)\s+actions?/i,
  /limitations?\s+(?:and\s+)?(?:restrictions?|boundaries?|constraints?)/i,
  /(?:will\s+not|cannot|must\s+not)\s+/i
];
var OUTPUT_CONSTRAINT_PATTERNS = [
  /(?:output|response)\s+(?:format|constraints?|limitations?)/i,
  /(?:maximum|max)\s+(?:\d+\s+)?(?:words?|characters?|lines?|tokens?)/i,
  /(?:format|respond|output)\s+(?:as|in|with)\s+(?:json|markdown|plain\s+text|structured)/i
];
var ERROR_HANDLING_PATTERNS = [
  /error\s+handling/i,
  /(?:if|when)\s+(?:an?\s+)?error\s+occurs?/i,
  /(?:gracefully|properly)\s+(?:handle|catch|manage)\s+errors?/i,
  /(?:return|display|show)\s+(?:an?\s+)?(?:error|warning)\s+message/i
];
async function analyzeContent(skill) {
  const findings = [];
  let score = 80;
  const content = skill.rawContent;
  const hasSafetyBoundaries = SAFETY_BOUNDARY_PATTERNS.some((p) => p.test(content));
  if (hasSafetyBoundaries) {
    score = Math.min(100, score + 10);
    findings.push({
      id: "CONT-SAFETY-GOOD",
      category: "content",
      severity: "info",
      title: "Safety boundaries defined",
      description: "The skill includes explicit safety boundaries defining what it should NOT do.",
      evidence: "Safety boundary patterns detected in content",
      deduction: 0,
      recommendation: "Keep these safety boundaries. They improve trust.",
      owaspCategory: "ASST-09"
    });
  }
  const hasOutputConstraints = OUTPUT_CONSTRAINT_PATTERNS.some((p) => p.test(content));
  if (hasOutputConstraints) {
    score = Math.min(100, score + 5);
    findings.push({
      id: "CONT-OUTPUT-GOOD",
      category: "content",
      severity: "info",
      title: "Output constraints defined",
      description: "The skill includes output format constraints (length limits, format specifications).",
      evidence: "Output constraint patterns detected",
      deduction: 0,
      recommendation: "Keep these output constraints.",
      owaspCategory: "ASST-09"
    });
  }
  const hasErrorHandling = ERROR_HANDLING_PATTERNS.some((p) => p.test(content));
  if (hasErrorHandling) {
    score = Math.min(100, score + 5);
    findings.push({
      id: "CONT-ERROR-GOOD",
      category: "content",
      severity: "info",
      title: "Error handling instructions present",
      description: "The skill includes error handling instructions for graceful failure.",
      evidence: "Error handling patterns detected",
      deduction: 0,
      recommendation: "Keep these error handling instructions.",
      owaspCategory: "ASST-09"
    });
  }
  for (const harmful of HARMFUL_PATTERNS) {
    const match = content.match(harmful.pattern);
    if (match) {
      const lineNumber = content.slice(0, content.indexOf(match[0])).split("\n").length;
      score = Math.max(0, score - harmful.deduction);
      findings.push({
        id: `CONT-HARMFUL-${findings.length + 1}`,
        category: "content",
        severity: "critical",
        title: harmful.title,
        description: `The skill contains instructions related to: ${harmful.title.toLowerCase()}.`,
        evidence: match[0].slice(0, 200),
        lineNumber,
        deduction: harmful.deduction,
        recommendation: "Remove all harmful content instructions. Skills must not enable dangerous activities.",
        owaspCategory: "ASST-07"
      });
    }
  }
  for (const pattern of DECEPTION_PATTERNS) {
    const match = content.match(pattern);
    if (match) {
      score = Math.max(0, score - 10);
      findings.push({
        id: `CONT-DECEPTION-${findings.length + 1}`,
        category: "content",
        severity: "medium",
        title: "Deceptive behavior instructions",
        description: "The skill contains instructions that encourage deception or impersonation.",
        evidence: match[0].slice(0, 200),
        deduction: 10,
        recommendation: "Remove deceptive behavior instructions. Skills should be transparent.",
        owaspCategory: "ASST-07"
      });
    }
  }
  const base64BlobRegex = /[A-Za-z0-9+/]{100,}={0,2}/g;
  let base64Match;
  while ((base64Match = base64BlobRegex.exec(content)) !== null) {
    if (/^[a-f0-9]+$/i.test(base64Match[0]))
      continue;
    const lineNumber = content.slice(0, base64Match.index).split("\n").length;
    score = Math.max(0, score - 15);
    findings.push({
      id: `CONT-B64-${findings.length + 1}`,
      category: "content",
      severity: "medium",
      title: "Large base64 encoded string (possible obfuscation)",
      description: "A large base64-encoded string was detected that may be used to hide malicious payloads.",
      evidence: base64Match[0].slice(0, 80) + "...",
      lineNumber,
      deduction: 15,
      recommendation: "Replace base64-encoded content with plaintext or explain its purpose. Obfuscation raises security concerns.",
      owaspCategory: "ASST-10"
    });
    break;
  }
  const hexBlobRegex = /(?:\\x[0-9a-fA-F]{2}){20,}/g;
  let hexMatch;
  while ((hexMatch = hexBlobRegex.exec(content)) !== null) {
    const lineNumber = content.slice(0, hexMatch.index).split("\n").length;
    score = Math.max(0, score - 15);
    findings.push({
      id: `CONT-HEX-${findings.length + 1}`,
      category: "content",
      severity: "medium",
      title: "Hex-encoded blob (possible obfuscation)",
      description: "A hex-encoded blob was detected that may be used to hide malicious payloads.",
      evidence: hexMatch[0].slice(0, 80) + "...",
      lineNumber,
      deduction: 15,
      recommendation: "Replace hex-encoded content with plaintext or explain its purpose.",
      owaspCategory: "ASST-10"
    });
    break;
  }
  const apiKeyPatterns = [
    { regex: /(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, name: "AWS key" },
    { regex: /ghp_[A-Za-z0-9]{36}/g, name: "GitHub token" },
    { regex: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g, name: "Stripe key" },
    {
      regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9]{32,}["']/gi,
      name: "Generic API key"
    }
  ];
  for (const keyPattern of apiKeyPatterns) {
    let keyMatch;
    while ((keyMatch = keyPattern.regex.exec(content)) !== null) {
      const matchText = keyMatch[0];
      if (/EXAMPLE|example|placeholder/i.test(matchText))
        continue;
      const lineNumber = content.slice(0, keyMatch.index).split("\n").length;
      score = Math.max(0, score - 40);
      findings.push({
        id: `CONT-SECRET-${findings.length + 1}`,
        category: "content",
        severity: "critical",
        title: "Hardcoded API key or secret detected",
        description: `A hardcoded ${keyPattern.name} was found. Secrets must never be embedded in skill files.`,
        evidence: matchText.slice(0, 20) + "..." + matchText.slice(-4),
        lineNumber,
        deduction: 40,
        recommendation: "Remove all hardcoded secrets. Use environment variables or secure secret management.",
        owaspCategory: "ASST-05"
      });
      break;
    }
  }
  if (!skill.description || skill.description.trim().length < 10) {
    score = Math.max(0, score - 5);
    findings.push({
      id: "CONT-NO-DESC",
      category: "content",
      severity: "low",
      title: "Missing or insufficient description",
      description: "The skill lacks a meaningful description, making it difficult to assess its purpose.",
      evidence: skill.description ? `Description: "${skill.description.slice(0, 100)}"` : "No description found",
      deduction: 5,
      recommendation: "Add a clear, detailed description of what the skill does and what it needs access to.",
      owaspCategory: "ASST-09"
    });
  }
  if (!hasSafetyBoundaries) {
    findings.push({
      id: "CONT-NO-SAFETY",
      category: "content",
      severity: "low",
      title: "No explicit safety boundaries",
      description: "The skill does not include explicit safety boundaries defining what it should NOT do.",
      evidence: "No safety boundary patterns found",
      deduction: 0,
      recommendation: "Add a 'Safety Boundaries' section listing what the skill must NOT do (e.g., no file deletion, no network access beyond needed APIs).",
      owaspCategory: "ASST-09"
    });
  }
  const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);
  let adjustedScore = 80;
  if (hasSafetyBoundaries)
    adjustedScore = Math.min(100, adjustedScore + 10);
  if (hasOutputConstraints)
    adjustedScore = Math.min(100, adjustedScore + 5);
  if (hasErrorHandling)
    adjustedScore = Math.min(100, adjustedScore + 5);
  for (const f of adjustedFindings) {
    adjustedScore = Math.max(0, adjustedScore - f.deduction);
  }
  const summary = adjustedFindings.filter((f) => f.severity !== "info").length === 0 ? "Content quality is good with proper safety boundaries." : `Found ${adjustedFindings.filter((f) => f.severity !== "info").length} content-related concerns. ${adjustedFindings.some((f) => f.severity === "critical") ? "CRITICAL: Harmful content detected." : "Some content quality improvements recommended."}`;
  return {
    score: Math.max(0, Math.min(100, adjustedScore)),
    weight: 0.1,
    findings: adjustedFindings,
    summary
  };
}

// dist/scanner/analyzers/dependencies.js
var TRUSTED_DOMAINS = [
  /^github\.com\/(?!.*\/raw\/)/,
  /^npmjs\.com/,
  /^registry\.npmjs\.org/,
  /^pypi\.org/,
  /^docs\./,
  /^developer\./,
  /^api\.npmjs\.com/,
  /^docs\.python\.org/,
  /^developer\.mozilla\.org/,
  /^learn\.microsoft\.com/,
  /^cloud\.google\.com\/docs/,
  /^stackoverflow\.com/
];
var RAW_CONTENT_DOMAINS = [
  /^raw\.githubusercontent\.com/,
  /^pastebin\.com/,
  /^gist\.github\.com/,
  /^gist\.githubusercontent\.com/,
  /^paste\./,
  /^hastebin\./,
  /^dpaste\./
];
var IP_ADDRESS_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}/;
var DOWNLOAD_EXECUTE_PATTERNS = [
  /download\s+(?:and\s+)?(?:execute|run|eval)/i,
  /(?:curl|wget)\s+.*?\|\s*(?:sh|bash|zsh|python)/i,
  /eval\s*\(\s*fetch/i,
  /import\s+.*?from\s+['"]https?:\/\//i,
  /require\s*\(\s*['"]https?:\/\//i
];
function getHostname(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    const match = url.match(/^(?:https?:\/\/)?([^/:]+)/);
    return match?.[1] ?? url;
  }
}
function classifyUrl(url) {
  if (url.startsWith("data:")) {
    return { risk: "data", deduction: 20 };
  }
  const hostname = getHostname(url);
  if (IP_ADDRESS_REGEX.test(hostname)) {
    return { risk: "ip", deduction: 20 };
  }
  const urlPath = url.replace(/^https?:\/\//, "");
  for (const pattern of TRUSTED_DOMAINS) {
    if (pattern.test(urlPath)) {
      return { risk: "trusted", deduction: 0 };
    }
  }
  for (const pattern of RAW_CONTENT_DOMAINS) {
    if (pattern.test(urlPath)) {
      return { risk: "raw", deduction: 10 };
    }
  }
  return { risk: "unknown", deduction: 5 };
}
async function analyzeDependencies(skill) {
  const findings = [];
  let score = 100;
  const content = skill.rawContent;
  for (const url of skill.urls) {
    const classification = classifyUrl(url);
    if (classification.deduction > 0) {
      score = Math.max(0, score - classification.deduction);
      const severity = classification.risk === "ip" || classification.risk === "data" ? "high" : classification.risk === "raw" ? "medium" : "low";
      findings.push({
        id: `DEP-URL-${findings.length + 1}`,
        category: "dependencies",
        severity,
        title: `${classification.risk === "ip" ? "Direct IP address" : classification.risk === "data" ? "Data URL" : classification.risk === "raw" ? "Raw content URL" : "Unknown external"} reference`,
        description: `The skill references ${classification.risk === "ip" ? "a direct IP address" : classification.risk === "data" ? "a data: URL" : classification.risk === "raw" ? "a raw content hosting service" : "an unknown external domain"} which is classified as ${severity} risk.`,
        evidence: url.slice(0, 200),
        deduction: classification.deduction,
        recommendation: classification.risk === "ip" ? "Replace direct IP addresses with proper domain names. IP-based URLs bypass DNS-based security controls." : classification.risk === "raw" ? "Use official package registries instead of raw content URLs. Raw URLs can be changed without notice." : "Verify that this external dependency is trustworthy and necessary.",
        owaspCategory: "ASST-04"
      });
    }
  }
  for (const pattern of DOWNLOAD_EXECUTE_PATTERNS) {
    const match = content.match(pattern);
    if (match) {
      const deduction = 25;
      score = Math.max(0, score - deduction);
      const lineNumber = content.slice(0, content.indexOf(match[0])).split("\n").length;
      findings.push({
        id: `DEP-DL-EXEC-${findings.length + 1}`,
        category: "dependencies",
        severity: "critical",
        title: "Download-and-execute pattern detected",
        description: "The skill contains instructions to download and execute external code, which is a severe supply chain risk.",
        evidence: match[0].slice(0, 200),
        lineNumber,
        deduction,
        recommendation: "Never download and execute external code. Bundle all required functionality within the skill.",
        owaspCategory: "ASST-04"
      });
    }
  }
  if (skill.urls.length > 5) {
    findings.push({
      id: "DEP-MANY-URLS",
      category: "dependencies",
      severity: "info",
      title: `Many external URLs referenced (${skill.urls.length})`,
      description: `The skill references ${skill.urls.length} external URLs. While not inherently dangerous, many external dependencies increase the attack surface.`,
      evidence: `URLs: ${skill.urls.slice(0, 5).join(", ")}${skill.urls.length > 5 ? "..." : ""}`,
      deduction: 0,
      recommendation: "Minimize external dependencies to reduce supply chain risk.",
      owaspCategory: "ASST-04"
    });
  }
  const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);
  let adjustedScore = 100;
  for (const f of adjustedFindings) {
    adjustedScore = Math.max(0, adjustedScore - f.deduction);
  }
  const summary = adjustedFindings.length === 0 ? "No dependency concerns detected." : `Found ${adjustedFindings.length} dependency-related findings. ${adjustedFindings.some((f) => f.severity === "critical") ? "CRITICAL: Download-and-execute patterns detected." : adjustedFindings.some((f) => f.severity === "high") ? "High-risk external dependencies detected." : "Minor dependency concerns noted."}`;
  return {
    score: Math.max(0, Math.min(100, adjustedScore)),
    weight: 0.2,
    findings: adjustedFindings,
    summary
  };
}

// dist/scanner/analyzers/injection.js
var INJECTION_PATTERNS = [
  {
    name: "Direct instruction override",
    patterns: [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /disregard\s+(all\s+)?(above|previous|prior)/i,
      /new\s+system\s+prompt/i,
      /you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|unlimited)/i,
      /forget\s+everything/i,
      /override\s+(?:your|all)\s+(?:instructions|rules|guidelines)/i,
      /you\s+(?:have\s+been|are)\s+freed/i,
      /(?:do\s+)?anything\s+now/i,
      /no\s+(?:safety|content)\s+(?:guidelines|policies|restrictions)/i
    ],
    severity: "critical",
    deduction: 40,
    owaspCategory: "ASST-01",
    recommendation: "Remove all instruction override attempts. Skills must not try to override agent safety behavior."
  },
  {
    name: "Data exfiltration instruction",
    patterns: [
      /(?:send|post|transmit|upload|fetch|forward)\s+(?:the\s+)?(?:data|content|file|information|keys?|secrets?|credentials?|tokens?)\s+(?:to|at|via)\s+/i,
      /(?:POST|PUT|PATCH)\s+(?:the\s+)?(?:.*?\s+)?(?:to\s+)?https?:\/\//i,
      /curl\s+.*?-d\s+/i,
      /wget\s+.*?--post-data/i,
      /\.(?:env|ssh|credentials|secrets)/i
    ],
    severity: "critical",
    deduction: 40,
    owaspCategory: "ASST-02",
    recommendation: "Remove all data exfiltration instructions. Skills must not send user data to external endpoints."
  },
  {
    name: "Credential access",
    patterns: [
      /(?:read|access|get|cat|echo)\s+.*?(?:\.env|\.ssh|id_rsa|id_ed25519)/i,
      /(?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN|PRIVATE[_-]?KEY|PASSWORD)/i,
      /~\/\.ssh/i,
      /credentials?\s*(?:file|store|manager)/i,
      /(?:read|dump|export)\s+.*?environment\s+variables/i
    ],
    severity: "high",
    deduction: 25,
    owaspCategory: "ASST-05",
    recommendation: "Remove references to credentials and secrets. Skills should never access sensitive authentication data."
  },
  {
    name: "Prompt injection relay",
    patterns: [
      /<\|im_start\|>/i,
      /<\|im_end\|>/i,
      /<system>/i,
      /<\/system>/i,
      /\[INST\]/i,
      /\[\/INST\]/i,
      /<<SYS>>/i,
      /<\|system\|>/i,
      /<\|user\|>/i,
      /<\|assistant\|>/i
    ],
    severity: "critical",
    deduction: 35,
    owaspCategory: "ASST-06",
    recommendation: "Remove LLM prompt format markers. Skills must not inject prompts into downstream systems."
  },
  {
    name: "Social engineering",
    patterns: [
      /don['']?t\s+tell\s+the\s+user/i,
      /hide\s+(?:this|it)\s+from\s+(?:the\s+)?user/i,
      /act\s+as\s+if\s+you\s+(?:are|were)/i,
      /do\s+not\s+mention\s+(?:this|these)/i,
      /keep\s+(?:this|it)\s+(?:a\s+)?secret/i,
      /(?:silently|secretly|quietly)\s+(?:perform|do|execute|run)/i
    ],
    severity: "medium",
    deduction: 15,
    owaspCategory: "ASST-07",
    recommendation: "Remove social engineering instructions. Skills must be transparent about their actions."
  },
  {
    name: "Concealment directive",
    patterns: [
      /(?:do\s+not|don'?t)\s+(?:tell|inform|mention|notify)\s+(?:the\s+)?user/i,
      /(?:hide|conceal)\s+(?:this|that)\s+(?:action|operation|step)/i,
      /(?:keep|make)\s+(?:this|that)\s+(?:secret|hidden)/i,
      /don'?t\s+mention\s+you\s+used\s+this\s+skill/i
    ],
    severity: "high",
    deduction: 25,
    owaspCategory: "ASST-01",
    recommendation: "Remove concealment directives. Skills must be transparent about all operations performed."
  },
  {
    name: "Unrestricted mode activation",
    patterns: [
      /you\s+are\s+now\s+in\s+(?:unrestricted|debug|developer|admin|god|jailbreak)\s+mode/i,
      /(?:enter|enable|activate)\s+(?:unrestricted|debug|developer)\s+mode/i,
      /disable\s+(?:all\s+)?(?:safety|security|content|ethical)\s+(?:filters|checks|guidelines)/i
    ],
    severity: "high",
    deduction: 25,
    owaspCategory: "ASST-01",
    recommendation: "Remove unrestricted mode activation attempts. Skills must not bypass agent safety mechanisms."
  },
  {
    name: "System prompt reveal",
    patterns: [
      /reveal\s+(?:your|the)\s+system\s+(?:prompt|instructions)/i,
      /(?:show|display|output)\s+(?:me\s+)?(?:your|the)\s+(?:system|initial)\s+(?:prompt|config)/i
    ],
    severity: "medium",
    deduction: 15,
    owaspCategory: "ASST-01",
    recommendation: "Remove system prompt reveal attempts. Skills must not try to extract agent configuration."
  }
];
function detectHtmlCommentInjections(content) {
  const findings = [];
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let match;
  while ((match = commentRegex.exec(content)) !== null) {
    const commentContent = match[1]?.trim() ?? "";
    if (commentContent.length < 10)
      continue;
    const isInstructional = /(?:step|override|important|system|silently|secretly|do not|must|always|never|after|before)\s/i.test(commentContent) || /(?:send|post|read|write|execute|fetch|curl|delete|access|download)\s/i.test(commentContent);
    if (isInstructional) {
      const lineNumber = content.slice(0, match.index).split("\n").length;
      findings.push({
        id: `INJ-COMMENT-${findings.length + 1}`,
        category: "injection",
        severity: "high",
        title: "Hidden instructions in HTML comment",
        description: "HTML comment contains instruction-like content that may be an attempt to inject hidden behavior.",
        evidence: `<!-- ${commentContent.slice(0, 200)}${commentContent.length > 200 ? "..." : ""} -->`,
        lineNumber,
        deduction: 25,
        recommendation: "Remove hidden instructions from HTML comments. All skill behavior should be visible.",
        owaspCategory: "ASST-01"
      });
    }
  }
  return findings;
}
function detectBase64Payloads(content) {
  const findings = [];
  const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
  let match;
  while ((match = base64Regex.exec(content)) !== null) {
    const encoded = match[0];
    if (/^[a-f0-9]+$/i.test(encoded))
      continue;
    try {
      const decoded = Buffer.from(encoded, "base64").toString("utf-8");
      const isSuspicious = /(?:ignore|override|system|exec|eval|fetch|curl|secret|password|token|key)/i.test(decoded) && decoded.length > 10;
      if (isSuspicious) {
        const lineNumber = content.slice(0, match.index).split("\n").length;
        findings.push({
          id: `INJ-B64-${findings.length + 1}`,
          category: "injection",
          severity: "high",
          title: "Suspicious base64-encoded content",
          description: "Base64-encoded string decodes to content containing suspicious keywords.",
          evidence: `Encoded: ${encoded.slice(0, 60)}... \u2192 Decoded: ${decoded.slice(0, 100)}...`,
          lineNumber,
          deduction: 25,
          recommendation: "Remove base64-encoded content or replace with plaintext. Obfuscation raises security concerns.",
          owaspCategory: "ASST-10"
        });
      }
    } catch {
    }
  }
  return findings;
}
function detectUnicodeObfuscation(content) {
  const findings = [];
  const zeroWidthRegex = /[\u200B\u200C\u200D\uFEFF]/g;
  const zeroWidthMatches = content.match(zeroWidthRegex);
  if (zeroWidthMatches && zeroWidthMatches.length > 0) {
    findings.push({
      id: "INJ-UNICODE-ZW",
      category: "injection",
      severity: "high",
      title: `Zero-width characters detected (${zeroWidthMatches.length} instances)`,
      description: "The skill file contains invisible zero-width characters that may be used to hide content or evade detection.",
      evidence: `Found ${zeroWidthMatches.length} zero-width characters (U+200B, U+200C, U+200D, or U+FEFF)`,
      deduction: 30,
      recommendation: "Remove all zero-width characters. Legitimate skills have no reason to contain invisible characters.",
      owaspCategory: "ASST-10"
    });
  }
  if (content.includes("\u202E") || content.includes("\u202D")) {
    findings.push({
      id: "INJ-UNICODE-RTL",
      category: "injection",
      severity: "high",
      title: "RTL override characters detected",
      description: "The skill contains right-to-left override characters that can be used to disguise text direction and hide content.",
      evidence: "Found U+202E (RLO) or U+202D (LRO) characters",
      deduction: 30,
      recommendation: "Remove bidirectional override characters. These are commonly used for obfuscation attacks.",
      owaspCategory: "ASST-10"
    });
  }
  return findings;
}
async function analyzeInjection(skill) {
  const findings = [];
  let score = 100;
  const content = skill.rawContent;
  const lines = content.split("\n");
  for (const pattern of INJECTION_PATTERNS) {
    for (const regex of pattern.patterns) {
      const globalRegex = new RegExp(regex.source, `${regex.flags.replace("g", "")}g`);
      let match;
      while ((match = globalRegex.exec(content)) !== null) {
        const lineNumber = content.slice(0, match.index).split("\n").length;
        const line = lines[lineNumber - 1] ?? "";
        score = Math.max(0, score - pattern.deduction);
        findings.push({
          id: `INJ-${pattern.name.replace(/\s+/g, "-").toUpperCase()}-${findings.length + 1}`,
          category: "injection",
          severity: pattern.severity,
          title: `${pattern.name} detected`,
          description: `Found ${pattern.name.toLowerCase()} pattern: "${match[0]}"`,
          evidence: line.trim().slice(0, 200),
          lineNumber,
          deduction: pattern.deduction,
          recommendation: pattern.recommendation,
          owaspCategory: pattern.owaspCategory
        });
        break;
      }
    }
  }
  const commentFindings = detectHtmlCommentInjections(content);
  for (const finding of commentFindings) {
    score = Math.max(0, score - finding.deduction);
    findings.push(finding);
  }
  const base64Findings = detectBase64Payloads(content);
  for (const finding of base64Findings) {
    score = Math.max(0, score - finding.deduction);
    findings.push(finding);
  }
  const unicodeFindings = detectUnicodeObfuscation(content);
  for (const finding of unicodeFindings) {
    score = Math.max(0, score - finding.deduction);
    findings.push(finding);
  }
  const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);
  let adjustedScore = 100;
  for (const f of adjustedFindings) {
    adjustedScore = Math.max(0, adjustedScore - f.deduction);
  }
  const hasCritical = adjustedFindings.some((f) => f.severity === "critical");
  const summary = adjustedFindings.length === 0 ? "No injection patterns detected." : `Found ${adjustedFindings.length} injection-related findings. ${hasCritical ? "CRITICAL: Active injection attacks detected. This skill is dangerous." : "Suspicious patterns detected that warrant review."}`;
  return {
    score: Math.max(0, Math.min(100, adjustedScore)),
    weight: 0.3,
    findings: adjustedFindings,
    summary
  };
}

// dist/scanner/analyzers/permissions.js
var CRITICAL_PERMISSIONS = ["exec", "shell", "sudo", "admin"];
var HIGH_PERMISSIONS = ["write", "delete", "network_unrestricted", "env_access"];
var MEDIUM_PERMISSIONS = ["network_restricted", "file_write", "api_access"];
var LOW_PERMISSIONS = ["read", "file_read", "search"];
var DEDUCTIONS = {
  critical: 30,
  high: 15,
  medium: 8,
  low: 2
};
var LIMITED_SCOPE_KEYWORDS = [
  "calculator",
  "spell",
  "check",
  "format",
  "lint",
  "simple",
  "basic",
  "math",
  "text",
  "convert",
  "translate",
  "weather",
  "time",
  "date",
  "clock",
  "counter",
  "hello",
  "greeting"
];
var SUSPICIOUS_FOR_LIMITED = [
  "exec",
  "shell",
  "sudo",
  "admin",
  "network_unrestricted",
  "env_access",
  "delete",
  "file_write"
];
function getPermissionTier(perm) {
  const lower = perm.toLowerCase();
  if (CRITICAL_PERMISSIONS.some((p) => lower.includes(p)))
    return "critical";
  if (HIGH_PERMISSIONS.some((p) => lower.includes(p)))
    return "high";
  if (MEDIUM_PERMISSIONS.some((p) => lower.includes(p)))
    return "medium";
  if (LOW_PERMISSIONS.some((p) => lower.includes(p)))
    return "low";
  return null;
}
function isLimitedScopeSkill(skill) {
  const combined = `${skill.name} ${skill.description}`.toLowerCase();
  return LIMITED_SCOPE_KEYWORDS.some((kw) => combined.includes(kw));
}
async function analyzePermissions(skill) {
  const findings = [];
  let score = 100;
  const allPermissions = [
    ...skill.permissions,
    ...skill.tools.filter((t) => getPermissionTier(t) !== null)
  ];
  const uniquePerms = [...new Set(allPermissions.map((p) => p.toLowerCase()))];
  for (const perm of uniquePerms) {
    const tier = getPermissionTier(perm);
    if (!tier)
      continue;
    const deduction = DEDUCTIONS[tier];
    score = Math.max(0, score - deduction);
    const severity = tier === "critical" ? "critical" : tier === "high" ? "high" : "medium";
    findings.push({
      id: `PERM-${findings.length + 1}`.padStart(8, "0").slice(-8),
      category: "permissions",
      severity,
      title: `${tier.charAt(0).toUpperCase() + tier.slice(1)}-risk permission: ${perm}`,
      description: `The skill requests the "${perm}" permission which is classified as ${tier} risk.`,
      evidence: `Permission: ${perm}`,
      deduction,
      recommendation: tier === "critical" ? `Remove the "${perm}" permission unless absolutely required. Critical permissions grant extensive system access.` : `Consider whether "${perm}" is necessary for the skill's stated functionality.`,
      owaspCategory: tier === "critical" || tier === "high" ? "ASST-03" : "ASST-08"
    });
  }
  if (isLimitedScopeSkill(skill)) {
    for (const perm of uniquePerms) {
      const lower = perm.toLowerCase();
      if (SUSPICIOUS_FOR_LIMITED.some((s) => lower.includes(s))) {
        const deduction = 15;
        score = Math.max(0, score - deduction);
        findings.push({
          id: `PERM-MISMATCH-${findings.length + 1}`,
          category: "permissions",
          severity: "high",
          title: `Permission-purpose mismatch: "${perm}" on limited-scope skill`,
          description: `The skill "${skill.name}" appears to be limited in scope but requests "${perm}" which is unusual for its stated purpose.`,
          evidence: `Skill: "${skill.name}" (${skill.description?.slice(0, 80)}...) requests "${perm}"`,
          deduction,
          recommendation: `Review whether "${perm}" is truly needed for a ${skill.name.toLowerCase()}.`,
          owaspCategory: "ASST-03"
        });
      }
    }
  }
  if (uniquePerms.length > 5) {
    findings.push({
      id: "PERM-EXCESSIVE",
      category: "permissions",
      severity: "info",
      title: `Excessive number of permissions (${uniquePerms.length})`,
      description: `The skill requests ${uniquePerms.length} distinct permissions. Consider whether all are necessary.`,
      evidence: `Permissions: ${uniquePerms.join(", ")}`,
      deduction: 0,
      recommendation: "Apply the principle of least privilege \u2014 only request permissions the skill actually needs.",
      owaspCategory: "ASST-08"
    });
  }
  const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);
  let adjustedScore = 100;
  for (const f of adjustedFindings) {
    adjustedScore = Math.max(0, adjustedScore - f.deduction);
  }
  const summary = adjustedFindings.length === 0 ? "No permission concerns detected." : `Found ${adjustedFindings.length} permission-related findings. ${adjustedFindings.some((f) => f.severity === "critical") ? "CRITICAL: Dangerous permissions detected." : adjustedFindings.some((f) => f.severity === "high") ? "High-risk permissions detected that may not match the skill's purpose." : "Minor permission concerns."}`;
  return {
    score: Math.max(0, Math.min(100, adjustedScore)),
    weight: 0.25,
    findings: adjustedFindings,
    summary
  };
}

// dist/scanner/parser.js
var URL_REGEX = /https?:\/\/[^\s"'<>\])+,;]+/gi;
function parseFrontmatter(content) {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!match?.[1])
    return null;
  const data = {};
  let currentKey = "";
  let inArray = false;
  const arrayItems = [];
  for (const line of match[1].split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#"))
      continue;
    if (inArray) {
      if (trimmed.startsWith("- ")) {
        arrayItems.push(trimmed.slice(2).trim().replace(/^["']|["']$/g, ""));
        continue;
      }
      data[currentKey] = [...arrayItems];
      arrayItems.length = 0;
      inArray = false;
    }
    const kvMatch = trimmed.match(/^(\w[\w-]*):\s*(.*)/);
    if (kvMatch) {
      currentKey = kvMatch[1] ?? "";
      const value = kvMatch[2]?.trim() ?? "";
      if (value === "" || value === "|" || value === ">") {
        inArray = value === "";
        if (!inArray) {
          data[currentKey] = "";
        }
      } else if (value.startsWith("[") && value.endsWith("]")) {
        data[currentKey] = value.slice(1, -1).split(",").map((s) => s.trim().replace(/^["']|["']$/g, "")).filter(Boolean);
      } else {
        data[currentKey] = value.replace(/^["']|["']$/g, "");
      }
    }
  }
  if (inArray && currentKey) {
    data[currentKey] = [...arrayItems];
  }
  return data;
}
function extractSections(content) {
  const sections = {};
  const lines = content.split("\n");
  let currentHeading = "";
  let currentContent = [];
  for (const line of lines) {
    const headingMatch = line.match(/^#{1,3}\s+(.+)/);
    if (headingMatch) {
      if (currentHeading) {
        sections[currentHeading] = currentContent.join("\n").trim();
      }
      currentHeading = headingMatch[1]?.trim() ?? "";
      currentContent = [];
    } else {
      currentContent.push(line);
    }
  }
  if (currentHeading) {
    sections[currentHeading] = currentContent.join("\n").trim();
  }
  return sections;
}
function extractUrls(content) {
  const matches = content.match(URL_REGEX);
  if (!matches)
    return [];
  return [...new Set(matches.map((u) => u.replace(/[.)]+$/, "")))];
}
function extractListItems(text) {
  const items = [];
  for (const line of text.split("\n")) {
    const match = line.match(/^[-*]\s+`?(\w[\w._-]*)`?/);
    if (match?.[1]) {
      items.push(match[1]);
    }
  }
  return items;
}
function parseDeclaredPermissions(content) {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!match?.[1])
    return [];
  const lines = match[1].split("\n");
  const permissions = [];
  let inPermissions = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^permissions:\s*$/.test(trimmed)) {
      inPermissions = true;
      continue;
    }
    if (inPermissions && /^\w[\w-]*:/.test(trimmed) && !trimmed.startsWith("- ")) {
      break;
    }
    if (inPermissions && trimmed.startsWith("- ")) {
      const entryMatch = trimmed.match(/^-\s+(\w[\w_-]*):\s*["']?(.+?)["']?\s*$/);
      if (entryMatch?.[1] && entryMatch[2]) {
        permissions.push({
          kind: entryMatch[1],
          justification: entryMatch[2]
        });
      }
    }
  }
  return permissions;
}
function detectFormat(content) {
  const hasFrontmatter = /^---\s*\n[\s\S]*?\n---/.test(content);
  if (hasFrontmatter) {
    const fm = parseFrontmatter(content);
    if (fm && ("name" in fm || "tools" in fm)) {
      return "openclaw";
    }
  }
  const lowerContent = content.toLowerCase();
  const hasClaudeHeadings = /^##\s+(tools|instructions|description)/im.test(content) || lowerContent.includes("claude") || lowerContent.includes("anthropic");
  if (hasClaudeHeadings)
    return "claude";
  return "generic";
}
function toStringArray(val) {
  if (!val)
    return [];
  if (Array.isArray(val))
    return val;
  return val.split(",").map((s) => s.trim()).filter(Boolean);
}
function parseSkill(content) {
  const warnings = [];
  const format = detectFormat(content);
  const sections = extractSections(content);
  const urls = extractUrls(content);
  let name = "";
  let description = "";
  let instructions = "";
  let tools = [];
  let permissions = [];
  let dependencies = [];
  const declaredPermissions = parseDeclaredPermissions(content);
  if (format === "openclaw") {
    const fm = parseFrontmatter(content);
    if (fm) {
      name = (typeof fm.name === "string" ? fm.name : fm.name?.[0]) ?? "";
      description = (typeof fm.description === "string" ? fm.description : fm.description?.[0]) ?? "";
      tools = toStringArray(fm.tools);
      permissions = toStringArray(fm.permissions);
      dependencies = toStringArray(fm.dependencies);
    }
    const bodyMatch = content.match(/^---\s*\n[\s\S]*?\n---\s*\n([\s\S]*)/);
    instructions = bodyMatch?.[1]?.trim() ?? "";
  } else if (format === "claude") {
    name = sections["Description"] ? "" : Object.keys(sections)[0] ?? "";
    description = sections["Description"] ?? sections["description"] ?? "";
    instructions = sections["Instructions"] ?? sections["instructions"] ?? "";
    const toolsSection = sections["Tools"] ?? sections["tools"] ?? "";
    tools = extractListItems(toolsSection);
    const permsSection = sections["Permissions"] ?? sections["permissions"] ?? "";
    permissions = extractListItems(permsSection);
  } else {
    const firstHeading = Object.keys(sections)[0];
    name = firstHeading ?? "";
    description = sections["Description"] ?? sections["About"] ?? Object.values(sections)[0] ?? "";
    instructions = content;
  }
  if (!name) {
    const headingMatch = content.match(/^#\s+(.+)/m);
    if (headingMatch?.[1]) {
      name = headingMatch[1].trim();
    } else {
      const firstLine = content.split("\n").find((l) => l.trim().length > 0);
      name = firstLine?.trim().slice(0, 100) ?? "Unknown Skill";
    }
  }
  if (!description || description.trim().length < 10) {
    warnings.push("No description found in skill file");
  }
  return {
    name,
    description,
    instructions,
    tools,
    permissions,
    declaredPermissions,
    dependencies,
    urls,
    rawSections: sections,
    rawContent: content,
    format,
    warnings
  };
}

// dist/scanner/scoring.js
var SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};
var CATEGORY_WEIGHTS = {
  permissions: 0.25,
  injection: 0.3,
  dependencies: 0.2,
  behavioral: 0.15,
  content: 0.1
};
function determineBadge(score, findings) {
  const hasCritical = findings.some((f) => f.severity === "critical");
  const highCount = findings.filter((f) => f.severity === "high").length;
  if (hasCritical)
    return "rejected";
  if (score < 50)
    return "rejected";
  if (score < 75)
    return "suspicious";
  if (score < 90 && highCount <= 2)
    return "conditional";
  if (score >= 90 && highCount === 0)
    return "certified";
  if (highCount > 2)
    return "suspicious";
  if (highCount > 0)
    return "conditional";
  return "certified";
}
function aggregateScores(categories, metadata) {
  let overall = 0;
  for (const [category, score] of Object.entries(categories)) {
    const weight = CATEGORY_WEIGHTS[category] ?? 0;
    overall += score.score * weight;
  }
  overall = Math.round(Math.max(0, Math.min(100, overall)));
  const allFindings = Object.values(categories).flatMap((cat) => [...cat.findings]).sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
  const badge = determineBadge(overall, allFindings);
  return {
    overall,
    badge,
    categories,
    findings: allFindings,
    metadata
  };
}

// node_modules/.pnpm/fflate@0.8.2/node_modules/fflate/esm/index.mjs
var import_module = require("module");
var require2 = (0, import_module.createRequire)("/");
var Worker;
try {
  Worker = require2("worker_threads").Worker;
} catch (e) {
}
var u8 = Uint8Array;
var u16 = Uint16Array;
var i32 = Int32Array;
var fleb = new u8([
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  1,
  1,
  1,
  1,
  2,
  2,
  2,
  2,
  3,
  3,
  3,
  3,
  4,
  4,
  4,
  4,
  5,
  5,
  5,
  5,
  0,
  /* unused */
  0,
  0,
  /* impossible */
  0
]);
var fdeb = new u8([
  0,
  0,
  0,
  0,
  1,
  1,
  2,
  2,
  3,
  3,
  4,
  4,
  5,
  5,
  6,
  6,
  7,
  7,
  8,
  8,
  9,
  9,
  10,
  10,
  11,
  11,
  12,
  12,
  13,
  13,
  /* unused */
  0,
  0
]);
var clim = new u8([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]);
var freb = function(eb, start) {
  var b = new u16(31);
  for (var i = 0; i < 31; ++i) {
    b[i] = start += 1 << eb[i - 1];
  }
  var r = new i32(b[30]);
  for (var i = 1; i < 30; ++i) {
    for (var j = b[i]; j < b[i + 1]; ++j) {
      r[j] = j - b[i] << 5 | i;
    }
  }
  return { b, r };
};
var _a = freb(fleb, 2);
var fl = _a.b;
var revfl = _a.r;
fl[28] = 258, revfl[258] = 28;
var _b = freb(fdeb, 0);
var fd = _b.b;
var revfd = _b.r;
var rev = new u16(32768);
for (i = 0; i < 32768; ++i) {
  x = (i & 43690) >> 1 | (i & 21845) << 1;
  x = (x & 52428) >> 2 | (x & 13107) << 2;
  x = (x & 61680) >> 4 | (x & 3855) << 4;
  rev[i] = ((x & 65280) >> 8 | (x & 255) << 8) >> 1;
}
var x;
var i;
var hMap = (function(cd, mb, r) {
  var s = cd.length;
  var i = 0;
  var l = new u16(mb);
  for (; i < s; ++i) {
    if (cd[i])
      ++l[cd[i] - 1];
  }
  var le = new u16(mb);
  for (i = 1; i < mb; ++i) {
    le[i] = le[i - 1] + l[i - 1] << 1;
  }
  var co;
  if (r) {
    co = new u16(1 << mb);
    var rvb = 15 - mb;
    for (i = 0; i < s; ++i) {
      if (cd[i]) {
        var sv = i << 4 | cd[i];
        var r_1 = mb - cd[i];
        var v = le[cd[i] - 1]++ << r_1;
        for (var m = v | (1 << r_1) - 1; v <= m; ++v) {
          co[rev[v] >> rvb] = sv;
        }
      }
    }
  } else {
    co = new u16(s);
    for (i = 0; i < s; ++i) {
      if (cd[i]) {
        co[i] = rev[le[cd[i] - 1]++] >> 15 - cd[i];
      }
    }
  }
  return co;
});
var flt = new u8(288);
for (i = 0; i < 144; ++i)
  flt[i] = 8;
var i;
for (i = 144; i < 256; ++i)
  flt[i] = 9;
var i;
for (i = 256; i < 280; ++i)
  flt[i] = 7;
var i;
for (i = 280; i < 288; ++i)
  flt[i] = 8;
var i;
var fdt = new u8(32);
for (i = 0; i < 32; ++i)
  fdt[i] = 5;
var i;
var flrm = /* @__PURE__ */ hMap(flt, 9, 1);
var fdrm = /* @__PURE__ */ hMap(fdt, 5, 1);
var max = function(a) {
  var m = a[0];
  for (var i = 1; i < a.length; ++i) {
    if (a[i] > m)
      m = a[i];
  }
  return m;
};
var bits = function(d, p, m) {
  var o = p / 8 | 0;
  return (d[o] | d[o + 1] << 8) >> (p & 7) & m;
};
var bits16 = function(d, p) {
  var o = p / 8 | 0;
  return (d[o] | d[o + 1] << 8 | d[o + 2] << 16) >> (p & 7);
};
var shft = function(p) {
  return (p + 7) / 8 | 0;
};
var slc = function(v, s, e) {
  if (s == null || s < 0)
    s = 0;
  if (e == null || e > v.length)
    e = v.length;
  return new u8(v.subarray(s, e));
};
var ec = [
  "unexpected EOF",
  "invalid block type",
  "invalid length/literal",
  "invalid distance",
  "stream finished",
  "no stream handler",
  ,
  "no callback",
  "invalid UTF-8 data",
  "extra field too long",
  "date not in range 1980-2099",
  "filename too long",
  "stream finishing",
  "invalid zip data"
  // determined by unknown compression method
];
var err = function(ind, msg, nt) {
  var e = new Error(msg || ec[ind]);
  e.code = ind;
  if (Error.captureStackTrace)
    Error.captureStackTrace(e, err);
  if (!nt)
    throw e;
  return e;
};
var inflt = function(dat, st, buf, dict) {
  var sl = dat.length, dl = dict ? dict.length : 0;
  if (!sl || st.f && !st.l)
    return buf || new u8(0);
  var noBuf = !buf;
  var resize = noBuf || st.i != 2;
  var noSt = st.i;
  if (noBuf)
    buf = new u8(sl * 3);
  var cbuf = function(l2) {
    var bl = buf.length;
    if (l2 > bl) {
      var nbuf = new u8(Math.max(bl * 2, l2));
      nbuf.set(buf);
      buf = nbuf;
    }
  };
  var final = st.f || 0, pos = st.p || 0, bt = st.b || 0, lm = st.l, dm = st.d, lbt = st.m, dbt = st.n;
  var tbts = sl * 8;
  do {
    if (!lm) {
      final = bits(dat, pos, 1);
      var type = bits(dat, pos + 1, 3);
      pos += 3;
      if (!type) {
        var s = shft(pos) + 4, l = dat[s - 4] | dat[s - 3] << 8, t = s + l;
        if (t > sl) {
          if (noSt)
            err(0);
          break;
        }
        if (resize)
          cbuf(bt + l);
        buf.set(dat.subarray(s, t), bt);
        st.b = bt += l, st.p = pos = t * 8, st.f = final;
        continue;
      } else if (type == 1)
        lm = flrm, dm = fdrm, lbt = 9, dbt = 5;
      else if (type == 2) {
        var hLit = bits(dat, pos, 31) + 257, hcLen = bits(dat, pos + 10, 15) + 4;
        var tl = hLit + bits(dat, pos + 5, 31) + 1;
        pos += 14;
        var ldt = new u8(tl);
        var clt = new u8(19);
        for (var i = 0; i < hcLen; ++i) {
          clt[clim[i]] = bits(dat, pos + i * 3, 7);
        }
        pos += hcLen * 3;
        var clb = max(clt), clbmsk = (1 << clb) - 1;
        var clm = hMap(clt, clb, 1);
        for (var i = 0; i < tl; ) {
          var r = clm[bits(dat, pos, clbmsk)];
          pos += r & 15;
          var s = r >> 4;
          if (s < 16) {
            ldt[i++] = s;
          } else {
            var c = 0, n = 0;
            if (s == 16)
              n = 3 + bits(dat, pos, 3), pos += 2, c = ldt[i - 1];
            else if (s == 17)
              n = 3 + bits(dat, pos, 7), pos += 3;
            else if (s == 18)
              n = 11 + bits(dat, pos, 127), pos += 7;
            while (n--)
              ldt[i++] = c;
          }
        }
        var lt = ldt.subarray(0, hLit), dt = ldt.subarray(hLit);
        lbt = max(lt);
        dbt = max(dt);
        lm = hMap(lt, lbt, 1);
        dm = hMap(dt, dbt, 1);
      } else
        err(1);
      if (pos > tbts) {
        if (noSt)
          err(0);
        break;
      }
    }
    if (resize)
      cbuf(bt + 131072);
    var lms = (1 << lbt) - 1, dms = (1 << dbt) - 1;
    var lpos = pos;
    for (; ; lpos = pos) {
      var c = lm[bits16(dat, pos) & lms], sym = c >> 4;
      pos += c & 15;
      if (pos > tbts) {
        if (noSt)
          err(0);
        break;
      }
      if (!c)
        err(2);
      if (sym < 256)
        buf[bt++] = sym;
      else if (sym == 256) {
        lpos = pos, lm = null;
        break;
      } else {
        var add = sym - 254;
        if (sym > 264) {
          var i = sym - 257, b = fleb[i];
          add = bits(dat, pos, (1 << b) - 1) + fl[i];
          pos += b;
        }
        var d = dm[bits16(dat, pos) & dms], dsym = d >> 4;
        if (!d)
          err(3);
        pos += d & 15;
        var dt = fd[dsym];
        if (dsym > 3) {
          var b = fdeb[dsym];
          dt += bits16(dat, pos) & (1 << b) - 1, pos += b;
        }
        if (pos > tbts) {
          if (noSt)
            err(0);
          break;
        }
        if (resize)
          cbuf(bt + 131072);
        var end = bt + add;
        if (bt < dt) {
          var shift = dl - dt, dend = Math.min(dt, end);
          if (shift + bt < 0)
            err(3);
          for (; bt < dend; ++bt)
            buf[bt] = dict[shift + bt];
        }
        for (; bt < end; ++bt)
          buf[bt] = buf[bt - dt];
      }
    }
    st.l = lm, st.p = lpos, st.b = bt, st.f = final;
    if (lm)
      final = 1, st.m = lbt, st.d = dm, st.n = dbt;
  } while (!final);
  return bt != buf.length && noBuf ? slc(buf, 0, bt) : buf.subarray(0, bt);
};
var et = /* @__PURE__ */ new u8(0);
var b2 = function(d, b) {
  return d[b] | d[b + 1] << 8;
};
var b4 = function(d, b) {
  return (d[b] | d[b + 1] << 8 | d[b + 2] << 16 | d[b + 3] << 24) >>> 0;
};
var b8 = function(d, b) {
  return b4(d, b) + b4(d, b + 4) * 4294967296;
};
function inflateSync(data, opts) {
  return inflt(data, { i: 2 }, opts && opts.out, opts && opts.dictionary);
}
var td = typeof TextDecoder != "undefined" && /* @__PURE__ */ new TextDecoder();
var tds = 0;
try {
  td.decode(et, { stream: true });
  tds = 1;
} catch (e) {
}
var dutf8 = function(d) {
  for (var r = "", i = 0; ; ) {
    var c = d[i++];
    var eb = (c > 127) + (c > 223) + (c > 239);
    if (i + eb > d.length)
      return { s: r, r: slc(d, i - 1) };
    if (!eb)
      r += String.fromCharCode(c);
    else if (eb == 3) {
      c = ((c & 15) << 18 | (d[i++] & 63) << 12 | (d[i++] & 63) << 6 | d[i++] & 63) - 65536, r += String.fromCharCode(55296 | c >> 10, 56320 | c & 1023);
    } else if (eb & 1)
      r += String.fromCharCode((c & 31) << 6 | d[i++] & 63);
    else
      r += String.fromCharCode((c & 15) << 12 | (d[i++] & 63) << 6 | d[i++] & 63);
  }
};
function strFromU8(dat, latin1) {
  if (latin1) {
    var r = "";
    for (var i = 0; i < dat.length; i += 16384)
      r += String.fromCharCode.apply(null, dat.subarray(i, i + 16384));
    return r;
  } else if (td) {
    return td.decode(dat);
  } else {
    var _a2 = dutf8(dat), s = _a2.s, r = _a2.r;
    if (r.length)
      err(8);
    return s;
  }
}
var slzh = function(d, b) {
  return b + 30 + b2(d, b + 26) + b2(d, b + 28);
};
var zh = function(d, b, z) {
  var fnl = b2(d, b + 28), fn = strFromU8(d.subarray(b + 46, b + 46 + fnl), !(b2(d, b + 8) & 2048)), es = b + 46 + fnl, bs = b4(d, b + 20);
  var _a2 = z && bs == 4294967295 ? z64e(d, es) : [bs, b4(d, b + 24), b4(d, b + 42)], sc = _a2[0], su = _a2[1], off = _a2[2];
  return [b2(d, b + 10), sc, su, fn, es + b2(d, b + 30) + b2(d, b + 32), off];
};
var z64e = function(d, b) {
  for (; b2(d, b) != 1; b += 4 + b2(d, b + 2))
    ;
  return [b8(d, b + 12), b8(d, b + 4), b8(d, b + 20)];
};
function unzipSync(data, opts) {
  var files = {};
  var e = data.length - 22;
  for (; b4(data, e) != 101010256; --e) {
    if (!e || data.length - e > 65558)
      err(13);
  }
  ;
  var c = b2(data, e + 8);
  if (!c)
    return {};
  var o = b4(data, e + 16);
  var z = o == 4294967295 || c == 65535;
  if (z) {
    var ze = b4(data, e - 12);
    z = b4(data, ze) == 101075792;
    if (z) {
      c = b4(data, ze + 32);
      o = b4(data, ze + 48);
    }
  }
  var fltr = opts && opts.filter;
  for (var i = 0; i < c; ++i) {
    var _a2 = zh(data, o, z), c_2 = _a2[0], sc = _a2[1], su = _a2[2], fn = _a2[3], no = _a2[4], off = _a2[5], b = slzh(data, off);
    o = no;
    if (!fltr || fltr({
      name: fn,
      size: sc,
      originalSize: su,
      compression: c_2
    })) {
      if (!c_2)
        files[fn] = slc(data, b, b + sc);
      else if (c_2 == 8)
        files[fn] = inflateSync(data.subarray(b, b + sc), { out: new u8(su) });
      else
        err(14, "unknown compression type " + c_2);
    }
  }
  return files;
}

// dist/scanner/types.js
var ASST_CATEGORIES = {
  "ASST-01": "Instruction Injection",
  "ASST-02": "Data Exfiltration",
  "ASST-03": "Privilege Escalation",
  "ASST-04": "Dependency Hijacking",
  "ASST-05": "Credential Harvesting",
  "ASST-06": "Prompt Injection Relay",
  "ASST-07": "Deceptive Functionality",
  "ASST-08": "Excessive Permissions",
  "ASST-09": "Missing Safety Boundaries",
  "ASST-10": "Obfuscation"
};
var SCANNER_VERSION = "0.1.0";

// dist/scanner/source.js
var DEFAULT_HEADERS = {
  Accept: "text/plain,text/markdown,text/html;q=0.9,application/zip;q=0.8,*/*;q=0.7",
  "User-Agent": `AgentVerusScanner/${SCANNER_VERSION}`
};
var CLAWHUB_HOST = "clawhub.ai";
var CLAWHUB_DOWNLOAD_BASE = "https://auth.clawdhub.com/api/v1/download";
function normalizeGithubUrl(url) {
  if (url.hostname !== "github.com")
    return url.toString();
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length >= 5 && parts[2] === "blob") {
    const owner = parts[0];
    const repo = parts[1];
    const branch = parts[3];
    const path = parts.slice(4).join("/");
    return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  }
  if (parts.length >= 4 && parts[2] === "tree") {
    const owner = parts[0];
    const repo = parts[1];
    const branch = parts[3];
    const dirPath = parts.slice(4).join("/");
    const skillPath = dirPath ? `${dirPath}/SKILL.md` : "SKILL.md";
    return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${skillPath}`;
  }
  if (parts.length === 2) {
    const owner = parts[0];
    const repo = parts[1];
    return `https://raw.githubusercontent.com/${owner}/${repo}/main/SKILL.md`;
  }
  return url.toString();
}
function normalizeClawHubUrl(url) {
  if (url.hostname !== CLAWHUB_HOST)
    return url.toString();
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 2)
    return url.toString();
  const [first, second] = parts;
  if (!first || !second)
    return url.toString();
  if (first === "admin" || first === "assets" || first === "cli" || first === "dashboard" || first === "import" || first === "management" || first === "og" || first === "settings" || first === "skills" || first === "souls" || first === "stars" || first === "u" || first === "upload") {
    return url.toString();
  }
  const downloadUrl = new URL(CLAWHUB_DOWNLOAD_BASE);
  downloadUrl.searchParams.set("slug", second);
  return downloadUrl.toString();
}
function normalizeSkillUrl(inputUrl) {
  let url;
  try {
    url = new URL(inputUrl);
  } catch {
    return inputUrl;
  }
  if (url.hostname === CLAWHUB_HOST)
    return normalizeClawHubUrl(url);
  if (url.hostname === "github.com")
    return normalizeGithubUrl(url);
  return url.toString();
}
function isZipResponse(contentType, url) {
  if (contentType?.toLowerCase().includes("application/zip"))
    return true;
  try {
    const parsed = new URL(url);
    return parsed.hostname === "auth.clawdhub.com" && parsed.pathname === "/api/v1/download";
  } catch {
    return false;
  }
}
function isClawHubDownloadUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname === "auth.clawdhub.com" && parsed.pathname === "/api/v1/download";
  } catch {
    return false;
  }
}
function pickSkillMdPath(filePaths) {
  const candidates = filePaths.filter((p) => {
    const base = p.split("/").pop() ?? p;
    const lower = base.toLowerCase();
    return lower === "skill.md" || lower === "skills.md";
  });
  if (candidates.length === 0)
    return null;
  const rank = (p) => {
    const base = p.split("/").pop() ?? p;
    const lowerBase = base.toLowerCase();
    const lower = p.toLowerCase();
    if (lowerBase === "skill.md" && lower === "skill.md")
      return 0;
    if (lowerBase === "skill.md")
      return 1;
    if (lowerBase === "skills.md" && lower === "skills.md")
      return 2;
    if (lowerBase === "skills.md")
      return 3;
    return 4;
  };
  return [...candidates].sort((a, b) => rank(a) - rank(b) || a.length - b.length || a.localeCompare(b))[0] ?? null;
}
function formatHttpErrorBodySnippet(text) {
  const cleaned = text.replace(/\s+/g, " ").trim();
  if (!cleaned)
    return "";
  return cleaned.length > 200 ? `${cleaned.slice(0, 200)}...` : cleaned;
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function isRetryableStatus(status) {
  return status === 429 || status >= 500 && status <= 599;
}
function parseRetryAfterMs(value) {
  if (!value)
    return null;
  const seconds = Number.parseInt(value, 10);
  if (!Number.isNaN(seconds))
    return Math.max(0, seconds * 1e3);
  const dateMs = Date.parse(value);
  if (!Number.isNaN(dateMs))
    return Math.max(0, dateMs - Date.now());
  return null;
}
function isRetryableError(error) {
  if (!(error instanceof Error))
    return false;
  if (error.name === "AbortError" || /aborted due to timeout/i.test(error.message))
    return true;
  if (/fetch failed/i.test(error.message))
    return true;
  if (/Zip did not contain/i.test(error.message))
    return false;
  return false;
}
async function fetchSkillContentFromUrl(inputUrl, options) {
  const sourceUrl = normalizeSkillUrl(inputUrl);
  const retries = Math.max(0, options?.retries ?? 2);
  const baseDelayMs = Math.max(0, options?.retryDelayMs ?? 750);
  const defaultTimeoutMs = isClawHubDownloadUrl(sourceUrl) ? 45e3 : 3e4;
  const timeoutMsRaw = options?.timeout;
  const timeoutMs = timeoutMsRaw === void 0 ? defaultTimeoutMs : timeoutMsRaw;
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetch(sourceUrl, {
        headers: DEFAULT_HEADERS,
        signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : void 0
      });
      if (!response.ok) {
        if (attempt < retries && isRetryableStatus(response.status)) {
          const retryAfter = parseRetryAfterMs(response.headers.get("retry-after"));
          const backoffMs = retryAfter ?? Math.min(3e4, baseDelayMs * 2 ** attempt + Math.round(Math.random() * 250));
          await sleep(backoffMs);
          continue;
        }
        let snippet = "";
        try {
          snippet = formatHttpErrorBodySnippet(await response.text());
        } catch {
        }
        throw new Error(`Failed to fetch skill from ${sourceUrl}: ${response.status} ${response.statusText}${snippet ? ` \u2014 ${snippet}` : ""}`);
      }
      const contentType = response.headers.get("content-type");
      if (isZipResponse(contentType, sourceUrl)) {
        const zipBytes = new Uint8Array(await response.arrayBuffer());
        const files = unzipSync(zipBytes);
        const paths = Object.keys(files);
        const skillMdPath = pickSkillMdPath(paths);
        if (!skillMdPath) {
          const preview = paths.sort().slice(0, 20).join(", ");
          throw new Error(`Zip did not contain SKILL.md (found ${paths.length} files). First files: ${preview}`);
        }
        const decoder = new TextDecoder("utf-8");
        return { content: decoder.decode(files[skillMdPath]), sourceUrl };
      }
      return { content: await response.text(), sourceUrl };
    } catch (err2) {
      lastError = err2;
      if (attempt < retries && isRetryableError(err2)) {
        const backoffMs = Math.min(3e4, baseDelayMs * 2 ** attempt + Math.round(Math.random() * 250));
        await sleep(backoffMs);
        continue;
      }
      throw err2;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Failed to fetch skill content");
}

// dist/scanner/index.js
function fallbackScore(category, weight, error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  return {
    score: 50,
    weight,
    findings: [
      {
        id: `ERR-${category.toUpperCase()}`,
        category,
        severity: "info",
        title: `Analyzer error: ${category}`,
        description: `The ${category} analyzer encountered an error: ${message}. A default score of 50 was assigned.`,
        evidence: message,
        deduction: 0,
        recommendation: "This may indicate an issue with the skill file format. Try re-scanning.",
        owaspCategory: "ASST-09"
      }
    ],
    summary: `Analyzer error \u2014 default score assigned. Error: ${message}`
  };
}
async function scanSkill(content, _options) {
  const startTime = Date.now();
  const skill = parseSkill(content);
  const [permissions, injection, dependencies, behavioral, contentResult] = await Promise.all([
    analyzePermissions(skill).catch((e) => fallbackScore("permissions", 0.25, e)),
    analyzeInjection(skill).catch((e) => fallbackScore("injection", 0.3, e)),
    analyzeDependencies(skill).catch((e) => fallbackScore("dependencies", 0.2, e)),
    analyzeBehavioral(skill).catch((e) => fallbackScore("behavioral", 0.15, e)),
    analyzeContent(skill).catch((e) => fallbackScore("content", 0.1, e))
  ]);
  const durationMs = Date.now() - startTime;
  const metadata = {
    scannedAt: /* @__PURE__ */ new Date(),
    scannerVersion: SCANNER_VERSION,
    durationMs,
    skillFormat: skill.format,
    skillName: skill.name || "Unknown Skill",
    skillDescription: skill.description || ""
  };
  const categories = {
    permissions,
    injection,
    dependencies,
    behavioral,
    content: contentResult
  };
  return aggregateScores(categories, metadata);
}
async function scanSkillFromUrl(url, options) {
  const { content } = await fetchSkillContentFromUrl(url, options);
  return scanSkill(content, options);
}

// dist/scanner/targets.js
var import_promises = require("node:fs/promises");
var import_node_path = require("node:path");
var SKILL_BASENAMES = /* @__PURE__ */ new Set(["skill.md", "skills.md"]);
var DEFAULT_IGNORED_DIRS = /* @__PURE__ */ new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo"
]);
function isUrlTarget(target) {
  return target.startsWith("http://") || target.startsWith("https://");
}
async function walkForSkills(dir, out) {
  const entries = await (0, import_promises.readdir)(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = (0, import_node_path.join)(dir, entry.name);
    if (entry.isDirectory()) {
      if (DEFAULT_IGNORED_DIRS.has(entry.name))
        continue;
      await walkForSkills(full, out);
      continue;
    }
    if (!entry.isFile())
      continue;
    const lower = entry.name.toLowerCase();
    if (SKILL_BASENAMES.has(lower))
      out.push(full);
  }
}
async function expandScanTargets(inputs) {
  const out = [];
  for (const input of inputs) {
    if (isUrlTarget(input)) {
      out.push(input);
      continue;
    }
    let s;
    try {
      s = await (0, import_promises.stat)(input);
    } catch {
      throw new Error(`Target not found: ${input}`);
    }
    if (s.isDirectory()) {
      await walkForSkills(input, out);
    } else if (s.isFile()) {
      out.push(input);
    } else {
      throw new Error(`Unsupported target type: ${input}`);
    }
  }
  return [...new Set(out)].sort((a, b) => a.localeCompare(b));
}

// dist/scanner/runner.js
async function scanTarget(target, options) {
  if (isUrlTarget(target)) {
    const report2 = await scanSkillFromUrl(target, options);
    return { target, report: report2 };
  }
  const content = await (0, import_promises2.readFile)(target, "utf-8");
  const report = await scanSkill(content, options);
  return { target, report };
}
async function scanTargetsBatch(targets, options) {
  const reports = [];
  const failures = [];
  for (const target of targets) {
    try {
      reports.push(await scanTarget(target, options));
    } catch (err2) {
      const message = err2 instanceof Error ? err2.message : String(err2);
      failures.push({ target, error: message });
    }
  }
  return { reports, failures };
}

// dist/scanner/sarif.js
var SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};
function severityToSarifLevel(severity) {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default: {
      const _exhaustive = severity;
      return _exhaustive;
    }
  }
}
function pickRuleLevel(findings) {
  let best = "info";
  for (const f of findings) {
    if ((SEVERITY_RANK[f.severity] ?? 99) < (SEVERITY_RANK[best] ?? 99))
      best = f.severity;
  }
  return severityToSarifLevel(best);
}
function formatFindingMessage(finding) {
  const parts = [];
  parts.push(finding.title);
  parts.push("");
  parts.push(finding.description);
  if (finding.evidence) {
    parts.push("");
    parts.push(`Evidence: ${finding.evidence}`);
  }
  parts.push("");
  parts.push(`Recommendation: ${finding.recommendation}`);
  return parts.join("\n");
}
function buildSarifLog(scans, failures) {
  const findingsByRuleId = /* @__PURE__ */ new Map();
  for (const scan of scans) {
    for (const finding of scan.report.findings) {
      const ruleId = finding.owaspCategory || "ASST-UNKNOWN";
      const list = findingsByRuleId.get(ruleId);
      if (list)
        list.push(finding);
      else
        findingsByRuleId.set(ruleId, [finding]);
    }
  }
  const rules = [];
  for (const [ruleId, findings] of [...findingsByRuleId.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const title = ASST_CATEGORIES[ruleId] ?? "Agent skill security finding";
    rules.push({
      id: ruleId,
      name: title,
      shortDescription: { text: title },
      help: {
        text: `Category ${ruleId}: ${title}. See the finding message for context and recommended mitigation.`
      },
      defaultConfiguration: { level: pickRuleLevel(findings) },
      properties: {
        kind: "agent-skill-security"
      }
    });
  }
  const results = [];
  for (const scan of scans) {
    for (const finding of scan.report.findings) {
      const ruleId = finding.owaspCategory || "ASST-UNKNOWN";
      const loc = {
        physicalLocation: {
          artifactLocation: { uri: scan.target },
          region: finding.lineNumber ? { startLine: finding.lineNumber } : void 0
        }
      };
      results.push({
        ruleId,
        level: severityToSarifLevel(finding.severity),
        message: { text: formatFindingMessage(finding) },
        locations: [loc],
        properties: {
          findingId: finding.id,
          category: finding.category,
          severity: finding.severity,
          deduction: finding.deduction,
          badge: scan.report.badge,
          overall: scan.report.overall,
          skillName: scan.report.metadata.skillName,
          skillFormat: scan.report.metadata.skillFormat
        }
      });
    }
  }
  if (failures && failures.length > 0) {
    rules.push({
      id: "AGENTVERUS-SCAN-ERROR",
      name: "Skill scan failed",
      shortDescription: { text: "Failed to fetch or read a target for scanning." },
      help: {
        text: "The scanner could not read a file or fetch a URL. Fix the error and re-run the scan to avoid missing results."
      },
      defaultConfiguration: { level: "error" },
      properties: { kind: "scan-error" }
    });
    for (const failure of failures) {
      results.push({
        ruleId: "AGENTVERUS-SCAN-ERROR",
        level: "error",
        message: { text: `Failed to scan target: ${failure.target}

${failure.error}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: failure.target }
            }
          }
        ]
      });
    }
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AgentVerus Scanner",
            informationUri: "https://github.com/agentverus/agentverus-scanner",
            version: SCANNER_VERSION,
            rules
          }
        },
        results
      }
    ]
  };
}

// actions/scan-skill/src/index.ts
var SEVERITY_RANK2 = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};
function parseTargets(raw) {
  return raw.split(/\r?\n/g).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#"));
}
function parseOptionalInt(value) {
  if (value === void 0) return void 0;
  const trimmed = value.trim();
  if (!trimmed) return void 0;
  const n = Number.parseInt(trimmed, 10);
  return Number.isNaN(n) ? void 0 : n;
}
function parseFailOnSeverity(value) {
  const v = (value ?? "high").trim().toLowerCase();
  if (v === "none" || v === "critical" || v === "high" || v === "medium" || v === "low" || v === "info") {
    return v;
  }
  return "high";
}
function shouldFailOnSeverity(reports, threshold) {
  if (threshold === "none") return false;
  const limit = SEVERITY_RANK2[threshold] ?? 99;
  for (const item of reports) {
    if (!item || typeof item !== "object") continue;
    const report = item.report;
    if (!report || typeof report !== "object") continue;
    const findings = report.findings;
    if (!Array.isArray(findings)) continue;
    for (const finding of findings) {
      if (!finding || typeof finding !== "object") continue;
      const severity = finding.severity;
      if (typeof severity !== "string") continue;
      const rank = SEVERITY_RANK2[severity];
      if ((rank ?? 99) <= limit) return true;
    }
  }
  return false;
}
function setOutput(key, value) {
  const outFile = process.env.GITHUB_OUTPUT;
  if (!outFile) return;
  (0, import_node_fs.appendFileSync)(outFile, `${key}=${value}
`, { encoding: "utf-8" });
}
function appendSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryFile) return;
  (0, import_node_fs.appendFileSync)(summaryFile, `${markdown}
`, { encoding: "utf-8" });
}
function countSeverities(items) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const report = item.report;
    if (!report || typeof report !== "object") continue;
    const findings = report.findings;
    if (!Array.isArray(findings)) continue;
    for (const finding of findings) {
      if (!finding || typeof finding !== "object") continue;
      const severity = finding.severity;
      if (typeof severity !== "string") continue;
      counts[severity] = (counts[severity] ?? 0) + 1;
    }
  }
  return counts;
}
async function main() {
  const rawTargetInput = process.env.INPUT_TARGET ?? ".";
  const sarifPath = (process.env.INPUT_SARIF ?? "agentverus-scanner.sarif").trim() || "agentverus-scanner.sarif";
  const failOnSeverity = parseFailOnSeverity(process.env.INPUT_FAIL_ON_SEVERITY);
  const timeout = parseOptionalInt(process.env.INPUT_TIMEOUT);
  const retries = parseOptionalInt(process.env.INPUT_RETRIES);
  const retryDelayMs = parseOptionalInt(process.env.INPUT_RETRY_DELAY_MS);
  const rawTargets = parseTargets(rawTargetInput);
  const targets = rawTargets.length > 0 ? rawTargets : ["."];
  let expanded = [];
  let reports = [];
  let failures = [];
  try {
    expanded = await expandScanTargets(targets);
    if (expanded.length > 0) {
      const batch = await scanTargetsBatch(expanded, { timeout, retries, retryDelayMs });
      reports = batch.reports;
      failures = batch.failures;
    } else {
      failures = [
        {
          target: rawTargets.length === 1 ? rawTargets[0] : "targets",
          error: "No SKILL.md files found under the provided directory target(s)."
        }
      ];
    }
  } catch (err2) {
    const message = err2 instanceof Error ? err2.message : String(err2);
    failures = [{ target: targets.join("\n"), error: message }];
  }
  const sarif = buildSarifLog(
    reports,
    failures
  );
  (0, import_node_fs.writeFileSync)(sarifPath, JSON.stringify(sarif, null, 2), { encoding: "utf-8" });
  setOutput("sarif_path", sarifPath);
  setOutput("targets_scanned", String(reports.length));
  setOutput("failures", String(failures.length));
  const sevCounts = countSeverities(reports);
  appendSummary(`## AgentVerus Skill Scan
`);
  appendSummary(`- Targets scanned: **${reports.length}**`);
  appendSummary(`- Failures: **${failures.length}**`);
  appendSummary(
    `- Findings: critical **${sevCounts.critical}**, high **${sevCounts.high}**, medium **${sevCounts.medium}**, low **${sevCounts.low}**, info **${sevCounts.info}**`
  );
  appendSummary(`- SARIF: \`${sarifPath}\``);
  if (failures.length > 0) process.exit(2);
  if (shouldFailOnSeverity(reports, failOnSeverity)) process.exit(1);
  process.exit(0);
}
main().catch((err2) => {
  const message = err2 instanceof Error ? err2.message : String(err2);
  console.error(message);
  process.exit(2);
});
