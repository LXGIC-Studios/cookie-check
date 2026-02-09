#!/usr/bin/env node

import * as https from "https";
import * as http from "http";
import * as url from "url";

// ANSI colors
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
};

interface CookieAttribute {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
  path: string | null;
  domain: string | null;
  expires: string | null;
  maxAge: number | null;
}

interface CookieAudit {
  cookie: CookieAttribute;
  grade: "A" | "B" | "C" | "D" | "F";
  score: number;
  issues: string[];
  recommendations: string[];
}

interface AuditResult {
  url: string;
  statusCode: number;
  cookies: CookieAudit[];
  summary: {
    total: number;
    gradeA: number;
    gradeB: number;
    gradeC: number;
    gradeD: number;
    gradeF: number;
    averageScore: number;
  };
}

const HELP = `
${c.bold}${c.cyan}cookie-check${c.reset} - Audit Set-Cookie headers for security issues

${c.bold}USAGE${c.reset}
  ${c.green}npx @lxgicstudios/cookie-check${c.reset} <url> [options]
  ${c.green}npx @lxgicstudios/cookie-check${c.reset} https://example.com
  ${c.green}npx @lxgicstudios/cookie-check${c.reset} https://example.com --json

${c.bold}OPTIONS${c.reset}
  --help              Show this help message
  --json              Output results as JSON (great for CI)
  --ci                Exit with code 1 if any cookie grades below threshold
  --min-grade <grade> Minimum acceptable grade (A-F, default: C)
  --follow-redirects  Follow HTTP redirects (default: true)
  --no-redirects      Don't follow redirects
  --timeout <ms>      Request timeout in milliseconds (default: 10000)
  --header <h>        Add custom header (format: "Name: Value", repeatable)
  --verbose           Show all cookie attributes

${c.bold}EXAMPLES${c.reset}
  ${c.dim}# Audit cookies on a site${c.reset}
  npx @lxgicstudios/cookie-check https://example.com

  ${c.dim}# CI mode with minimum grade${c.reset}
  npx @lxgicstudios/cookie-check https://example.com --ci --min-grade B

  ${c.dim}# JSON output${c.reset}
  npx @lxgicstudios/cookie-check https://example.com --json

  ${c.dim}# With custom headers${c.reset}
  npx @lxgicstudios/cookie-check https://example.com --header "Authorization: Bearer token123"
`;

function parseArgs(argv: string[]) {
  const args = {
    help: false,
    json: false,
    ci: false,
    minGrade: "C" as string,
    followRedirects: true,
    timeout: 10000,
    headers: {} as Record<string, string>,
    verbose: false,
    url: "",
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--help":
      case "-h":
        args.help = true;
        break;
      case "--json":
        args.json = true;
        break;
      case "--ci":
        args.ci = true;
        break;
      case "--min-grade":
        args.minGrade = (argv[++i] || "C").toUpperCase();
        break;
      case "--follow-redirects":
        args.followRedirects = true;
        break;
      case "--no-redirects":
        args.followRedirects = false;
        break;
      case "--timeout":
        args.timeout = parseInt(argv[++i] || "10000", 10);
        break;
      case "--header":
        {
          const header = argv[++i] || "";
          const idx = header.indexOf(":");
          if (idx > 0) {
            args.headers[header.slice(0, idx).trim()] = header.slice(idx + 1).trim();
          }
        }
        break;
      case "--verbose":
      case "-v":
        args.verbose = true;
        break;
      default:
        if (!arg.startsWith("-") && !args.url) {
          args.url = arg;
        }
        break;
    }
  }

  return args;
}

function fetchUrl(
  targetUrl: string,
  options: {
    followRedirects: boolean;
    timeout: number;
    headers: Record<string, string>;
    maxRedirects?: number;
  }
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; url: string }> {
  const maxRedirects = options.maxRedirects ?? 5;

  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === "https:" ? https : http;

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: "GET",
      headers: {
        "User-Agent": "cookie-check/1.0 (https://github.com/lxgicstudios/cookie-check)",
        Accept: "text/html,application/xhtml+xml,*/*",
        ...options.headers,
      },
      timeout: options.timeout,
    };

    const req = client.request(reqOptions, (res) => {
      // Handle redirects
      if (
        options.followRedirects &&
        res.statusCode &&
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location &&
        maxRedirects > 0
      ) {
        const redirectUrl = new URL(res.headers.location, targetUrl).toString();
        fetchUrl(redirectUrl, { ...options, maxRedirects: maxRedirects - 1 })
          .then(resolve)
          .catch(reject);
        return;
      }

      // Consume body
      res.on("data", () => {});
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode || 0,
          headers: res.headers,
          url: targetUrl,
        });
      });
    });

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Request timed out after ${options.timeout}ms`));
    });

    req.end();
  });
}

function parseCookie(setCookieHeader: string): CookieAttribute {
  const parts = setCookieHeader.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const eqIdx = nameValue.indexOf("=");
  const name = eqIdx > 0 ? nameValue.slice(0, eqIdx).trim() : nameValue.trim();
  const value = eqIdx > 0 ? nameValue.slice(eqIdx + 1).trim() : "";

  const cookie: CookieAttribute = {
    name,
    value,
    httpOnly: false,
    secure: false,
    sameSite: null,
    path: null,
    domain: null,
    expires: null,
    maxAge: null,
  };

  for (const attr of attrs) {
    const lower = attr.toLowerCase();
    if (lower === "httponly") {
      cookie.httpOnly = true;
    } else if (lower === "secure") {
      cookie.secure = true;
    } else if (lower.startsWith("samesite=")) {
      cookie.sameSite = attr.split("=")[1]?.trim() || null;
    } else if (lower.startsWith("path=")) {
      cookie.path = attr.split("=")[1]?.trim() || null;
    } else if (lower.startsWith("domain=")) {
      cookie.domain = attr.split("=")[1]?.trim() || null;
    } else if (lower.startsWith("expires=")) {
      cookie.expires = attr.slice(attr.indexOf("=") + 1).trim();
    } else if (lower.startsWith("max-age=")) {
      cookie.maxAge = parseInt(attr.split("=")[1]?.trim() || "0", 10);
    }
  }

  return cookie;
}

function auditCookie(cookie: CookieAttribute, isHttps: boolean): CookieAudit {
  const issues: string[] = [];
  const recommendations: string[] = [];
  let score = 100;

  // HttpOnly check
  if (!cookie.httpOnly) {
    issues.push("Missing HttpOnly flag (vulnerable to XSS cookie theft)");
    recommendations.push("Add HttpOnly flag to prevent JavaScript access");
    score -= 25;
  }

  // Secure check
  if (!cookie.secure) {
    if (isHttps) {
      issues.push("Missing Secure flag on HTTPS site (cookie sent over HTTP too)");
      recommendations.push("Add Secure flag to restrict cookie to HTTPS connections");
      score -= 25;
    } else {
      issues.push("Missing Secure flag (cookie sent in cleartext)");
      recommendations.push("Serve site over HTTPS and add Secure flag");
      score -= 20;
    }
  }

  // SameSite check
  if (!cookie.sameSite) {
    issues.push("Missing SameSite attribute (vulnerable to CSRF)");
    recommendations.push("Add SameSite=Lax or SameSite=Strict");
    score -= 20;
  } else {
    const ss = cookie.sameSite.toLowerCase();
    if (ss === "none") {
      if (!cookie.secure) {
        issues.push("SameSite=None requires Secure flag");
        score -= 15;
      }
      issues.push("SameSite=None allows cross-site requests (CSRF risk)");
      recommendations.push("Use SameSite=Lax unless cross-site access is required");
      score -= 5;
    }
  }

  // Path check
  if (!cookie.path || cookie.path === "/") {
    // Path=/ is common but worth noting
    if (!cookie.path) {
      issues.push("No Path set (defaults to current path)");
      recommendations.push("Set Path=/ for site-wide cookies or restrict to specific paths");
      score -= 5;
    }
  }

  // Expiry check - session cookies without expiry
  if (cookie.maxAge === null && cookie.expires === null) {
    issues.push("Session cookie (no Expires or Max-Age, deleted when browser closes)");
    // Not necessarily bad, just informational
    score -= 2;
  } else if (cookie.maxAge !== null && cookie.maxAge > 365 * 24 * 60 * 60) {
    issues.push("Cookie expires in over 1 year");
    recommendations.push("Consider shorter expiry times for security");
    score -= 5;
  }

  // Cookie name prefixes
  if (cookie.name.startsWith("__Secure-") && !cookie.secure) {
    issues.push("__Secure- prefix requires Secure flag");
    score -= 10;
  }
  if (cookie.name.startsWith("__Host-")) {
    if (!cookie.secure) {
      issues.push("__Host- prefix requires Secure flag");
      score -= 10;
    }
    if (cookie.path !== "/") {
      issues.push("__Host- prefix requires Path=/");
      score -= 5;
    }
    if (cookie.domain) {
      issues.push("__Host- prefix must not have Domain attribute");
      score -= 5;
    }
  }

  // Value analysis
  if (cookie.value && cookie.value.length > 4096) {
    issues.push("Cookie value exceeds 4096 bytes");
    recommendations.push("Store large data server-side, use a session ID cookie instead");
    score -= 5;
  }

  score = Math.max(0, Math.min(100, score));

  let grade: "A" | "B" | "C" | "D" | "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else grade = "F";

  return { cookie, grade, score, issues, recommendations };
}

function getGradeColor(grade: string): string {
  switch (grade) {
    case "A":
      return c.green;
    case "B":
      return c.cyan;
    case "C":
      return c.yellow;
    case "D":
      return c.red;
    case "F":
      return `${c.bgRed}${c.white}`;
    default:
      return c.reset;
  }
}

function getGradeEmoji(grade: string): string {
  switch (grade) {
    case "A":
      return "✅";
    case "B":
      return "🟢";
    case "C":
      return "⚠️";
    case "D":
      return "🔴";
    case "F":
      return "💀";
    default:
      return "?";
  }
}

const GRADE_ORDER: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };

function printAudit(audit: CookieAudit, verbose: boolean) {
  const gradeColor = getGradeColor(audit.grade);
  const emoji = getGradeEmoji(audit.grade);

  console.log(
    `\n  ${emoji} ${c.bold}${audit.cookie.name}${c.reset}` +
      `  ${gradeColor}${c.bold}Grade: ${audit.grade} (${audit.score}/100)${c.reset}`
  );

  if (verbose) {
    console.log(`     ${c.dim}Value:${c.reset} ${audit.cookie.value.substring(0, 40)}${audit.cookie.value.length > 40 ? "..." : ""}`);
    console.log(
      `     ${c.dim}HttpOnly:${c.reset} ${audit.cookie.httpOnly ? `${c.green}yes${c.reset}` : `${c.red}no${c.reset}`}  ` +
        `${c.dim}Secure:${c.reset} ${audit.cookie.secure ? `${c.green}yes${c.reset}` : `${c.red}no${c.reset}`}  ` +
        `${c.dim}SameSite:${c.reset} ${audit.cookie.sameSite || `${c.red}not set${c.reset}`}`
    );
    if (audit.cookie.path) console.log(`     ${c.dim}Path:${c.reset} ${audit.cookie.path}`);
    if (audit.cookie.domain) console.log(`     ${c.dim}Domain:${c.reset} ${audit.cookie.domain}`);
    if (audit.cookie.expires) console.log(`     ${c.dim}Expires:${c.reset} ${audit.cookie.expires}`);
    if (audit.cookie.maxAge !== null) console.log(`     ${c.dim}Max-Age:${c.reset} ${audit.cookie.maxAge}s`);
  }

  for (const issue of audit.issues) {
    console.log(`     ${c.yellow}!${c.reset} ${issue}`);
  }

  for (const rec of audit.recommendations) {
    console.log(`     ${c.cyan}>${c.reset} ${rec}`);
  }
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    console.log(HELP);
    process.exit(0);
  }

  if (!args.url) {
    console.error(`${c.red}Error:${c.reset} Please provide a URL to check.`);
    console.error(`${c.dim}Usage: npx @lxgicstudios/cookie-check <url>${c.reset}`);
    process.exit(1);
  }

  // Ensure URL has protocol
  let targetUrl = args.url;
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
  }

  const isHttps = targetUrl.startsWith("https:");

  if (!args.json) {
    console.log(
      `\n${c.bold}${c.cyan}cookie-check${c.reset} ${c.dim}Fetching ${targetUrl}...${c.reset}\n`
    );
  }

  let response;
  try {
    response = await fetchUrl(targetUrl, {
      followRedirects: args.followRedirects,
      timeout: args.timeout,
      headers: args.headers,
    });
  } catch (err: any) {
    console.error(`${c.red}Error:${c.reset} ${err.message}`);
    process.exit(1);
  }

  // Extract Set-Cookie headers
  const rawCookies: string[] = [];
  const setCookieHeader = response.headers["set-cookie"];
  if (setCookieHeader) {
    if (Array.isArray(setCookieHeader)) {
      rawCookies.push(...setCookieHeader);
    } else {
      rawCookies.push(setCookieHeader);
    }
  }

  if (rawCookies.length === 0) {
    if (args.json) {
      console.log(
        JSON.stringify({
          url: targetUrl,
          statusCode: response.statusCode,
          cookies: [],
          summary: { total: 0, gradeA: 0, gradeB: 0, gradeC: 0, gradeD: 0, gradeF: 0, averageScore: 0 },
        }, null, 2)
      );
    } else {
      console.log(`  ${c.green}No Set-Cookie headers found.${c.reset}`);
      console.log(`  ${c.dim}Status: ${response.statusCode}${c.reset}\n`);
    }
    process.exit(0);
  }

  // Parse and audit cookies
  const audits: CookieAudit[] = rawCookies.map((raw) => {
    const cookie = parseCookie(raw);
    return auditCookie(cookie, isHttps);
  });

  const result: AuditResult = {
    url: targetUrl,
    statusCode: response.statusCode,
    cookies: audits,
    summary: {
      total: audits.length,
      gradeA: audits.filter((a) => a.grade === "A").length,
      gradeB: audits.filter((a) => a.grade === "B").length,
      gradeC: audits.filter((a) => a.grade === "C").length,
      gradeD: audits.filter((a) => a.grade === "D").length,
      gradeF: audits.filter((a) => a.grade === "F").length,
      averageScore: Math.round(
        audits.reduce((sum, a) => sum + a.score, 0) / audits.length
      ),
    },
  };

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`  ${c.dim}Status: ${response.statusCode}  Cookies found: ${audits.length}${c.reset}`);

    for (const audit of audits) {
      printAudit(audit, args.verbose);
    }

    // Summary
    console.log(`\n${c.bold}${"─".repeat(50)}${c.reset}`);
    console.log(`${c.bold}Summary${c.reset} - ${targetUrl}`);
    console.log(
      `  ${c.green}A: ${result.summary.gradeA}${c.reset}  ` +
        `${c.cyan}B: ${result.summary.gradeB}${c.reset}  ` +
        `${c.yellow}C: ${result.summary.gradeC}${c.reset}  ` +
        `${c.red}D: ${result.summary.gradeD}${c.reset}  ` +
        `${c.bgRed}${c.white} F: ${result.summary.gradeF} ${c.reset}`
    );
    console.log(`  Average score: ${result.summary.averageScore}/100\n`);
  }

  // CI exit
  if (args.ci) {
    const minGradeNum = GRADE_ORDER[args.minGrade] || 3;
    const hasBadCookie = audits.some((a) => GRADE_ORDER[a.grade] < minGradeNum);
    if (hasBadCookie) {
      if (!args.json) {
        console.log(
          `${c.red}${c.bold}CI FAILED:${c.reset} Found cookies grading below ${args.minGrade}`
        );
      }
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error(`${c.red}Error:${c.reset}`, err.message);
  process.exit(1);
});
