import ignore, { type Ignore } from "ignore";
import fs from "node:fs";
import path from "node:path";

/**
 * Files that must never be readable through MCP, regardless of user config.
 * Matched with gitignore semantics against workspace-relative paths.
 */
export const SENSITIVE_PATTERNS: string[] = [
  ".env",
  ".env.*",
  "!.env.example",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "*.jks",
  "*.keystore",
  "id_rsa",
  "id_rsa.*",
  "id_ed25519",
  "id_ed25519.*",
  "id_ecdsa",
  "id_ecdsa.*",
  "id_dsa",
  "id_dsa.*",
  ".ssh/",
  ".aws/",
  ".gnupg/",
  ".npmrc",
  ".netrc",
  "_netrc",
  ".git-credentials",
  "*.keychain",
  "*.keychain-db",
  ".cloudflared/",
  "credentials.json",
  "service-account*.json",
  "secrets.json",
  "cookies.sqlite",
  "Cookies",
  ".c2c-secrets*",
];

/** High-noise directories excluded from listing/search by default. */
export const NOISE_PATTERNS: string[] = [
  ".git/",
  "node_modules/",
  "dist/",
  "build/",
  "out/",
  ".next/",
  ".nuxt/",
  ".svelte-kit/",
  "coverage/",
  ".cache/",
  ".turbo/",
  ".venv/",
  "venv/",
  "__pycache__/",
  ".pytest_cache/",
  ".mypy_cache/",
  "target/",
  ".gradle/",
  ".idea/",
  ".tooling/",
  ".pnpm-store/",
  ".DS_Store",
  "*.lock",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
];

const SENSITIVE_CONTENT_PATTERNS: RegExp[] = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}/i,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:/]+:[^\s@/]{4,}@/i,
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key)\b\s*[:=]\s*["']?[^\s"']{8,}/i,
];

/** True when readable text contains a credential-like value. */
export function containsSensitiveContent(text: string): boolean {
  return SENSITIVE_CONTENT_PATTERNS.some((pattern) => pattern.test(text));
}

export class IgnoreRules {
  private sensitive: Ignore;
  private noise: Ignore;
  private custom: Ignore;

  constructor(workspaceRoot: string) {
    this.sensitive = ignore().add(SENSITIVE_PATTERNS);
    this.noise = ignore().add(NOISE_PATTERNS);
    this.custom = ignore();
    const c2cignore = path.join(workspaceRoot, ".c2cignore");
    try {
      if (fs.existsSync(c2cignore)) {
        this.custom.add(fs.readFileSync(c2cignore, "utf8"));
      }
    } catch {
      // unreadable .c2cignore: fall back to defaults only
    }
  }

  /** True when the path must be denied with ACCESS_DENIED_SENSITIVE_FILE. */
  isSensitive(relPath: string): boolean {
    if (!relPath || relPath === ".") return false;
    return this.sensitive.ignores(relPath) || this.custom.ignores(relPath);
  }

  /** True when the path should be hidden from listing/search (not an error). */
  isNoise(relPath: string): boolean {
    if (!relPath || relPath === ".") return false;
    return this.noise.ignores(relPath);
  }

  isHidden(relPath: string): boolean {
    return this.isSensitive(relPath) || this.isNoise(relPath);
  }
}
