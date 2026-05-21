/**
 * Hand-rolled ANSI styling — zero dependencies.
 *
 * All color/style output is gated on `isColorEnabled()` so that
 * --no-color, NO_COLOR, FORCE_COLOR, CI, and non-TTY environments
 * all work correctly.
 */

// ---------------------------------------------------------------------------
// Color detection
// ---------------------------------------------------------------------------

let _colorEnabled: boolean | undefined;

export function isColorEnabled(): boolean {
  if (_colorEnabled !== undefined) return _colorEnabled;

  // Explicit overrides
  if (process.env.NO_COLOR !== undefined) return (_colorEnabled = false);
  if (process.env.FORCE_COLOR === "0") return (_colorEnabled = false);
  if (process.env.FORCE_COLOR !== undefined) return (_colorEnabled = true);

  // CI flag check — default to no color in CI unless FORCE_COLOR is set
  // (most CI systems set CI=true but also support FORCE_COLOR)
  if (process.env.CI === "true" || process.env.CI === "1") {
    return (_colorEnabled = false);
  }

  return (_colorEnabled = Boolean(process.stdout.isTTY));
}

export function setColorEnabled(enabled: boolean): void {
  _colorEnabled = enabled;
}

// ---------------------------------------------------------------------------
// ANSI escape sequences
// ---------------------------------------------------------------------------

const ESC = "\x1b[";

export const RESET = `${ESC}0m`;
export const BOLD = `${ESC}1m`;
export const DIM = `${ESC}2m`;
export const ITALIC = `${ESC}3m`;

export const FG_GRAY = `${ESC}90m`;
export const FG_RED = `${ESC}31m`;
export const FG_GREEN = `${ESC}32m`;
export const FG_YELLOW = `${ESC}33m`;
export const FG_BLUE = `${ESC}34m`;
export const FG_CYAN = `${ESC}36m`;
export const FG_WHITE = `${ESC}37m`;
export const FG_BRIGHT_RED = `${ESC}91m`;
export const FG_BRIGHT_GREEN = `${ESC}92m`;
export const FG_BRIGHT_YELLOW = `${ESC}93m`;
export const FG_BRIGHT_BLUE = `${ESC}94m`;
export const FG_BRIGHT_CYAN = `${ESC}96m`;
export const FG_BRIGHT_WHITE = `${ESC}97m`;

export const BG_RED = `${ESC}41m`;
export const BG_YELLOW = `${ESC}43m`;
export const BG_GRAY = `${ESC}100m`;

// Cursor control
export const CURSOR_HIDE = `${ESC}?25l`;
export const CURSOR_SHOW = `${ESC}?25h`;
export const CLEAR_LINE = `\r${ESC}K`;

// ---------------------------------------------------------------------------
// Style application helpers
// ---------------------------------------------------------------------------

export function styled(ansi: string, text: string): string {
  return isColorEnabled() ? `${ansi}${text}${RESET}` : text;
}

export function bold(text: string): string {
  return styled(BOLD, text);
}

export function dim(text: string): string {
  return styled(DIM, text);
}

export function italic(text: string): string {
  return styled(ITALIC, text);
}

export function gray(text: string): string {
  return styled(FG_GRAY, text);
}

export function red(text: string): string {
  return styled(FG_RED, text);
}

export function green(text: string): string {
  return styled(FG_GREEN, text);
}

export function yellow(text: string): string {
  return styled(FG_YELLOW, text);
}

export function blue(text: string): string {
  return styled(FG_BLUE, text);
}

export function cyan(text: string): string {
  return styled(FG_CYAN, text);
}

export function brightRed(text: string): string {
  return styled(FG_BRIGHT_RED, text);
}

export function brightGreen(text: string): string {
  return styled(FG_BRIGHT_GREEN, text);
}

export function brightYellow(text: string): string {
  return styled(FG_BRIGHT_YELLOW, text);
}

export function brightCyan(text: string): string {
  return styled(FG_BRIGHT_CYAN, text);
}

export function boldRed(text: string): string {
  return isColorEnabled() ? `${BOLD}${FG_BRIGHT_RED}${text}${RESET}` : text;
}

export function boldCyan(text: string): string {
  return isColorEnabled() ? `${BOLD}${FG_BRIGHT_CYAN}${text}${RESET}` : text;
}

export function boldGreen(text: string): string {
  return isColorEnabled() ? `${BOLD}${FG_BRIGHT_GREEN}${text}${RESET}` : text;
}

// ---------------------------------------------------------------------------
// Risk level badges
// ---------------------------------------------------------------------------

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export function riskColor(level: RiskLevel): string {
  switch (level) {
    case "none":     return styled(FG_GRAY, "none");
    case "low":      return styled(FG_BLUE, "low");
    case "medium":   return styled(FG_YELLOW, "medium");
    case "high":     return styled(FG_RED, "high");
    case "critical": return boldRed("critical");
    default:         return String(level);
  }
}

/** Padded badge for table alignment — accounts for invisible ANSI bytes. */
export function riskBadge(level: RiskLevel, score: number): string {
  const label = riskColor(level);
  const plain = `${level} (${score})`;
  // Right-pad to a standard width using the *visible* length
  const padWidth = 18;
  const padding = " ".repeat(Math.max(0, padWidth - plain.length));
  return `${label} ${dim(`(${score})`)}${padding}`;
}

/** Plain badge for non-TTY output. */
export function riskBadgePlain(level: RiskLevel, score: number): string {
  return `${level} (${score})`;
}

// ---------------------------------------------------------------------------
// Section/layout helpers
// ---------------------------------------------------------------------------

export function sectionHeader(title: string, width = 60): string {
  const line = "─".repeat(width);
  return isColorEnabled()
    ? `\n${FG_BRIGHT_CYAN}${BOLD}${title}${RESET}\n${FG_GRAY}${line}${RESET}`
    : `\n${title}\n${line}`;
}

export function divider(width = 60): string {
  return styled(FG_GRAY, "─".repeat(width));
}

export function label(text: string): string {
  return styled(`${DIM}`, text + ":");
}

/**
 * Draw a boxed panel.
 *
 * Example:
 *   ╔══════════════════════╗
 *   ║  VERDICT: CRITICAL   ║
 *   ╚══════════════════════╝
 */
export function box(lines: string[], width = 60): string {
  const color = isColorEnabled();
  const h = "═".repeat(width + 2);
  const top = color ? `${FG_BRIGHT_CYAN}╔${h}╗${RESET}` : `╔${h}╗`;
  const bot = color ? `${FG_BRIGHT_CYAN}╚${h}╝${RESET}` : `╚${h}╝`;

  const rows = lines.map((line) => {
    // Visible length: strip ANSI
    const visible = stripAnsi(line);
    const pad = Math.max(0, width - visible.length);
    const left = color ? `${FG_BRIGHT_CYAN}║${RESET}` : "║";
    const right = color ? `${FG_BRIGHT_CYAN}║${RESET}` : "║";
    return `${left} ${line}${" ".repeat(pad)} ${right}`;
  });

  return [top, ...rows, bot].join("\n");
}

/** Strip ANSI escape codes for visible-length calculation. */
export function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

// ---------------------------------------------------------------------------
// Text utilities
// ---------------------------------------------------------------------------

export function padRight(text: string, width: number): string {
  const visible = stripAnsi(text);
  if (visible.length >= width) return text;
  return text + " ".repeat(width - visible.length);
}

export function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen - 1) + "…";
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
