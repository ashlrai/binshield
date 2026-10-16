/**
 * Hand-rolled terminal spinner — zero dependencies.
 *
 * Degrades gracefully when stdout is not a TTY or color is disabled:
 * emits a single progress line per update instead of in-place animation.
 */

import { isColorEnabled, FG_CYAN, BOLD, RESET, CURSOR_HIDE, CURSOR_SHOW, CLEAR_LINE } from "./style.js";

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const FRAME_INTERVAL_MS = 80;

export class Spinner {
  private timer: ReturnType<typeof setInterval> | null = null;
  private frame = 0;
  private currentMessage = "";
  private started = false;

  start(message: string): void {
    this.currentMessage = message;
    this.started = true;

    if (!isColorEnabled()) {
      process.stderr.write(`  ${message}...\n`);
      return;
    }

    process.stderr.write(CURSOR_HIDE);

    this.timer = setInterval(() => {
      const f = FRAMES[this.frame % FRAMES.length];
      process.stderr.write(`${CLEAR_LINE}  ${BOLD}${FG_CYAN}${f}${RESET}  ${this.currentMessage}`);
      this.frame++;
    }, FRAME_INTERVAL_MS);
  }

  update(message: string): void {
    this.currentMessage = message;

    if (!isColorEnabled()) {
      process.stderr.write(`  ${message}\n`);
      return;
    }

    // The interval will pick up the new message on the next tick
  }

  stop(finalMessage?: string): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    if (!this.started) return;
    this.started = false;

    if (isColorEnabled()) {
      process.stderr.write(`${CLEAR_LINE}${CURSOR_SHOW}`);
    }

    if (finalMessage) {
      process.stderr.write(`  ${finalMessage}\n`);
    }
  }

  /** Stop spinner and clear without printing anything. */
  clear(): void {
    this.stop();
  }
}
