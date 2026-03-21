import { describe, expect, it } from "vitest";

import { productCopy, readEnv } from "./index";

describe("config", () => {
  it("reads env with defaults", () => {
    const env = readEnv({});
    expect(env.apiBaseUrl).toContain("localhost");
    expect(productCopy.name).toBe("BinShield");
  });
});
