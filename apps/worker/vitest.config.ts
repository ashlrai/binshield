import { defineConfig, mergeConfig } from "vitest/config";
import rootConfig from "../../vitest.config";

// apps/worker's test suite includes real binary-processing work (wheel/sdist
// extraction, native-binary fingerprinting, YARA scanning) that reliably
// takes >1s even on a fast local machine and can exceed vitest's 5000ms
// default under CI's more CPU-constrained shared runners. Give this package
// a longer per-test timeout rather than raising it repo-wide, where it would
// mask real hangs in the much lighter-weight packages.
export default mergeConfig(
  rootConfig,
  defineConfig({
    test: {
      testTimeout: 20_000
    }
  })
);
