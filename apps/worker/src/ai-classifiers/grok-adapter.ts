/**
 * GrokAIClassifierAdapter — wraps `GrokClassifierProvider` to satisfy the
 * `AIClassifierProvider` interface (adds the required `model` field).
 *
 * This keeps the routing layer type-safe without modifying grok-classifier.ts.
 */

import type { ClassifiedArtifact, ClassifierProvider } from "../types";
import type { DecompiledArtifact, FingerprintedArtifact, WorkerScanRequest } from "../types";
import type { AIClassifierProvider } from "./types";

export class GrokAIClassifierAdapter implements AIClassifierProvider {
  readonly name: string;
  readonly model: string;

  constructor(private readonly inner: ClassifierProvider, modelId = "grok-4.3") {
    this.name = inner.name;
    this.model = modelId;
  }

  classify(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
    decompiled: DecompiledArtifact;
  }): Promise<ClassifiedArtifact> {
    return this.inner.classify(input);
  }
}
