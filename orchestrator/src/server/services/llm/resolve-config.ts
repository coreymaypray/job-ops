/**
 * Shared utility for resolving LLM runtime configuration.
 *
 * Reads DB-stored settings first, falls back to environment variables.
 * This ensures services always pick up API keys / providers saved via
 * the Settings UI, regardless of process.env state.
 */

import { getAllSettings } from "../../repositories/settings";
import type { LlmServiceOptions } from "./types";

export type LlmRuntimeConfig = {
  /** Resolved model identifier */
  model: string;
  /** Options to pass directly to `new LlmService()` */
  serviceOptions: LlmServiceOptions;
};

/**
 * Resolve LLM runtime settings from DB → env → defaults.
 *
 * @param modelOverrideKey - Optional task-specific model key from DB
 *   (e.g. the value of `modelScorer` or `modelTailoring`). When provided
 *   it takes precedence over the global model.
 */
export async function resolveLlmConfig(
  modelOverrideKey?: string | null,
): Promise<LlmRuntimeConfig> {
  const overrides = await getAllSettings();

  const model =
    modelOverrideKey ||
    overrides.model ||
    process.env.MODEL ||
    "google/gemini-3-flash-preview";

  const provider =
    overrides.llmProvider || process.env.LLM_PROVIDER || "openrouter";

  const baseUrl = overrides.llmBaseUrl || process.env.LLM_BASE_URL || null;

  const apiKey = overrides.llmApiKey || process.env.LLM_API_KEY || null;

  return {
    model,
    serviceOptions: {
      provider,
      baseUrl,
      apiKey,
    },
  };
}
