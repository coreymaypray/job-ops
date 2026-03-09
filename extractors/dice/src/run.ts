import { resolveSearchCities } from "@shared/search-cities.js";
import type { CreateJobInput } from "@shared/types/jobs";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DiceJob {
  title?: string;
  summary?: string;
  companyName?: string;
  companyPageUrl?: string;
  detailsPageUrl?: string;
  salary?: string;
  location?: string;
  employmentType?: string;
  postedDate?: string;
  workplaceTypes?: string[];
  [key: string]: unknown;
}

export interface DiceSearchResult {
  data?: DiceJob[];
  meta?: {
    totalResults?: number;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export type DiceProgressEvent =
  | {
      type: "term_start";
      termIndex: number;
      termTotal: number;
      searchTerm: string;
    }
  | {
      type: "term_complete";
      termIndex: number;
      termTotal: number;
      searchTerm: string;
      jobsFound: number;
    };

export interface RunDiceOptions {
  searchTerms: string[];
  locations?: string[];
  maxJobsPerTerm?: number;
  onProgress?: (event: DiceProgressEvent) => void;
  shouldCancel?: () => boolean;
}

export interface DiceResult {
  success: boolean;
  jobs: CreateJobInput[];
  error?: string;
}

// ---------------------------------------------------------------------------
// Dice MCP Server HTTP Client
// ---------------------------------------------------------------------------

const DICE_MCP_ENDPOINT = "https://mcp.dice.com/mcp";

/**
 * Call the Dice MCP server's search_jobs tool via HTTP POST (JSON-RPC).
 *
 * The Dice MCP server exposes a `search_jobs` tool with parameters:
 *   keyword, location, radius, radius_unit, jobs_per_page, page_number,
 *   posted_date, workplace_types, employment_types, employer_types,
 *   willing_to_sponsor, easy_apply, fields
 */
async function callDiceSearch(args: {
  keyword: string;
  location?: string;
  jobsPerPage?: number;
}): Promise<DiceSearchResult> {
  const searchArgs: Record<string, unknown> = {
    keyword: args.keyword,
    jobs_per_page: args.jobsPerPage ?? 50,
    employment_types: ["FULLTIME"],
  };

  if (args.location) {
    searchArgs.location = args.location;
  }

  // Try JSON-RPC POST first (standard MCP HTTP transport)
  const body = {
    jsonrpc: "2.0",
    method: "tools/call",
    params: {
      name: "search_jobs",
      arguments: searchArgs,
    },
    id: 1,
  };

  const response = await fetch(DICE_MCP_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(
      `Dice MCP server returned HTTP ${response.status}: ${response.statusText}`,
    );
  }

  const contentType = response.headers.get("content-type") ?? "";

  // Handle JSON-RPC response
  if (contentType.includes("application/json")) {
    const json = (await response.json()) as Record<string, unknown>;

    // JSON-RPC success response has result field
    if (json.result) {
      return parseToolResult(json.result);
    }

    // JSON-RPC error response
    if (json.error) {
      const err = json.error as Record<string, unknown>;
      throw new Error(
        `Dice MCP error: ${String(err.message ?? "Unknown error")}`,
      );
    }

    // Might be a direct response (non-standard)
    return parseDirectResponse(json);
  }

  // Handle SSE / text event streams (some MCP servers use this)
  if (
    contentType.includes("text/event-stream") ||
    contentType.includes("text/plain")
  ) {
    const text = await response.text();
    return parseSSEResponse(text);
  }

  // Fallback: try to parse as JSON
  const text = await response.text();
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    return parseDirectResponse(parsed);
  } catch {
    throw new Error(`Unexpected Dice MCP response format: ${contentType}`);
  }
}

/**
 * Parse MCP tool result (from JSON-RPC result field).
 * The result may be wrapped in a content array per MCP spec.
 */
function parseToolResult(result: unknown): DiceSearchResult {
  if (!result || typeof result !== "object") {
    return { data: [] };
  }

  const obj = result as Record<string, unknown>;

  // MCP tool results are often wrapped: { content: [{ type: "text", text: "..." }] }
  if (Array.isArray(obj.content)) {
    for (const item of obj.content) {
      if (
        item &&
        typeof item === "object" &&
        "type" in item &&
        item.type === "text" &&
        "text" in item
      ) {
        try {
          return JSON.parse(String(item.text)) as DiceSearchResult;
        } catch {
          // Not JSON, try next content item
        }
      }
    }
  }

  // Direct result object (has data array)
  if (Array.isArray(obj.data)) {
    return obj as DiceSearchResult;
  }

  return { data: [] };
}

/**
 * Parse a direct (non-JSON-RPC) response.
 */
function parseDirectResponse(json: Record<string, unknown>): DiceSearchResult {
  if (Array.isArray(json.data)) {
    return json as DiceSearchResult;
  }

  // Maybe it's an array of jobs directly
  if (Array.isArray(json)) {
    return { data: json as DiceJob[] };
  }

  return { data: [] };
}

/**
 * Parse SSE (Server-Sent Events) response to extract job data.
 */
function parseSSEResponse(text: string): DiceSearchResult {
  const jobs: DiceJob[] = [];

  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("data:")) continue;
    const payload = trimmed.slice(5).trim();
    if (!payload || payload === "[DONE]") continue;

    try {
      const parsed = JSON.parse(payload) as Record<string, unknown>;

      // Check if this is a tool result message
      if (parsed.result) {
        const result = parseToolResult(parsed.result);
        if (result.data && result.data.length > 0) {
          return result;
        }
      }

      // Check if payload itself is a job list
      if (Array.isArray(parsed.data)) {
        return parsed as DiceSearchResult;
      }
    } catch {
      // Skip non-JSON lines
    }
  }

  return { data: jobs };
}

// ---------------------------------------------------------------------------
// Field Mapping
// ---------------------------------------------------------------------------

function parseSalaryRange(salary?: string): {
  min: number | null;
  max: number | null;
  currency: string | null;
} {
  if (!salary) return { min: null, max: null, currency: null };

  // Try to extract numbers from salary string like "$80,000 - $120,000" or "$50/hr"
  const numbers = salary.match(/[\d,]+(?:\.\d+)?/g);
  if (!numbers || numbers.length === 0) return { min: null, max: null, currency: null };

  const parsed = numbers.map((n) => parseFloat(n.replace(/,/g, "")));
  const currency = salary.includes("$")
    ? "USD"
    : salary.includes("\u00a3")
      ? "GBP"
      : salary.includes("\u20ac")
        ? "EUR"
        : null;

  return {
    min: parsed[0] ?? null,
    max: parsed.length > 1 ? (parsed[1] ?? null) : null,
    currency,
  };
}

function mapWorkplaceType(types?: string[]): {
  isRemote: boolean | null;
  workFromHomeType: string | null;
} {
  if (!types || types.length === 0) return { isRemote: null, workFromHomeType: null };

  const lower = types.map((t) => t.toLowerCase());
  if (lower.includes("remote")) {
    return { isRemote: true, workFromHomeType: "remote" };
  }
  if (lower.includes("hybrid")) {
    return { isRemote: false, workFromHomeType: "hybrid" };
  }
  if (lower.includes("on-site") || lower.includes("onsite")) {
    return { isRemote: false, workFromHomeType: "onsite" };
  }

  return { isRemote: null, workFromHomeType: null };
}

function mapDiceJob(raw: DiceJob): CreateJobInput | null {
  const jobUrl = raw.detailsPageUrl;
  if (!jobUrl) return null;

  const title = raw.title ?? "Unknown Title";
  const employer = raw.companyName ?? "Unknown Employer";
  const salary = parseSalaryRange(raw.salary);
  const workplace = mapWorkplaceType(raw.workplaceTypes);

  return {
    source: "dice",
    title,
    employer,
    employerUrl: raw.companyPageUrl ?? undefined,
    jobUrl,
    applicationLink: jobUrl,
    location: raw.location ?? undefined,
    salary: raw.salary ?? undefined,
    jobDescription: raw.summary ?? undefined,
    jobType: raw.employmentType ?? undefined,
    datePosted: raw.postedDate ?? undefined,
    salaryMinAmount: salary.min ?? undefined,
    salaryMaxAmount: salary.max ?? undefined,
    salaryCurrency: salary.currency ?? undefined,
    isRemote: workplace.isRemote ?? undefined,
    workFromHomeType: workplace.workFromHomeType ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// Main Runner
// ---------------------------------------------------------------------------

export async function runDice(options: RunDiceOptions): Promise<DiceResult> {
  const { searchTerms, maxJobsPerTerm = 50, onProgress, shouldCancel } = options;

  const locations =
    options.locations && options.locations.length > 0
      ? options.locations
      : [undefined];

  const termTotal = searchTerms.length;
  const allJobs: CreateJobInput[] = [];
  const seen = new Set<string>();

  for (let termIdx = 0; termIdx < searchTerms.length; termIdx++) {
    if (shouldCancel?.()) break;

    const searchTerm = searchTerms[termIdx]!;

    onProgress?.({
      type: "term_start",
      termIndex: termIdx + 1,
      termTotal,
      searchTerm,
    });

    // Search across all configured locations
    for (const location of locations) {
      if (shouldCancel?.()) break;

      try {
        const result = await callDiceSearch({
          keyword: searchTerm,
          location,
          jobsPerPage: Math.min(maxJobsPerTerm, 100), // Dice max is 100
        });

        const rawJobs = result.data ?? [];

        for (const raw of rawJobs) {
          const mapped = mapDiceJob(raw);
          if (!mapped) continue;

          const dedupeKey = mapped.jobUrl;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);
          allJobs.push(mapped);
        }
      } catch (error) {
        const message =
          error instanceof Error ? error.message : "Unknown error";
        console.error(
          `[Dice] Error searching "${searchTerm}" in "${location ?? "default"}": ${message}`,
        );
        // Continue with next term/location instead of failing entirely
      }
    }

    onProgress?.({
      type: "term_complete",
      termIndex: termIdx + 1,
      termTotal,
      searchTerm,
      jobsFound: allJobs.length,
    });
  }

  return {
    success: true,
    jobs: allJobs,
  };
}
