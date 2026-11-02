export type Status = "pass" | "warn" | "fail" | "info";

export interface CheckResult {
  id: string;
  title: string;
  status: Status;
  summary: string;
  details: string[];
  records: string[];
}

export interface CheckResponse {
  domain: string;
  overall: Status;
  checks: CheckResult[];
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

/** Split a free-text field such as "selector1, s2" into a list of selectors. */
export function parseSelectors(input: string): string[] {
  return input
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

async function readDetail(response: Response): Promise<string | null> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    return typeof body.detail === "string" ? body.detail : null;
  } catch {
    return null;
  }
}

export async function checkDomain(
  domain: string,
  selectors: string[],
  fetchImpl: typeof fetch = fetch,
): Promise<CheckResponse> {
  let response: Response;
  try {
    response = await fetchImpl(`${API_BASE}/api/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, dkim_selectors: selectors }),
    });
  } catch {
    throw new ApiError("Could not reach the server. Check your connection and try again.");
  }

  if (response.ok) {
    return (await response.json()) as CheckResponse;
  }

  const detail = await readDetail(response);
  switch (response.status) {
    case 404:
      throw new ApiError(detail ?? "That domain does not exist.", 404);
    case 422:
      throw new ApiError(detail ?? "Enter a valid domain such as example.com.", 422);
    case 429: {
      const wait = response.headers.get("Retry-After");
      throw new ApiError(
        wait ? `Too many checks. Try again in ${wait} seconds.` : "Too many checks. Try again shortly.",
        429,
      );
    }
    default:
      throw new ApiError(detail ?? "The check failed on the server. Try again.", response.status);
  }
}
