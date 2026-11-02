import { describe, expect, it } from "vitest";
import { ApiError, checkDomain, parseSelectors } from "./api";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("parseSelectors", () => {
  it("splits on commas and whitespace and drops empties", () => {
    expect(parseSelectors("selector1, s2  k1,,")).toEqual(["selector1", "s2", "k1"]);
    expect(parseSelectors("   ")).toEqual([]);
  });
});

describe("checkDomain", () => {
  it("posts the domain and selectors and returns the parsed result", async () => {
    let captured: { url: string; init?: RequestInit } | undefined;
    const fetchMock = (async (url: string, init?: RequestInit) => {
      captured = { url, init };
      return jsonResponse(200, { domain: "example.com", overall: "pass", checks: [] });
    }) as unknown as typeof fetch;

    const result = await checkDomain("example.com", ["s1"], fetchMock);

    expect(result.overall).toBe("pass");
    expect(captured?.url).toBe("/api/check");
    expect(JSON.parse(String(captured?.init?.body))).toEqual({
      domain: "example.com",
      dkim_selectors: ["s1"],
    });
  });

  it.each([
    [404, { detail: "nope.test does not exist in DNS." }, "nope.test does not exist in DNS."],
    [422, { detail: "Domain is empty." }, "Domain is empty."],
    [422, { detail: [{ msg: "too short" }] }, "Enter a valid domain such as example.com."],
    [502, {}, "The check failed on the server. Try again."],
  ])("maps HTTP %i to a readable message", async (status, body, message) => {
    const fetchMock = (async () => jsonResponse(status, body)) as unknown as typeof fetch;
    await expect(checkDomain("x.com", [], fetchMock)).rejects.toMatchObject({
      message,
      status,
    });
  });

  it("includes Retry-After when rate limited", async () => {
    const fetchMock = (async () =>
      jsonResponse(429, { detail: "slow down" }, { "Retry-After": "12" })) as unknown as typeof fetch;
    await expect(checkDomain("x.com", [], fetchMock)).rejects.toThrow("12 seconds");
  });

  it("reports network failures", async () => {
    const fetchMock = (async () => {
      throw new TypeError("failed to fetch");
    }) as unknown as typeof fetch;
    const error = await checkDomain("x.com", [], fetchMock).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBeUndefined();
  });
});
