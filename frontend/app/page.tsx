"use client";

import { FormEvent, useState } from "react";
import { Results } from "@/components/Results";
import { ApiError, CheckResponse, checkDomain, parseSelectors } from "@/lib/api";

export default function Home() {
  const [domain, setDomain] = useState("");
  const [selectors, setSelectors] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CheckResponse | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      setResult(await checkDomain(domain.trim(), parseSelectors(selectors)));
    } catch (e) {
      setResult(null);
      setError(e instanceof ApiError ? e.message : "Something went wrong. Try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page">
      <header>
        <h1>DNS and Email Health Checker</h1>
        <p className="lede">
          Check whether a domain publishes working MX, SPF, DKIM and DMARC records. The checks are
          read-only DNS lookups.
        </p>
      </header>

      <form onSubmit={onSubmit} className="form">
        <label htmlFor="domain">Domain</label>
        <input
          id="domain"
          name="domain"
          type="text"
          inputMode="url"
          autoComplete="off"
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          required
        />

        <label htmlFor="selectors">
          DKIM selectors <span className="optional">(optional, comma separated)</span>
        </label>
        <input
          id="selectors"
          name="selectors"
          type="text"
          autoComplete="off"
          placeholder="selector1, s2"
          value={selectors}
          onChange={(e) => setSelectors(e.target.value)}
          aria-describedby="selectors-help"
        />
        <p id="selectors-help" className="help">
          DKIM selectors are chosen by the sender. Common ones are tried automatically. Add the
          selector from a message&apos;s DKIM-Signature header to check yours.
        </p>

        <button type="submit" disabled={loading || domain.trim().length === 0}>
          {loading ? "Checking…" : "Check domain"}
        </button>
      </form>

      <div aria-live="polite">
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {result && <Results result={result} />}
      </div>
    </main>
  );
}
