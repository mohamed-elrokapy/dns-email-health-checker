import type { CheckResponse, Status } from "@/lib/api";

const LABELS: Record<Status, string> = {
  pass: "Pass",
  warn: "Warning",
  fail: "Fail",
  info: "Info",
};

function StatusBadge({ status }: { status: Status }) {
  // The text label is always shown, so the status never depends on colour alone.
  return <span className={`badge badge-${status}`}>{LABELS[status]}</span>;
}

export function Results({ result }: { result: CheckResponse }) {
  return (
    <section aria-labelledby="results-heading">
      <h2 id="results-heading" className="results-heading">
        <span>{result.domain}</span>
        <StatusBadge status={result.overall} />
      </h2>
      <ul className="cards">
        {result.checks.map((check) => (
          <li key={check.id} className="card">
            <div className="card-head">
              <h3>{check.title}</h3>
              <StatusBadge status={check.status} />
            </div>
            <p>{check.summary}</p>
            {check.details.length > 0 && (
              <ul className="details">
                {check.details.map((detail) => (
                  <li key={detail}>{detail}</li>
                ))}
              </ul>
            )}
            {check.records.length > 0 && (
              <details className="records">
                <summary>Published records</summary>
                {check.records.map((record) => (
                  <code key={record}>{record}</code>
                ))}
              </details>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
