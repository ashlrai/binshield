const repos = [
  { name: "ashlrai/payments-api", dependencies: 6, risk: 18, status: "healthy" },
  { name: "ashlrai/platform-web", dependencies: 4, risk: 22, status: "watch" },
  { name: "ashlrai/agent-runtime", dependencies: 9, risk: 43, status: "review" }
];

export default function DashboardPage() {
  return (
    <main className="dashboard-page">
      <section className="dashboard-hero">
        <div>
          <p className="eyebrow">Org dashboard</p>
          <h1>Native dependency coverage across your repos</h1>
        </div>
        <div className="dashboard-kpis">
          <article>
            <span>Repos monitored</span>
            <strong>3</strong>
          </article>
          <article>
            <span>Binaries tracked</span>
            <strong>19</strong>
          </article>
          <article>
            <span>Open reviews</span>
            <strong>1</strong>
          </article>
        </div>
      </section>

      <section className="panel">
        <div className="panel__heading">
          <h2>Repository posture</h2>
          <span>Sample authenticated view</span>
        </div>
        <div className="repo-table">
          {repos.map((repo) => (
            <article key={repo.name} className="repo-row">
              <div>
                <h3>{repo.name}</h3>
                <p>{repo.dependencies} native dependencies monitored</p>
              </div>
              <strong>{repo.risk}</strong>
              <span className={`status-pill status-pill--${repo.status}`}>{repo.status}</span>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
