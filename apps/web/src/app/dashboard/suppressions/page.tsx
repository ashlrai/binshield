import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { PageHeader } from "../../../components/page-header";
import { SuppressionManager } from "../../../components/suppression-manager";
import { createServerClient, getOrgContext } from "../../../lib/supabase";

export default async function SuppressionsPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const orgCtx = await getOrgContext(user.id);
  const orgId = orgCtx?.orgId ?? "";

  return (
    <main className="dashboard-page">
      <PageHeader
        eyebrow="False-positive management"
        title="Finding suppressions"
        description="Silence findings that your security team has reviewed and confirmed as benign. Suppressions are applied transparently to the dashboard, GitHub Action output, and API responses."
      />

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Active suppressions</h2>
          </div>
          <SuppressionManager orgId={orgId} />
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>How suppressions work</h2>
          </div>
          <ul className="stack-list">
            <li className="stack-item">
              <strong>Package-level</strong>
              <p>Suppress all findings on a package (optionally for a specific version only).</p>
            </li>
            <li className="stack-item">
              <strong>Finding-level</strong>
              <p>Target a specific finding title or category within a package.</p>
            </li>
            <li className="stack-item">
              <strong>Transparent filtering</strong>
              <p>Suppressed findings are hidden everywhere — API, dashboard, and CI — without altering the underlying analysis record.</p>
            </li>
            <li className="stack-item">
              <strong>Auditable</strong>
              <p>Every suppression includes a required reason field and is logged to the audit trail.</p>
            </li>
          </ul>
        </div>
      </section>
    </main>
  );
}
