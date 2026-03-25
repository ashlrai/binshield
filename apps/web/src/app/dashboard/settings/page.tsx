import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ApiKeyManager } from "../../../components/api-key-manager";
import { PageHeader } from "../../../components/page-header";
import { getSettingsSnapshot } from "../../../lib/site-data";
import { createServerClient, getOrgContext } from "../../../lib/supabase";

export default async function SettingsPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const orgCtx = await getOrgContext(user.id);
  const settings = await getSettingsSnapshot(orgCtx?.orgId, user.email ?? undefined);

  const orgId = orgCtx?.orgId ?? "";

  return (
    <main className="dashboard-page">
      <PageHeader
        eyebrow="Settings"
        title="Org profile and API access"
        description={`Manage API keys, contact details, and alert preferences for the ${settings.orgName} org.`}
        actions={<Link href="/dashboard/billing" className="button-link">Billing</Link>}
      />

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Organization</h2>
            <span>{settings.role}</span>
          </div>
          <dl className="detail-grid-list">
            <div>
              <dt>Org name</dt>
              <dd>{settings.orgName}</dd>
            </div>
            <div>
              <dt>Slug</dt>
              <dd>{settings.orgSlug}</dd>
            </div>
            <div>
              <dt>Primary email</dt>
              <dd>{settings.contactEmail}</dd>
            </div>
          </dl>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>API keys</h2>
            <span>CI and automation</span>
          </div>
          <ApiKeyManager orgId={orgId} keys={settings.apiKeys} />
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Alert preferences</h2>
            <span>Notification policy</span>
          </div>
          <div className="tag-list">
            {settings.alertPreferences.map((preference) => (
              <span key={preference} className="tag">
                {preference}
              </span>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Audit trail</h2>
            <span>Recent account events</span>
          </div>
          <ul className="timeline">
            {settings.auditTrail.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
