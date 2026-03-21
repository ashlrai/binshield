import Link from "next/link";

import { PageHeader } from "../../../components/page-header";
import { getSettingsSnapshot } from "../../../lib/site-data";

export default async function SettingsPage() {
  const settings = await getSettingsSnapshot();

  return (
    <main className="dashboard-page">
      <PageHeader
        eyebrow="Settings"
        title="Org profile and API access"
        description="Manage API keys, contact details, and alert preferences for the Ashlr AI org."
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
          <div className="key-list">
            {settings.apiKeys.map((key) => (
              <article key={key.label} className="key-row">
                <div>
                  <strong>{key.label}</strong>
                  <p>{key.maskedKey}</p>
                </div>
                <span>{key.lastUsedLabel}</span>
              </article>
            ))}
          </div>
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
