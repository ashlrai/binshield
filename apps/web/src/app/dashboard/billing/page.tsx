import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { MetricCard } from "../../../components/metric-card";
import { ManageSubscriptionButton } from "../../../components/manage-subscription-button";
import { PageHeader } from "../../../components/page-header";
import { getBillingSnapshot } from "../../../lib/site-data";
import { createServerClient, getOrgContext } from "../../../lib/supabase";

export default async function BillingPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const orgCtx = await getOrgContext(user.id);
  const billing = await getBillingSnapshot(orgCtx?.orgId);
  const usagePercent = billing.monthlyLimit > 0
    ? Math.min(100, Math.round((billing.monthlyUsage / billing.monthlyLimit) * 100))
    : 0;

  const isFreePlan = billing.plan === "Free";

  return (
    <main className="dashboard-page">
      <PageHeader
        eyebrow="Billing"
        title="Plans, usage, and invoices"
        description="Launch-ready billing surfaces for self-serve signup, usage visibility, and customer-portal handoff."
        actions={
          <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
            <ManageSubscriptionButton />
            <Link href="/dashboard/settings" className="button-link button-link--ghost">Payment settings</Link>
          </div>
        }
      />

      <section className="metrics-grid">
        <MetricCard label="Plan" value={billing.plan} detail={`${billing.billingInterval} subscription`} tone="accent" />
        <MetricCard label="Seats" value={`${billing.seatCount}/${billing.seatLimit}`} detail="Assigned users" />
        <MetricCard label="Usage" value={`${billing.monthlyUsage}/${billing.monthlyLimit}`} detail={`${usagePercent}% of monthly allowance`} tone="warning" />
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Usage</h2>
            <span>{billing.paymentMethod}</span>
          </div>
          <div className="usage-meter">
            <div className="usage-meter__bar" style={{ width: `${usagePercent}%` }} />
          </div>
          {isFreePlan ? (
            <div>
              <p>
                You are on the <strong>Free</strong> plan with {billing.monthlyLimit} scans per month.
                Upgrade to unlock higher limits, more seats, and advanced features.
              </p>
              <Link href="/pricing" className="button-link" style={{ marginTop: "1rem", display: "inline-block" }}>
                Upgrade plan
              </Link>
            </div>
          ) : (
            <p>
              {billing.monthlyUsage} scans consumed out of {billing.monthlyLimit}. Keep billing live once Stripe is wired so teams can self-serve upgrades.
            </p>
          )}
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Invoices</h2>
            <span>Stripe-ready history</span>
          </div>
          {billing.invoices.length > 0 ? (
            <div className="invoice-list">
              {billing.invoices.map((invoice) => (
                <article key={invoice.id} className="invoice-row">
                  <div>
                    <strong>{invoice.id}</strong>
                    <p>{invoice.dateLabel}</p>
                  </div>
                  <span>{invoice.amount}</span>
                  <span className={`status-pill status-pill--${invoice.status === "paid" ? "healthy" : invoice.status === "open" ? "watch" : "review"}`}>
                    {invoice.status}
                  </span>
                </article>
              ))}
            </div>
          ) : (
            <p>No invoices yet. Invoices will appear here once you upgrade to a paid plan.</p>
          )}
        </div>
      </section>
    </main>
  );
}
