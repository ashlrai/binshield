import Link from "next/link";

import { MetricCard } from "../../../components/metric-card";
import { PageHeader } from "../../../components/page-header";
import { getBillingSnapshot } from "../../../lib/site-data";

export default async function BillingPage() {
  const billing = await getBillingSnapshot();
  const usagePercent = Math.min(100, Math.round((billing.monthlyUsage / billing.monthlyLimit) * 100));

  return (
    <main className="dashboard-page">
      <PageHeader
        eyebrow="Billing"
        title="Plans, usage, and invoices"
        description="Launch-ready billing surfaces for self-serve signup, usage visibility, and customer-portal handoff."
        actions={<Link href="/dashboard/settings" className="button-link">Payment settings</Link>}
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
          <p>
            {billing.monthlyUsage} scans consumed out of {billing.monthlyLimit}. Keep billing live once Stripe is wired so teams can self-serve upgrades.
          </p>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Invoices</h2>
            <span>Stripe-ready history</span>
          </div>
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
        </div>
      </section>
    </main>
  );
}
