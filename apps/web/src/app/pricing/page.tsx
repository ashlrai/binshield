import type { Metadata } from "next";
import Link from "next/link";

import { pricingCopy } from "@binshield/config";
import { CheckoutButton } from "../../components/checkout-button";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "Choose the BinShield plan that fits your security needs — from free open-source scanning to enterprise-grade compliance controls."
};

type Feature = {
  name: string;
  values: [string, string, string, string];
};

const features: Feature[] = [
  { name: "Public database access", values: ["Yes", "Yes", "Yes", "Yes"] },
  { name: "Repos", values: ["3", "25", "50", "1,000"] },
  { name: "Monthly scans", values: ["50", "2,500", "10,000", "100,000"] },
  { name: "API access", values: ["No", "Yes", "Yes", "Yes"] },
  { name: "Watchlists", values: ["No", "Yes", "Yes", "Yes"] },
  { name: "SBOM export", values: ["No", "No", "Yes", "Yes"] },
  { name: "Slack alerts", values: ["No", "No", "Yes", "Yes"] },
  { name: "Compliance reports", values: ["No", "No", "No", "Yes"] },
  { name: "SSO / SAML", values: ["No", "No", "No", "Yes"] },
  { name: "Support", values: ["Community", "Email", "Email", "Dedicated"] }
];

function TierCta({ plan }: { plan: string }) {
  if (plan === "free") {
    return (
      <Link href="/login" className="button-link button-link--ghost">
        Get started free
      </Link>
    );
  }

  if (plan === "enterprise") {
    return (
      <a
        href="mailto:mason@ashlr.ai?subject=BinShield%20Enterprise"
        className="button-link button-link--ghost"
      >
        Contact sales
      </a>
    );
  }

  return <CheckoutButton plan={plan} label="Start trial" />;
}

export default function PricingPage() {
  return (
    <div className="browse-page">
      <section className="page-header">
        <div>
          <p className="eyebrow">Pricing</p>
          <h1>Plans for every stage</h1>
          <p style={{ color: "var(--muted)", maxWidth: "52ch" }}>
            Start free with public database access and lightweight CI coverage.
            Scale up as your dependency surface grows.
          </p>
        </div>
      </section>

      <div className="surface-grid pricing-grid">
        {pricingCopy.map((tier) => (
          <div key={tier.plan} className="panel pricing-card">
            <p className="eyebrow">{tier.plan}</p>
            <p className="pricing-card__price">{tier.price}</p>
            <p className="pricing-card__headline">{tier.headline}</p>
            <TierCta plan={tier.plan} />
          </div>
        ))}
      </div>

      <section className="panel pricing-matrix">
        <p className="eyebrow">Feature comparison</p>
        <div className="pricing-matrix__table-wrap">
          <table className="pricing-matrix__table">
            <thead>
              <tr>
                <th>Feature</th>
                <th>Free</th>
                <th>Pro</th>
                <th>Team</th>
                <th>Enterprise</th>
              </tr>
            </thead>
            <tbody>
              {features.map((f) => (
                <tr key={f.name}>
                  <td>{f.name}</td>
                  {f.values.map((v, i) => (
                    <td key={i} data-available={v !== "No" ? "true" : undefined}>
                      {v}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
