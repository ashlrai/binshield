import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: "BinShield terms of service — the agreement governing your use of the platform."
};

export default function TermsPage() {
  return (
    <div className="browse-page">
      <section className="page-header">
        <div>
          <p className="eyebrow">Legal</p>
          <h1>Terms of Service</h1>
          <p style={{ color: "var(--muted)" }}>Last updated: March 22, 2026</p>
        </div>
      </section>

      <article className="panel legal-content">
        <h2>1. Acceptance of Terms</h2>
        <p>
          By accessing or using BinShield (the &quot;Service&quot;), operated by
          Ashlr AI (AshlrAI Inc.), you agree to be bound by these Terms of Service.
          If you do not agree, do not use the Service.
        </p>

        <h2>2. Description of Service</h2>
        <p>
          BinShield is a binary supply-chain security platform that decompiles
          native package artifacts, classifies behavior using AI, and provides
          risk scoring, alerting, and policy enforcement tools. The Service is
          provided via web application, API, and CI/CD integrations.
        </p>

        <h2>3. Accounts</h2>
        <p>
          You must provide accurate information when creating an account. You are
          responsible for maintaining the confidentiality of your credentials and
          for all activity under your account. Notify us immediately of any
          unauthorized use.
        </p>

        <h2>4. Plans and Billing</h2>
        <p>
          The Service is offered under multiple plan tiers (Free, Pro, Team,
          Enterprise). Paid plans are billed monthly unless otherwise agreed.
          Fees are non-refundable except as required by law. We may change
          pricing with 30 days&apos; notice. Downgrades take effect at the end
          of the current billing cycle.
        </p>

        <h2>5. Acceptable Use</h2>
        <p>You agree not to:</p>
        <ul>
          <li>Use the Service for any unlawful purpose</li>
          <li>Attempt to reverse-engineer, decompile, or disassemble the Service itself</li>
          <li>Exceed your plan&apos;s rate limits or entitlements through circumvention</li>
          <li>Redistribute scan results or API data in a competing product</li>
          <li>Upload malicious content intended to attack or degrade the Service</li>
          <li>Share account credentials or API keys with unauthorized parties</li>
        </ul>

        <h2>6. API Usage</h2>
        <p>
          API access is subject to rate limits and usage quotas defined by your
          plan tier. We reserve the right to throttle or suspend API access if
          usage patterns indicate abuse or excessive load. API keys are
          confidential and must not be embedded in client-side code.
        </p>

        <h2>7. Intellectual Property</h2>
        <p>
          The Service, including its design, code, algorithms, and documentation,
          is owned by Ashlr AI (AshlrAI Inc.) and protected by intellectual property
          laws. You retain ownership of the packages and data you submit for
          analysis.
        </p>

        <h2>8. Data Rights</h2>
        <p>
          You grant us a limited license to process your submitted artifacts
          solely for the purpose of performing analysis and delivering results.
          We do not claim ownership of your data. Aggregated, anonymized data
          may be used to improve our threat intelligence database.
        </p>

        <h2>9. Disclaimer of Warranties</h2>
        <p>
          The Service is provided &quot;as is&quot; and &quot;as available&quot;
          without warranties of any kind, whether express or implied. We do not
          warrant that the Service will be uninterrupted, error-free, or that
          scan results will detect all security threats.
        </p>

        <h2>10. Limitation of Liability</h2>
        <p>
          To the maximum extent permitted by law, Ashlr AI (AshlrAI Inc.) shall not
          be liable for any indirect, incidental, special, consequential, or
          punitive damages, or any loss of profits or revenue, whether incurred
          directly or indirectly. Our total liability shall not exceed the amount
          you paid us in the twelve months preceding the claim.
        </p>

        <h2>11. Indemnification</h2>
        <p>
          You agree to indemnify and hold harmless Ashlr AI (AshlrAI Inc.) from any
          claims, damages, or expenses arising from your use of the Service or
          violation of these Terms.
        </p>

        <h2>12. Termination</h2>
        <p>
          We may suspend or terminate your account if you violate these Terms.
          You may cancel your account at any time. Upon termination, your right
          to use the Service ceases immediately. We may retain data as required
          by law or legitimate business purposes.
        </p>

        <h2>13. Changes to Terms</h2>
        <p>
          We may modify these Terms at any time. Material changes will be
          communicated via email or in-app notification at least 30 days before
          taking effect. Continued use of the Service after changes constitutes
          acceptance.
        </p>

        <h2>14. Governing Law</h2>
        <p>
          These Terms are governed by the laws of the State of Delaware, without
          regard to conflict of law principles. Any disputes shall be resolved
          in the state or federal courts located in Delaware.
        </p>

        <h2>15. Contact</h2>
        <p>
          Questions about these Terms may be directed to{" "}
          <a href="mailto:mason@ashlr.ai" style={{ color: "var(--accent)" }}>
            mason@ashlr.ai
          </a>
          .
        </p>
        <p>
          Ashlr AI (AshlrAI Inc.)
        </p>
      </article>
    </div>
  );
}
