import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: "BinShield privacy policy — how we collect, use, and protect your data."
};

export default function PrivacyPage() {
  return (
    <div className="browse-page">
      <section className="page-header">
        <div>
          <p className="eyebrow">Legal</p>
          <h1>Privacy Policy</h1>
          <p style={{ color: "var(--muted)" }}>Last updated: March 22, 2026</p>
        </div>
      </section>

      <article className="panel legal-content">
        <h2>1. Introduction</h2>
        <p>
          BinShield is a product of Ashlr AI, operated by AshlrAI Inc. (&quot;we,&quot;
          &quot;us,&quot; or &quot;our&quot;). This Privacy Policy describes how we collect,
          use, disclose, and safeguard your information when you use the BinShield
          platform, website, APIs, and related services (collectively, the
          &quot;Service&quot;).
        </p>

        <h2>2. Information We Collect</h2>
        <h3>Account Information</h3>
        <p>
          When you create an account, we collect your name, email address, and
          authentication credentials. If you sign in via a third-party provider
          (e.g., GitHub), we receive limited profile information from that provider.
        </p>
        <h3>Usage Data</h3>
        <p>
          We automatically collect information about how you interact with the
          Service, including pages visited, features used, scan requests, API calls,
          IP address, browser type, and device identifiers.
        </p>
        <h3>Scan Data</h3>
        <p>
          When you submit packages for analysis, we process the binary artifacts
          and metadata necessary to perform decompilation, behavior classification,
          and risk scoring. Scan results are stored in your account.
        </p>

        <h2>3. How We Use Your Information</h2>
        <p>We use collected information to:</p>
        <ul>
          <li>Provide, operate, and maintain the Service</li>
          <li>Process scans and deliver analysis results</li>
          <li>Manage your account and enforce plan entitlements</li>
          <li>Send transactional notifications (e.g., scan alerts, billing receipts)</li>
          <li>Improve the Service and develop new features</li>
          <li>Detect and prevent fraud, abuse, and security threats</li>
          <li>Comply with legal obligations</li>
        </ul>

        <h2>4. Information Sharing</h2>
        <p>
          We do not sell your personal information. We may share information with:
        </p>
        <ul>
          <li>
            <strong>Service providers</strong> who assist in operating the platform
            (hosting, analytics, payment processing)
          </li>
          <li>
            <strong>Legal authorities</strong> when required by law or to protect our
            rights
          </li>
          <li>
            <strong>Business transfers</strong> in connection with a merger,
            acquisition, or sale of assets
          </li>
        </ul>
        <p>
          Aggregated, anonymized scan data may be used to improve our public
          threat database. Individual account data is never included.
        </p>

        <h2>5. Cookies and Tracking</h2>
        <p>
          We use essential cookies to maintain session state and authentication.
          We may use analytics cookies to understand usage patterns. You can
          control cookie preferences through your browser settings.
        </p>

        <h2>6. Data Security</h2>
        <p>
          We implement industry-standard security measures including encryption
          in transit (TLS), encryption at rest, access controls, and regular
          security reviews. No method of transmission or storage is 100% secure,
          and we cannot guarantee absolute security.
        </p>

        <h2>7. Data Retention</h2>
        <p>
          We retain account data for as long as your account is active. Scan
          results are retained according to your plan tier. You may request
          deletion of your data at any time by contacting us.
        </p>

        <h2>8. Your Rights</h2>
        <p>
          Depending on your jurisdiction, you may have the right to access,
          correct, delete, or port your personal data. To exercise these rights,
          contact us at the address below.
        </p>

        <h2>9. Changes to This Policy</h2>
        <p>
          We may update this Privacy Policy from time to time. We will notify you
          of material changes by posting the updated policy on this page and
          updating the &quot;Last updated&quot; date.
        </p>

        <h2>10. Contact Us</h2>
        <p>
          If you have questions about this Privacy Policy, please contact us at{" "}
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
