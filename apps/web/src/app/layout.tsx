import type { Metadata } from "next";

import { productCopy } from "@binshield/config";

import { Footer } from "../components/footer";
import { Header } from "../components/header";
import "./globals.css";

const SITE_URL = "https://binshield.dev";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "BinShield — Binary Supply-Chain Security",
    template: "%s | BinShield"
  },
  description: productCopy.description,
  alternates: {
    canonical: SITE_URL
  },
  openGraph: {
    title: "BinShield — Binary Supply-Chain Security",
    description: "Decompile native package binaries, classify behavior with AI, and block threats before they reach production.",
    url: SITE_URL,
    siteName: "BinShield",
    locale: "en_US",
    type: "website"
  },
  twitter: {
    card: "summary_large_image",
    title: "BinShield — Binary Supply-Chain Security",
    description: "See inside the compiled code your dependencies actually execute."
  },
  manifest: "/manifest.json",
  other: {
    "theme-color": "#5ffbbd"
  }
};

const jsonLd = [
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: "BinShield",
    url: SITE_URL,
    logo: `${SITE_URL}/icon.png`,
    description:
      "BinShield decompiles native package binaries, classifies behavior with AI, and blocks supply-chain threats before they reach production.",
    foundingDate: "2025",
    parentOrganization: {
      "@type": "Organization",
      name: "Ashlr AI"
    }
  },
  {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: "BinShield",
    url: SITE_URL,
    potentialAction: {
      "@type": "SearchAction",
      target: {
        "@type": "EntryPoint",
        urlTemplate: `${SITE_URL}/search?q={search_term_string}`
      },
      "query-input": "required name=search_term_string"
    }
  },
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "BinShield",
    applicationCategory: "SecurityApplication",
    operatingSystem: "Web",
    url: SITE_URL,
    description:
      "Binary supply-chain security platform that decompiles native package artifacts, classifies behavior with AI, and surfaces actionable risk scores.",
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
      description: "Free tier available"
    }
  }
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link rel="dns-prefetch" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://lofwvdksrxszmwnghqci.supabase.co" />
        <link rel="dns-prefetch" href="https://lofwvdksrxszmwnghqci.supabase.co" />
        <link rel="preconnect" href="https://binshieldapi-production.up.railway.app" />
        <link rel="dns-prefetch" href="https://binshieldapi-production.up.railway.app" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Instrument+Sans:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body>
        <div className="scan-lines" aria-hidden="true" />
        <div className="grid-dots" aria-hidden="true" />
        <div className="page-shell">
          <Header />
          {children}
          <Footer />
        </div>
      </body>
    </html>
  );
}
