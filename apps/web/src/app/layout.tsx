import type { Metadata } from "next";

import { productCopy } from "@binshield/config";

import { Header } from "../components/header";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "BinShield",
    template: "%s | BinShield"
  },
  description: productCopy.description
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Instrument+Sans:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <div className="scan-lines" aria-hidden="true" />
        <div className="grid-dots" aria-hidden="true" />
        <div className="page-shell">
          <Header />
          {children}
        </div>
      </body>
    </html>
  );
}
