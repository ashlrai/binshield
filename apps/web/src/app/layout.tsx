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
      <body>
        <div className="page-shell">
          <Header />
          {children}
        </div>
      </body>
    </html>
  );
}
