import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DNS and Email Health Checker",
  description: "Check the MX, SPF, DKIM and DMARC records of a domain.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
