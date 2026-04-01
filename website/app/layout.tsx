import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RecoverMax | Free Linux/NTFS/ext4 Data Recovery (R-Linux Alternative)",
  description:
    "RecoverMax is open-source data recovery for ext4 and NTFS: filesystem reconstruction, carving, and interactive shell workflows for forensics and incident response. AGPL-3.0 core and Rust performance for multi-TB images.",
  keywords: [
    "data recovery",
    "file recovery",
    "free linux data recovery",
    "open source data recovery",
    "ext4",
    "NTFS",
    "disk recovery",
    "undelete",
    "open source",
    "Linux",
    "deleted files",
    "file carving",
    "disk image",
    "forensics",
    "R-Linux alternative",
    "photorec alternative",
    "forensic data recovery tool",
  ],
  metadataBase: new URL("https://recovermax.dev"),
  alternates: {
    canonical: "/",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  openGraph: {
    title: "RecoverMax | AGPL Open-Source Data Recovery",
    description:
      "Recover ext4 and NTFS images with a command-first open-source tool for forensics, sysadmin, and incident response.",
    url: "https://recovermax.dev",
    siteName: "RecoverMax",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "RecoverMax - Open Source Data Recovery",
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "RecoverMax | Open-Source Data Recovery",
    description:
      "RecoverMax for ext4 and NTFS data recovery with filesystem reconstruction, carving, and interactive shell.",
    images: ["/og-image.png"],
  },
};

const jsonLd = [
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "RecoverMax",
    applicationCategory: "UtilitiesApplication",
    operatingSystem: "Linux, macOS, Windows",
    description:
      "High-performance open source data recovery for ext4 and NTFS images. Filesystem parsing, carving, and interactive shell workflows.",
    url: "https://recovermax.dev",
    downloadUrl: "https://github.com/KyleQ1/recovermax",
    softwareVersion: "0.1.0",
    license: "https://www.gnu.org/licenses/agpl-3.0.html",
    featureList: [
      "ext4 filesystem recovery",
      "NTFS recovery",
      "file carving",
      "interactive shell",
      "selective recovery",
    ],
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
    },
    author: {
      "@type": "Organization",
      name: "UCSB SecLab",
      url: "https://github.com/KyleQ1",
    },
  },
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: "UCSB SecLab",
    url: "https://github.com/KyleQ1",
    description:
      "Security research lab at the University of California, Santa Barbara.",
  },
];

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
