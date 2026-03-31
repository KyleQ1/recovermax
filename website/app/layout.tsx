import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RecoverMax - High-Performance Open Source Data Recovery Tool",
  description:
    "Recover deleted files from ext4 and NTFS disk images. Interactive shell, file carving, streaming recovery for multi-TB drives. Free and open source.",
  keywords: [
    "data recovery",
    "file recovery",
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
    title: "RecoverMax - High-Performance Open Source Data Recovery Tool",
    description:
      "Recover deleted files from ext4 and NTFS disk images. Interactive shell, file carving, streaming recovery for multi-TB drives. Free and open source.",
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
    title: "RecoverMax - High-Performance Open Source Data Recovery Tool",
    description:
      "Recover deleted files from ext4 and NTFS disk images. Interactive shell, file carving, streaming recovery for multi-TB drives.",
    images: ["/og-image.png"],
  },
};

const jsonLd = [
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "RecoverMax",
    applicationCategory: "UtilitiesApplication",
    operatingSystem: "Linux, macOS",
    description:
      "High-performance open source data recovery tool for ext4 and NTFS disk images. Interactive shell, file carving, and streaming recovery for multi-TB drives.",
    url: "https://recovermax.dev",
    downloadUrl: "https://github.com/KyleQ1/recovermax",
    softwareVersion: "0.1.0",
    license: "https://www.gnu.org/licenses/agpl-3.0.html",
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
