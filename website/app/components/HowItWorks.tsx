import styles from "./HowItWorks.module.css";

const rows = [
  { feature: "License", recovermax: "AGPL-3.0", photorec: "GPL-2.0", rlinux: "Proprietary", sleuthkit: "Apache 2.0" },
  { feature: "Language", recovermax: "Rust", photorec: "C", rlinux: "C++", sleuthkit: "C / Java" },
  { feature: "Interactive Shell", recovermax: "Yes", photorec: "No", rlinux: "No", sleuthkit: "Limited" },
  { feature: "ext4 Recovery", recovermax: "Yes", photorec: "Carving only", rlinux: "Yes", sleuthkit: "Yes" },
  { feature: "NTFS Recovery", recovermax: "Yes", photorec: "Carving only", rlinux: "No", sleuthkit: "Yes" },
  { feature: "File Carving", recovermax: "8 signatures", photorec: "400+", rlinux: "No", sleuthkit: "No" },
  { feature: "Deleted Scanning", recovermax: "Yes", photorec: "No", rlinux: "Yes", sleuthkit: "Yes" },
  { feature: "Multi-TB Streaming", recovermax: "Yes", photorec: "Yes", rlinux: "Yes", sleuthkit: "Yes" },
  { feature: "Forensic Reports", recovermax: "Yes", photorec: "No", rlinux: "No", sleuthkit: "Partial" },
  { feature: "Cross-Platform", recovermax: "Yes", photorec: "Yes", rlinux: "Linux only", sleuthkit: "Yes" },
  { feature: "Maintained (2026)", recovermax: "Active", photorec: "Slow", rlinux: "Slow", sleuthkit: "Active" },
];

export default function HowItWorks() {
  return (
    <section className={styles.section} id="comparison">
      <div className={styles.container}>
        <h2 className={styles.heading}>Comparison</h2>
        <p className={styles.subhead}>
          RecoverMax combines filesystem-aware recovery and file carving in one tool —
          something no other open-source project does.
        </p>
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Feature</th>
                <th className={styles.highlight}>RecoverMax</th>
                <th>Photorec</th>
                <th>R-Linux</th>
                <th>Sleuth Kit</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.feature}>
                  <td className={styles.featureCol}>{row.feature}</td>
                  <td className={styles.highlight}>{row.recovermax}</td>
                  <td>{row.photorec}</td>
                  <td>{row.rlinux}</td>
                  <td>{row.sleuthkit}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
