import styles from "./Features.module.css";

const capabilities = [
  { label: "ext4 Recovery", desc: "Superblock, inodes, extents, block maps, directory entries, sparse files, symlinks" },
  { label: "NTFS Recovery", desc: "Boot sector, MFT parsing, data run decoding, resident and non-resident file reading" },
  { label: "File Carving", desc: "8 signatures: JPEG, PNG, PDF, ZIP, GIF, ELF, gzip, SQLite with smart size detection" },
  { label: "Deleted Scanning", desc: "Walk block groups, find inodes with dtime set or links_count=0, recover by inode number" },
  { label: "Interactive Shell", desc: "ls, cd, tree, cat, hexdump, recover, deleted, carve — browse disk images like a filesystem" },
  { label: "Streaming Recovery", desc: "Files >1MB stream directly to disk via BufWriter. No OOM on multi-TB images" },
  { label: "Partition Detection", desc: "MBR and GPT partition table parsing. Auto-detect ext4 and NTFS on each partition" },
  { label: "Forensic Reports", desc: "SHA-256 hashing, audit logging, HTML report generation. Chain of custody for NIST SP 800-86" },
];

export default function Features() {
  return (
    <section className={styles.section} id="features">
      <div className={styles.container}>
        <h2 className={styles.heading}>Capabilities</h2>
        <div className={styles.grid}>
          {capabilities.map((cap) => (
            <div key={cap.label} className={styles.item}>
              <h3>{cap.label}</h3>
              <p>{cap.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
