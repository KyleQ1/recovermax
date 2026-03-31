import styles from "./Features.module.css";

export default function Features() {
  return (
    <section className={styles.features} id="features">
      <div className={styles.container}>
        <span className={styles.label}>Features</span>
        <h2 className={styles.heading}>Everything you need to recover data</h2>
        <p className={styles.subhead}>
          From structured filesystem recovery to raw file carving, RecoverMax
          handles the full spectrum of data recovery scenarios.
        </p>

        <div className={styles.grid}>
          <article className={styles.card}>
            <div className={`${styles.icon} ${styles.iconFs}`}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
              </svg>
            </div>
            <h3>Filesystem Recovery</h3>
            <p>
              Reads ext4 and NTFS filesystem structures directly. Walks inode
              tables and directory entries to reconstruct deleted files with
              their original names and paths.
            </p>
          </article>

          <article className={styles.card}>
            <div className={`${styles.icon} ${styles.iconCarve}`}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
            </div>
            <h3>Raw File Carving</h3>
            <p>
              Signature-based recovery for JPEG, PNG, PDF, ZIP, SQLite, ELF, and
              more. Smart size detection reads embedded headers to extract exact
              file boundaries.
            </p>
          </article>

          <article className={styles.card}>
            <div className={`${styles.icon} ${styles.iconShell}`}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <polyline points="4 17 10 11 4 5" />
                <line x1="12" y1="19" x2="20" y2="19" />
              </svg>
            </div>
            <h3>Interactive Shell</h3>
            <p>
              Browse recovered filesystems with familiar commands: ls, cd, tree,
              cat. Explore and verify before committing to a full recovery.
            </p>
          </article>

          <article className={styles.card}>
            <div className={`${styles.icon} ${styles.iconSpeed}`}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
              </svg>
            </div>
            <h3>Built for Speed</h3>
            <p>
              Zero-copy mmap I/O with parallel scanning. Designed from the
              ground up to handle multi-terabyte disk images without breaking a
              sweat.
            </p>
          </article>
        </div>
      </div>
    </section>
  );
}
