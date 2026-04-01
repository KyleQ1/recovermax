import styles from "./OpenSource.module.css";

export default function OpenSource() {
  return (
    <section className={styles.section} id="specs">
      <div className={styles.container}>
        <div className={styles.columns}>
          <div>
            <h2 className={styles.heading}>Technical Specifications</h2>
            <table className={styles.specTable}>
              <tbody>
                <tr><td>Language</td><td>Rust (memory-safe, zero-cost abstractions)</td></tr>
                <tr><td>I/O</td><td>mmap via memmap2 (zero-copy, multi-TB capable)</td></tr>
                <tr><td>Filesystems</td><td>ext4 (full), NTFS (read + recover)</td></tr>
                <tr><td>Carving Signatures</td><td>JPEG, PNG, PDF, ZIP, GIF, ELF, gzip, SQLite</td></tr>
                <tr><td>Partition Tables</td><td>MBR, GPT</td></tr>
                <tr><td>Platforms</td><td>Linux, macOS, Windows</td></tr>
                <tr><td>License</td><td>AGPL-3.0</td></tr>
                <tr><td>Tests</td><td>183 integration tests across 11 suites</td></tr>
                <tr><td>Streaming Threshold</td><td>1 MB (larger files stream to disk)</td></tr>
                <tr><td>Forensics</td><td>SHA-256 hashing, audit log, HTML reports</td></tr>
              </tbody>
            </table>
          </div>
          <div>
            <h2 className={styles.heading}>One-Shot CLI Commands</h2>
            <div className={styles.cmdList}>
              <div className={styles.cmd}>
                <code>recovermax info &lt;image&gt;</code>
                <span>Show image info, partitions, filesystems</span>
              </div>
              <div className={styles.cmd}>
                <code>recovermax scan &lt;image&gt;</code>
                <span>Scan for recoverable filesystems</span>
              </div>
              <div className={styles.cmd}>
                <code>recovermax recover &lt;image&gt; -d &lt;dest&gt;</code>
                <span>Recover all files to destination</span>
              </div>
              <div className={styles.cmd}>
                <code>recovermax carve &lt;image&gt; -d &lt;dest&gt;</code>
                <span>Raw file carving by signature</span>
              </div>
              <div className={styles.cmd}>
                <code>recovermax deleted &lt;image&gt;</code>
                <span>List deleted inodes</span>
              </div>
              <div className={styles.cmd}>
                <code>recovermax hexdump &lt;image&gt; -o 0x400</code>
                <span>Hex dump at offset</span>
              </div>
              <div className={styles.cmd}>
                <code>recovermax &lt;image&gt;</code>
                <span>Open interactive shell</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
