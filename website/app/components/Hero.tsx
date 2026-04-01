import styles from "./Hero.module.css";

export default function Hero() {
  return (
    <section className={styles.hero} id="top">
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>RecoverMax</h1>
          <p className={styles.tagline}>
            Open-source data recovery for ext4 and NTFS. Filesystem reconstruction,
            file carving, interactive shell. Built in Rust.
          </p>
          <div className={styles.badges}>
            <span className={styles.badge}>AGPL-3.0</span>
            <span className={styles.badge}>ext4</span>
            <span className={styles.badge}>NTFS</span>
            <span className={styles.badge}>File Carving</span>
            <span className={styles.badge}>Forensics</span>
            <span className={styles.badge}>Rust</span>
          </div>
          <div className={styles.install}>
            <code>cargo install recovermax</code>
          </div>
          <div className={styles.links}>
            <a href="https://github.com/KyleQ1/recovermax" rel="noopener noreferrer" target="_blank">
              GitHub
            </a>
            <a href="https://github.com/KyleQ1/recovermax/releases" rel="noopener noreferrer" target="_blank">
              Releases
            </a>
            <a href="https://github.com/KyleQ1/recovermax#installation" rel="noopener noreferrer" target="_blank">
              Documentation
            </a>
          </div>
        </div>

        <div className={styles.terminal}>
          <div className={styles.termBar}>
            <span className={styles.termTitle}>recovermax interactive shell</span>
          </div>
          <pre className={styles.termBody}>{`$ recovermax /dev/sda1
RecoverMax v0.1.0
Image: /dev/sda1 (1.82 TB)

Scanning... done.
Partitions:
  [0] EFI System — 512 MB (1.0 MB) type=EFI
  [1] Linux — 1.82 TB (513 MB) type=Linux
Filesystems:
  [0] ext4 "rootfs" — 1.82 TB (offset 513 MB)

Mounted ext4 "rootfs" at /
Type 'help' for available commands.

recovermax:/> ls /home/
  d       4 KB       11 praneeth-bala/
  d       4 KB       12 degrigis/
  d       4 KB       13 gpizarro/
  d       4 KB       14 jerry/
  (4 entries)

recovermax:/> tree /home/praneeth-bala/ 1
├── Documents/
├── research/
├── .ssh/
└── .bashrc

recovermax:/> recover /home/praneeth-bala/ -d ./recovered/
Recovery complete. Files saved to ./recovered/`}</pre>
        </div>
      </div>
    </section>
  );
}
