import styles from "./Hero.module.css";

export default function Hero() {
  return (
    <section className={styles.hero}>
      <div className={styles.container}>
        <span className={styles.badge}>Open Source</span>
        <h1 className={styles.title}>RecoverMax</h1>
        <p className={styles.tagline}>
          High-performance data recovery. Open source.
        </p>

        <div className={styles.buttons}>
          <a
            href="https://github.com/KyleQ1/recovermax"
            className={styles.btnPrimary}
            rel="noopener noreferrer"
            target="_blank"
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
              <path d="M2 2.5A2.5 2.5 0 014.5 0h8.75a.75.75 0 01.75.75v12.5a.75.75 0 01-.75.75h-2.5a.75.75 0 110-1.5h1.75v-2h-8a1 1 0 00-.714 1.7.75.75 0 01-1.072 1.05A2.495 2.495 0 012 11.5v-9zm10.5-1h-6a1 1 0 00-1 1v6.708A2.486 2.486 0 017.5 9h5V1.5zM6 13.25v.5a.75.75 0 001.5 0v-.5a.75.75 0 00-1.5 0z" />
            </svg>
            Get Started
          </a>
          <a
            href="https://github.com/KyleQ1/recovermax"
            className={styles.btnSecondary}
            rel="noopener noreferrer"
            target="_blank"
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
              <path d="M4.72 3.22a.75.75 0 011.06 1.06L2.06 8l3.72 3.72a.75.75 0 11-1.06 1.06L.47 8.53a.75.75 0 010-1.06l4.25-4.25zm6.56 0a.75.75 0 10-1.06 1.06L13.94 8l-3.72 3.72a.75.75 0 101.06 1.06l4.25-4.25a.75.75 0 000-1.06l-4.25-4.25z" />
            </svg>
            View Source
          </a>
        </div>

        <div className={styles.terminal} role="img" aria-label="Terminal demonstration of RecoverMax interactive shell showing file listing and recovery commands">
          <div className={styles.terminalBar}>
            <div className={`${styles.dot} ${styles.dotRed}`} />
            <div className={`${styles.dot} ${styles.dotYellow}`} />
            <div className={`${styles.dot} ${styles.dotGreen}`} />
            <div className={styles.terminalTitle}>recovermax — interactive shell</div>
            <div style={{ width: 36 }} />
          </div>
          <div className={styles.terminalBody}>
            <div className={styles.line}>
              <span className={styles.prompt}>$ </span>
              <span className={styles.cmd}>recovermax /dev/sda1 --shell</span>
            </div>
            <div className={styles.line}>
              <span className={styles.output}>Scanning image... 1.82 TB</span>
            </div>
            <div className={styles.line}>
              <span className={styles.highlight}>Found 14,283 recoverable files across 3 partitions</span>
            </div>
            <div className={styles.line}>&nbsp;</div>
            <div className={styles.line}>
              <span className={styles.prompt}>{"recovermax> "}</span>
              <span className={styles.cmd}>ls /home/</span>
            </div>
            <div className={styles.line}>
              <span className={styles.fileDir}>drwxr-xr-x</span>{"  "}
              <span className={styles.fileName}>praneeth-bala/</span>
            </div>
            <div className={styles.line}>
              <span className={styles.fileDir}>drwxr-xr-x</span>{"  "}
              <span className={styles.fileName}>degrigis/</span>
            </div>
            <div className={styles.line}>
              <span className={styles.fileDir}>drwxr-xr-x</span>{"  "}
              <span className={styles.fileName}>gpizarro/</span>
            </div>
            <div className={styles.line}>
              <span className={styles.fileDir}>drwxr-xr-x</span>{"  "}
              <span className={styles.fileName}>jerry/</span>
            </div>
            <div className={styles.line}>
              <span className={styles.dim}>... 8 more directories</span>
            </div>
            <div className={styles.line}>&nbsp;</div>
            <div className={styles.line}>
              <span className={styles.prompt}>{"recovermax> "}</span>
              <span className={styles.cmd}>tree /home/praneeth-bala/ --depth 1</span>
            </div>
            <div className={styles.line}>
              <span className={styles.fileName}>/home/praneeth-bala/</span>
            </div>
            <div className={styles.line}>
              <span className={styles.output}>{"  ├── "}</span>
              <span className={styles.fileName}>Documents/</span>{"    "}
              <span className={styles.fileSize}>2.4 GB</span>
            </div>
            <div className={styles.line}>
              <span className={styles.output}>{"  ├── "}</span>
              <span className={styles.fileName}>research/</span>{"     "}
              <span className={styles.fileSize}>18.7 GB</span>
            </div>
            <div className={styles.line}>
              <span className={styles.output}>{"  ├── "}</span>
              <span className={styles.fileName}>.ssh/</span>{"          "}
              <span className={styles.fileSize}>4.1 KB</span>
            </div>
            <div className={styles.line}>
              <span className={styles.output}>{"  └── "}</span>
              <span className={styles.fileName}>.bashrc</span>{"        "}
              <span className={styles.fileSize}>3.7 KB</span>
            </div>
            <div className={styles.line}>&nbsp;</div>
            <div className={styles.line}>
              <span className={styles.prompt}>{"recovermax> "}</span>
              <span className={styles.cmd}>recover /home/praneeth-bala/ -o ./recovered/</span>
            </div>
            <div className={styles.line}>
              <span className={styles.highlight}>Recovering 1,247 files (21.1 GB)... done in 4m 12s</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
