import styles from "./Footer.module.css";

export default function Footer() {
  return (
    <footer className={styles.footer}>
      <div className={styles.container}>
        <span className={styles.copy}>&copy; {new Date().getFullYear()} RecoverMax</span>
        <span className={styles.sep}>&middot;</span>
        <a href="https://github.com/KyleQ1/recovermax" rel="noopener noreferrer" target="_blank">GitHub</a>
        <span className={styles.sep}>&middot;</span>
        <a href="https://github.com/KyleQ1/recovermax/blob/main/LICENSE" rel="noopener noreferrer" target="_blank">AGPL-3.0</a>
        <span className={styles.sep}>&middot;</span>
        <a href="https://github.com/KyleQ1" rel="noopener noreferrer" target="_blank">UCSB SecLab</a>
      </div>
    </footer>
  );
}
