import Link from "next/link";
import styles from "./Navbar.module.css";

export default function Navbar() {
  return (
    <nav className={styles.nav}>
      <div className={styles.container}>
        <a href="/#top" className={styles.logo}>recovermax</a>
        <ul className={styles.links}>
          <li><Link href="/#features">Capabilities</Link></li>
          <li><Link href="/#comparison">Comparison</Link></li>
          <li><Link href="/#usage">Usage</Link></li>
          <li><Link href="/#specs">Specs</Link></li>
        </ul>
        <a
          href="https://github.com/KyleQ1/recovermax"
          className={styles.github}
          aria-label="GitHub repository"
          rel="noopener noreferrer"
          target="_blank"
        >
          Source Code
        </a>
      </div>
    </nav>
  );
}
