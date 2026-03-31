import styles from "./HowItWorks.module.css";

export default function HowItWorks() {
  return (
    <section className={styles.section} id="how-it-works">
      <div className={styles.container}>
        <span className={styles.label}>How It Works</span>
        <h2 className={styles.heading}>Three steps to recovered data</h2>
        <p className={styles.subhead}>
          No complicated setup. No GUIs to configure. Point, explore, recover.
        </p>

        <div className={styles.steps}>
          <div className={styles.step}>
            <div className={styles.stepNumber}>1</div>
            <h3>Point at a disk image</h3>
            <p>
              Pass a raw disk image, device file, or partition. RecoverMax
              handles the rest.
            </p>
            <div className={styles.stepCmd}>recovermax ./disk.img</div>
          </div>

          <div className={styles.step}>
            <div className={styles.stepNumber}>2</div>
            <h3>Browse and explore</h3>
            <p>
              Use the interactive shell to navigate the recovered filesystem.
              Preview files before recovering.
            </p>
            <div className={styles.stepCmd}>recovermax&gt; tree /home/</div>
          </div>

          <div className={styles.step}>
            <div className={styles.stepNumber}>3</div>
            <h3>Recover what you need</h3>
            <p>
              Selectively recover individual files, directories, or everything
              at once.
            </p>
            <div className={styles.stepCmd}>
              recovermax&gt; recover /home/ -o ./out/
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
