import { Journal } from './journal.js';
import { initializeScheduleSchema } from './schedule.js';
export interface Notification { id: string; kind: string; subject: string; status: 'prepared' | 'delivered' | 'acknowledged' }
export class NotificationFailure extends Error { constructor() { super('notification or journal interlock failed'); } }
function id(s: string): void { if (!/^[-a-zA-Z0-9_.:@/]+$/.test(s) || s.length > 256) throw new Error('Invalid notification metadata'); }
/** Compose checkEffectFence into ApprovalService, including continuation checks. */
export class MutationInterlock {
  private failed = false;
  private journalFailure = false;
  private flushing: Promise<void> | undefined;
  constructor(readonly journal: Journal, private readonly push?: (notification: Readonly<Notification>) => Promise<void>) { initializeScheduleSchema(journal); }
  prepare(notificationId: string, kind: string, subject: string): void {
    id(notificationId); id(kind); id(subject);
    try { this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare("INSERT INTO schedule_outbox VALUES(?,?,?,'prepared')").run(notificationId, kind, subject); }); }
    catch { this.failed = true; throw new NotificationFailure(); }
  }
  list(): Notification[] { return this.journal.read(db => db.prepare('SELECT id,kind,subject,status FROM schedule_outbox ORDER BY rowid').all() as unknown as Notification[]); }
  acknowledge(notificationId: string): void {
    id(notificationId);
    try { this.journal.transaction(db => { this.journal.assertCurrent(db); const result = db.prepare("UPDATE schedule_outbox SET status='acknowledged' WHERE id=? AND status IN ('prepared','delivered')").run(notificationId); if (result.changes !== 1) throw new Error('Unknown or acknowledged notification'); }); }
    catch { this.failed = true; throw new NotificationFailure(); }
  }
  alarms(): Array<{ kind: string; subject: string }> { return this.journal.read(db => db.prepare('SELECT kind,subject FROM schedule_alarm WHERE resolved=0 ORDER BY id').all() as Array<{kind: string; subject: string}>); }
  journalFailed(subject: string): void {
    this.journalFailure = true;
    try { this.journal.transaction(db => db.prepare("INSERT INTO schedule_alarm(kind,subject) VALUES('journal-failed',?)").run(subject)); } catch { /* latch remains if the journal itself is unavailable */ }
  }
  async checkEffectFence(): Promise<void> {
    if (this.failed || this.journalFailure) throw new NotificationFailure();
    try { if (this.alarms().length) throw new NotificationFailure(); await this.flush(); if (this.failed || this.journalFailure || this.alarms().length) throw new NotificationFailure(); }
    catch { this.failed = true; throw new NotificationFailure(); }
  }
  private async flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    this.flushing = this.doFlush();
    try { await this.flushing; } finally { this.flushing = undefined; }
  }
  private async doFlush(): Promise<void> {
    for (const n of this.list().filter(item => item.status === 'prepared')) {
      // No transport means the journaled outbox itself is the notification; the owner reads it.
      if (!this.push) continue;
      try { await this.push(Object.freeze({ ...n })); }
      catch {
        try { this.journal.transaction(db => db.prepare("INSERT INTO schedule_alarm(kind,subject) VALUES('notification-failed',?)").run(n.id)); } catch { /* in-memory latch remains */ }
        throw new NotificationFailure();
      }
      this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare("UPDATE schedule_outbox SET status='delivered' WHERE id=? AND status='prepared'").run(n.id); });
    }
  }
  /** The trusted controller calls only after actual pending intents have been reconciled. */
  acknowledgeJournalRecovery(): void {
    try {
      this.journal.transaction(db => {
        this.journal.assertCurrent(db);
        if (db.prepare("SELECT 1 FROM intent WHERE state!='observed' LIMIT 1").get()) throw new Error('Unreconciled intents remain');
        db.prepare("UPDATE schedule_alarm SET resolved=1 WHERE kind='journal-failed' AND resolved=0").run();
      });
      this.failed = this.alarms().length > 0;
      this.journalFailure = false;
    } catch { this.failed = true; throw new NotificationFailure(); }
  }
  async retry(): Promise<void> {
    try {
      await this.flush();
      this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare("UPDATE schedule_alarm SET resolved=1 WHERE resolved=0 AND kind='notification-failed'").run(); });
      this.failed = this.alarms().length > 0;
      if (this.failed || this.journalFailure) throw new NotificationFailure();
    } catch { this.failed = true; throw new NotificationFailure(); }
  }
}
