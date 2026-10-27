import { randomUUID } from 'node:crypto';
import type { Journal } from './journal.js';
export interface EpochRecord {
    version: number;
    installationId: string;
    ownerId: string;
}
/** Existing-store adapter must make compareAndSet atomic; local configuration does not establish this. */
export interface InstallationEpochStore {
    read(): Promise<EpochRecord | undefined>;
    compareAndSet(expectedVersion: number | undefined, next: Omit<EpochRecord, 'version'>): Promise<EpochRecord | undefined>;
}
export interface RecoveryObservations {
    predecessor: 'quiesced' | 'management-authority-invalidated';
    evidenceHash: string;
    inFlightOutcomes: 'reconciled';
}
/** Checks fence future dispatch. They cannot cancel an already-issued upstream request or promise exactly-once effects. */
export class InstallationEpoch {
    readonly ownerId = randomUUID();
    private version: number | undefined;
    private held = true;
    constructor(readonly installationId: string, private readonly store: InstallationEpochStore, private readonly journal: Journal) {
    }
    get recoveryHeld(): boolean {
        return this.held;
    }
    async establishFresh(): Promise<void> {
        const current = await this.store.read();
        if (current) {
            this.journal.setRecoveryHold();
            throw new Error('Existing installation epoch requires predecessor recovery');
        }
        const next = await this.store.compareAndSet(undefined, { installationId: this.installationId, ownerId: this.ownerId });
        if (!next || next.installationId !== this.installationId || next.ownerId !== this.ownerId) {
            this.journal.setRecoveryHold();
            throw new Error('Installation epoch raced; recovery hold');
        }
        this.version = next.version;
        this.held = false;
    }
    async assertBeforeEffect(): Promise<void> {
        const current = await this.store.read();
        if (this.held || !current || current.version !== this.version || current.ownerId !== this.ownerId || current.installationId !== this.installationId) {
            this.held = true;
            this.journal.setRecoveryHold();
            throw new Error('Installation epoch lost; reconcile predecessor and in-flight effects');
        }
    }
    /** Only owning recovery workflow calls after independent observations. No booleans from HTTP are evidence. */
    async recover(observations: RecoveryObservations): Promise<void> {
        if (!['quiesced', 'management-authority-invalidated'].includes(observations.predecessor) || observations.inFlightOutcomes !== 'reconciled' || !/^sha256:[a-f0-9]{64}$/.test(observations.evidenceHash))
            throw new Error('Independent predecessor and reconciliation evidence required');
        this.held = true;
        this.journal.setRecoveryHold();
        const current = await this.store.read();
        if (!current)
            throw new Error('Missing predecessor epoch requires explicit store recovery');
        const next = await this.store.compareAndSet(current.version, { installationId: this.installationId, ownerId: this.ownerId });
        if (!next || next.installationId !== this.installationId || next.ownerId !== this.ownerId)
            throw new Error('Recovery epoch raced');
        this.journal.releaseRecoveryHold();
        this.version = next.version;
        this.held = false;
    }
}
