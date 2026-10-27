import type { Id } from './inventory.js';
export type PrivilegedAuthorityKind = 'store-root' | 'store-recovery' | 'issuer-admin' | 'push-token' | 'approver' | 'dashboard-session';
/** Metadata only: no secret values. Dependencies are IDs of other authorities or recovery resources. */
export interface PrivilegedAuthority { id: Id; kind: PrivilegedAuthorityKind; owner: string; recoveryDependencies: Id[]; }
export type AuthorityRole = 'owner-administration' | 'consumer-delivery' | 'connector-execution';
export interface AuthorityScope { role: AuthorityRole; resourceIds: Id[]; authorityFingerprint: string; }
