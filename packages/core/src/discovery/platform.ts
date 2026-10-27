import type { Binding, DiscoveryResult, Gap } from './scanner.js';
export interface PlatformProvider { id: string; scan(): Promise<{ bindings: Binding[]; gaps: Gap[] }> }
const identifier = /^[A-Za-z0-9_.:@/-]{1,256}$/;
/** Provider adapters return names and availability only. Encrypted values remain unknown. */
export async function scanPlatforms(providers: readonly PlatformProvider[]): Promise<DiscoveryResult> {
  const result: DiscoveryResult = { bindings: [], gaps: [] };
  for (const provider of providers) {
    if (!identifier.test(provider.id)) throw new Error('Invalid provider identifier');
    try {
      const data = await provider.scan();
      const staged: DiscoveryResult = { bindings: [], gaps: [] };
      for (const b of data.bindings) {
        if (!identifier.test(b.sourceId) || !identifier.test(b.name) || (b.consumerId !== undefined && !identifier.test(b.consumerId)) || !['declared', 'inferred', 'observed'].includes(b.provenance)) throw new Error('Invalid metadata');
        staged.bindings.push({ sourceId: b.sourceId, name: b.name, ...(b.consumerId ? { consumerId: b.consumerId } : {}), provenance: b.provenance });
        if (!b.consumerId) staged.gaps.push({ sourceId: b.sourceId, status: 'unplaced', reason: 'consumer association unknown' });
      }
      for (const gap of data.gaps) {
        if (!identifier.test(gap.sourceId) || !['unreadable', 'unscanned', 'unplaced'].includes(gap.status)) throw new Error('Invalid metadata');
        staged.gaps.push({ sourceId: gap.sourceId, status: gap.status, reason: 'provider reported coverage gap' });
      }
      result.bindings.push(...staged.bindings);
      result.gaps.push(...staged.gaps);
    } catch { result.gaps.push({ sourceId: provider.id, status: 'unscanned', reason: 'provider scan failed' }); }
  }
  return result;
}
