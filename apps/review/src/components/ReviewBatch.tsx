import { ArrowRight, DeviceMobile } from '@phosphor-icons/react';
import type { CredentialDisplay } from './Inventory.js';
export interface ReviewBatchProps {
  credentials: readonly CredentialDisplay[];
  windowLabel: string;
  phoneHref: string;
  onCancel: () => void;
}
export function ReviewBatch({ credentials, windowLabel, phoneHref, onCancel }: ReviewBatchProps) {
  return <section aria-labelledby="batch-heading"><h3 id="batch-heading">A finite batch, for this week only</h3>
    <p>{credentials.length} named credentials · {windowLabel}. This sample draft grants no standing authority and cannot approve future changes.</p>
    <ol className="detail-list">{credentials.map(item => <li key={item.id}><strong>{item.label}</strong><span>{item.action} · {item.consumers.length} mapped {item.consumers.length === 1 ? 'consumer' : 'consumers'}</span></li>)}</ol>
    <div className="notice"><strong>Demo · signing unavailable</strong><p>This preview cannot sign a manifest or rotate credentials. The separate phone preview shows the approval boundary; no approval is granted here.</p></div>
    <div className="drawer-actions"><a className="button primary" href={phoneHref}><DeviceMobile size={23} aria-hidden="true" />Open phone preview<ArrowRight size={21} aria-hidden="true" /></a><button className="button secondary-button" onClick={onCancel}>Cancel draft</button></div>
  </section>;
}
