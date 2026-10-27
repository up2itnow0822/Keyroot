export interface EvidenceDisplay { label: string; outcome: string; detail: string; }
export interface OperationProps { evidence: readonly EvidenceDisplay[]; nextAction: string; }
export function Operation({ evidence, nextAction }: OperationProps) {
  return <section aria-labelledby="operation-heading"><h3 id="operation-heading">Evidence stays separate</h3><p>No operation has started in this preview. Planned delivery is never evidence of adoption or revocation.</p>
    <dl className="evidence-list">{evidence.map(item => <div key={item.label}><dt>{item.label}</dt><dd><strong>{item.outcome}</strong><span>{item.detail}</span></dd></div>)}</dl>
    <div className="notice"><strong>Next owner action</strong><p>{nextAction}</p></div>
  </section>;
}
