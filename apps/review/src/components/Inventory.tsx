import { Cloud, Laptop, OpenAiLogo } from '@phosphor-icons/react';

export type ProviderIcon = 'openai' | 'hosting' | 'local';
export interface CredentialDisplay {
  id: string;
  label: string;
  action: string;
  icon: ProviderIcon;
  consumers: readonly string[];
  status: string;
  statusDetail: string;
  notes: string;
  capability: string;
  provenance: string;
  limitations: readonly string[];
}
export interface InventoryProps {
  credentials: readonly CredentialDisplay[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}
const icons = { openai: OpenAiLogo, hosting: Cloud, local: Laptop };
export function Inventory({ credentials, selectedId, onSelect }: InventoryProps) {
  return <div className="inventory-scroll"><table className="inventory">
    <caption className="sr-only">Credential changes awaiting your review</caption>
    <colgroup><col className="credential-column" /><col className="consumer-column" /><col className="status-column" /><col className="notes-column" /></colgroup>
    <thead><tr><th scope="col">Credential</th><th scope="col">Known consumers</th><th scope="col">Status</th><th scope="col">Notes</th></tr></thead>
    <tbody>{credentials.map(credential => {
      const Icon = icons[credential.icon];
      return <tr key={credential.id} data-selected={credential.id === selectedId ? 'true' : undefined}>
        <th scope="row"><button className="credential-link" onClick={() => onSelect(credential.id)} aria-haspopup="dialog" aria-label={`Inspect ${credential.label}`}>
          <Icon className="provider-icon" size={47} weight="regular" aria-hidden="true" />
          <span><span className="credential-title">{credential.label}</span><span className="secondary credential-action">{credential.action}</span></span>
        </button></th>
        <td><strong className="consumer-count">{credential.consumers.length} {credential.consumers.length === 1 ? 'consumer' : 'consumers'}</strong><span className="secondary consumer-list">{credential.consumers.map(name => <span key={name}>{name}</span>)}</span></td>
        <td><span className="status-badge">{credential.status}</span><span className="secondary status-detail">{credential.statusDetail}</span></td>
        <td className="secondary notes">{credential.notes}</td>
      </tr>;
    })}</tbody>
  </table></div>;
}
