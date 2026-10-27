import { useEffect, useReducer, useRef, useState } from 'react';
import { ArrowRight, DeviceMobile, Info, Moon, Sun } from '@phosphor-icons/react';
import { Inventory, type CredentialDisplay } from './components/Inventory.js';
import { DetailDrawer } from './components/DetailDrawer.js';
import { Operation, type EvidenceDisplay } from './components/Operation.js';
import { ReviewBatch } from './components/ReviewBatch.js';
import { createThemeController, THEME_STORAGE_KEY, type Theme, type ThemeChoice } from './theme.js';

export interface ReviewDisplay {
  dateLabel: string;
  weekLabel: string;
  intro: string;
  windowLabel: string;
  credentials: readonly CredentialDisplay[];
  evidence: readonly EvidenceDisplay[];
  nextAction: string;
  phoneHref: string;
}
export const sampleReview: ReviewDisplay = {
  dateLabel: 'Monday, October 26, 2026', weekLabel: 'Oct 26 – Nov 1, 2026',
  intro: 'Three rotations are ready for your review. Changes start only after phone approval.',
  windowLabel: 'Window ends Nov 1', phoneHref: '/phone.html',
  credentials: [
    { id: 'openai-api', label: 'OpenAI · project service key', action: 'Rotating to a new key', icon: 'openai', consumers: ['Research script', 'CI test job'], status: 'Planned', statusDetail: 'Awaiting approval', notes: 'Mapped consumer adoption is checked before ordinary revocation.', capability: 'API workload · project service key', provenance: 'Synthetic fixture: Research script and CI test job are declared sample consumers, not discovered accounts.', limitations: ['Delivery has not started.', 'Consumer adoption is unknown until a direct use receipt is observed.', 'Issuer revocation and old-key rejection require separate evidence.'] },
    { id: 'demo-hosting', label: 'Demo hosting · API key', action: 'Rotating to a new key', icon: 'hosting', consumers: ['Demo web app'], status: 'Planned', statusDetail: 'Awaiting approval', notes: 'Mapped consumer adoption is checked before ordinary revocation.', capability: 'API key · provider eligibility unverified', provenance: 'Synthetic fixture: Demo hosting is an illustrative provider, not a verified dashboard or API integration.', limitations: ['No issuer capability is admitted for a real account.', 'Use a guided procedure if no eligible API or admitted dashboard workflow exists.', 'Recipe drift requires owner review before further guided work.'] },
    { id: 'local-oauth', label: 'Local integration · OAuth grant', action: 'Refreshing OAuth grant', icon: 'local', consumers: ['Local desktop integration'], status: 'Planned', statusDetail: 'Awaiting approval', notes: 'Issuer consent may be required for this local grant.', capability: 'OAuth grant · issuer consent may be required', provenance: 'Synthetic fixture: local integration is an illustrative OAuth consumer. Native Claude Code and Codex subscription sign-ins are outside this batch.', limitations: ['Consent eligibility and refresh support are unverified.', 'If issuer consent is needed, complete it through the issuer-owned flow.', 'Native subscription sign-ins remain unchanged.'] },
  ],
  evidence: [
    { label: 'Delivery', outcome: 'Not started', detail: 'No secret has been created, pushed, or replaced.' },
    { label: 'Consumer adoption', outcome: 'Unknown', detail: 'No direct-use receipts. Inferred evidence would be labeled separately.' },
    { label: 'Old-use hold', outcome: 'Not evaluated', detail: 'Observed old-key use would hold ordinary revocation for reconciliation.' },
    { label: 'Issuer revocation', outcome: 'Unverified', detail: 'No issuer request or issuer confirmation exists.' },
    { label: 'Old-key rejection', outcome: 'Unverified', detail: 'A timeout or failed request would not prove revocation.' },
  ],
  nextAction: 'Inspect the named consumers and provider limitations, then review the finite scope on the phone preview. Signing and credential mutation remain unavailable.',
};
export type DrawerView = 'details' | 'credential' | 'inventory' | 'operation' | 'batch' | 'settings';
export interface ReviewState { drawer: DrawerView | null; selectedId: string | null; draft: 'none' | 'reviewing'; }
export type ReviewAction = { type: 'select'; id: string } | { type: 'open'; drawer: DrawerView } | { type: 'close' } | { type: 'cancel' } | { type: 'reset'; review: ReviewDisplay };
export function createReviewState(review: ReviewDisplay): ReviewState { return { drawer: null, selectedId: review.credentials[0]?.id ?? null, draft: 'none' }; }
export function reviewReducer(state: ReviewState, action: ReviewAction): ReviewState {
  switch (action.type) {
    case 'select': return { ...state, selectedId: action.id, drawer: 'credential' };
    case 'open': return { ...state, drawer: action.drawer, draft: action.drawer === 'batch' ? 'reviewing' : state.draft };
    case 'close': return { ...state, drawer: null };
    case 'cancel': return { ...state, drawer: null, draft: 'none' };
    case 'reset': return createReviewState(action.review);
  }
}
export function useAppearance() {
  const [appearance] = useState(() => {
    let storedChoice: string | null = null;
    try { if (typeof window !== 'undefined') storedChoice = window.localStorage.getItem(THEME_STORAGE_KEY); } catch { /* Follow system when storage is unavailable. */ }
    return createThemeController({ storedChoice, systemDark: typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches, persist: value => window.localStorage.setItem(THEME_STORAGE_KEY, value) });
  });
  const [, redraw] = useReducer((value: number) => value + 1, 0);
  useEffect(() => {
    document.documentElement.dataset.theme = appearance.theme;
    document.documentElement.style.colorScheme = appearance.theme;
  }, [appearance, appearance.theme]);
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const update = () => { appearance.systemChanged(media.matches); redraw(); };
    update();
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, [appearance]);
  return { theme: appearance.theme, choice: appearance.choice, choose: (value: ThemeChoice) => { appearance.choose(value); redraw(); } };
}
export interface AppearanceProps { choice: ThemeChoice; theme: Theme; choose: (value: ThemeChoice) => void; }
export function AppearanceControls({ theme, choose }: AppearanceProps) {
  return <div className="theme-control" role="group" aria-label="Appearance"><button aria-pressed={theme === 'light'} onClick={() => choose('light')}><Sun size={25} aria-hidden="true" />Light</button><button aria-pressed={theme === 'dark'} onClick={() => choose('dark')}><Moon size={24} aria-hidden="true" />Dark</button></div>;
}
export interface AppProps { review?: ReviewDisplay; }
export function App({ review = sampleReview }: AppProps) {
  const [state, dispatch] = useReducer(reviewReducer, review, createReviewState);
  const drawerOpener = useRef<HTMLElement | null>(null);
  const detailsTrigger = useRef<HTMLButtonElement | null>(null);
  const appearance = useAppearance();
  const selected = review.credentials.find(item => item.id === state.selectedId);
  const consumerCount = review.credentials.reduce((count, item) => count + item.consumers.length, 0);
  const titles: Record<DrawerView, string> = { details: 'This week’s change details', credential: selected?.label ?? 'Credential details', inventory: 'Known inventory & coverage', operation: 'Operation evidence', batch: 'Review on phone', settings: 'Appearance & preview' };
  return <>
    <header className="site-header"><a className="wordmark" href="#main">Keyroot</a><span className="preview-label">Design preview · sample data</span><div className="header-right"><AppearanceControls {...appearance} /><time dateTime="2026-10-26">{review.dateLabel}</time></div></header>
    <main id="main" className="review-page" onClickCapture={event => {
      if (state.drawer !== null || !(event.target instanceof Element)) return;
      const trigger = event.target.closest<HTMLElement>('button, a');
      if (trigger?.isConnected && event.currentTarget.contains(trigger)) drawerOpener.current = trigger;
    }}>
      <section className="hero" aria-labelledby="review-title"><h1 id="review-title">Review this week’s changes</h1><p className="week-label">{review.weekLabel}</p><p className="intro">{review.intro}</p></section>
      <section className="stats-strip" aria-label="Batch scope"><div className="stat"><p><span className="stat-number">{review.credentials.length}</span> credentials</p><span>In this week’s batch</span></div><div className="stat"><p><span className="stat-number">{consumerCount}</span> mapped consumers</p><span>Across your development machines<br />and connected platforms</span></div><div className="stat window-stat"><p>{review.windowLabel}</p><span>No planned outage</span></div></section>
      <Inventory credentials={review.credentials} selectedId={state.selectedId} onSelect={id => dispatch({ type: 'select', id })} />
      <footer className="review-footer"><div className="caveats"><div className="evidence-caveat"><Info size={27} aria-hidden="true" /><p>Consumer adoption and issuer revocation will be checked separately after you approve.<br />Production requests and refresh do not depend on Box.</p></div><p className="scope-caveat">Native subscription sign-ins remain unchanged.<br />We reuse your existing secret store. No raw secret values are shown.</p></div><div className="footer-actions"><div className="main-actions"><button className="button primary" aria-haspopup="dialog" onClick={() => dispatch({ type: 'open', drawer: 'batch' })}><DeviceMobile size={28} aria-hidden="true" />Review on phone<ArrowRight size={24} aria-hidden="true" /></button><button ref={detailsTrigger} className="button secondary-button" aria-haspopup="dialog" onClick={() => dispatch({ type: 'open', drawer: 'details' })}>Inspect change details</button></div><p className="coverage-caveat">Coverage is based on known consumers. Unknowns remain visible.</p></div></footer>
    </main>
    {state.drawer && <DetailDrawer title={titles[state.drawer]} returnFocusTo={drawerOpener.current} fallbackFocusTo={detailsTrigger.current} onClose={() => dispatch({ type: 'close' })}>
      <nav className="drawer-nav" aria-label="Review details">{(['details', 'inventory', 'operation', 'settings'] as const).map(view => <button key={view} aria-current={state.drawer === view ? 'page' : undefined} onClick={() => dispatch({ type: 'open', drawer: view })}>{({ details: 'Overview', inventory: 'Inventory', operation: 'Evidence', settings: 'Appearance' })[view]}</button>)}</nav>
      {state.draft === 'reviewing' && state.drawer !== 'batch' && <button className="draft-return" onClick={() => dispatch({ type: 'open', drawer: 'batch' })}>Return to phone review draft<ArrowRight size={18} aria-hidden="true" /></button>}
      {state.drawer === 'batch' && <ReviewBatch credentials={review.credentials} windowLabel={review.windowLabel} phoneHref={review.phoneHref} onCancel={() => dispatch({ type: 'cancel' })} />}
      {state.drawer === 'details' && <section><p className="eyebrow">Sample batch · no credential changes</p><h3>Review scope before giving authority</h3><p>{review.credentials.length} credentials and {consumerCount} mapped consumers are proposed for this finite window. Unknown consumers remain unknown; known coverage is not a complete scan.</p><ul className="detail-list">{review.credentials.map(item => <li key={item.id}><button className="text-link" onClick={() => dispatch({ type: 'select', id: item.id })}>{item.label}<ArrowRight size={18} aria-hidden="true" /></button><span>{item.action}</span></li>)}</ul><div className="notice"><strong>Recovery and local control</strong><p>Independent recovery, emergency scope, and the configured 15–30 minute outage grace require validation. Production requests do not depend on this box. This preview cannot contain a compromised machine or recover a vault.</p></div><button className="button primary" onClick={() => dispatch({ type: 'open', drawer: 'batch' })}>Review finite phone scope<ArrowRight size={20} aria-hidden="true" /></button></section>}
      {state.drawer === 'credential' && selected && <section><p className="eyebrow">{selected.capability}</p><h3>{selected.action}</h3><p><span className="status-badge">{selected.status}</span> <span className="secondary">{selected.statusDetail}</span></p><h4>Known consumers</h4><ul>{selected.consumers.map(consumer => <li key={consumer}>{consumer} <span className="secondary">· adoption unknown</span></li>)}</ul><h4>Provenance</h4><p>{selected.provenance}</p><h4>Limits & next steps</h4><ul>{selected.limitations.map(limit => <li key={limit}>{limit}</li>)}</ul><button className="button secondary-button" onClick={() => dispatch({ type: 'open', drawer: 'operation' })}>Inspect separate evidence</button></section>}
      {state.drawer === 'inventory' && <section><h3>Declared consumers, visible unknowns</h3><p>Four personal machines are in product scope. These sample rows name {consumerCount} consumers; they do not claim a completed scan of those machines or connected platforms.</p><ul className="detail-list">{review.credentials.map(item => <li key={item.id}><button className="text-link" onClick={() => dispatch({ type: 'select', id: item.id })}>{item.label}<ArrowRight size={18} aria-hidden="true" /></button><span>{item.consumers.join(' · ')}</span><span>{item.capability}</span></li>)}</ul><div className="notice"><strong>Coverage is unverified</strong><p>No real provider, store, account, or consumer is connected. Native subscription sessions remain owned by their applications.</p></div></section>}
      {state.drawer === 'operation' && <Operation evidence={review.evidence} nextAction={review.nextAction} />}
      {state.drawer === 'settings' && <section><h3>Choose your appearance</h3><p>Your first visit follows your device. An explicit choice stays on this browser and preserves your open details, selected credential, and review draft.</p><AppearanceControls {...appearance} /><button className="button secondary-button system-choice" aria-pressed={appearance.choice === 'system'} onClick={() => appearance.choose('system')}>Follow system appearance</button><p className="secondary">{appearance.choice === 'system' ? 'Following your device appearance.' : `Using your saved ${appearance.choice === 'light' ? 'Light' : 'Dark'} appearance.`} If browser storage is unavailable, your choice lasts for this visit.</p><h3>Reset this sample</h3><p>Closes the drawer and clears the local sample draft. No credential operation is created or canceled.</p><button className="button secondary-button" onClick={() => dispatch({ type: 'reset', review })}>Reset preview</button></section>}
      <div className="drawer-appearance"><span>Appearance</span><AppearanceControls {...appearance} /></div>
    </DetailDrawer>}
  </>;
}
