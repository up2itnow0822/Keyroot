import { useEffect, useRef, type ReactNode } from 'react';
import { X } from '@phosphor-icons/react';
export interface DetailDrawerProps {
  title: string;
  onClose: () => void;
  children: ReactNode;
  returnFocusTo: HTMLElement | null;
  fallbackFocusTo: HTMLElement | null;
}
export function DetailDrawer({ title, onClose, children, returnFocusTo, fallbackFocusTo }: DetailDrawerProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    element.showModal();
    return () => {
      element.close();
      // App captures the actual trigger before React autofocus or showModal runs.
      const target = returnFocusTo?.isConnected ? returnFocusTo : fallbackFocusTo;
      target?.focus({ preventScroll: true });
      if (document.activeElement !== target && fallbackFocusTo?.isConnected) {
        fallbackFocusTo.focus({ preventScroll: true });
      }
    };
  }, [returnFocusTo, fallbackFocusTo]);
  return <dialog ref={dialog} className="detail-drawer" aria-labelledby="drawer-title" onCancel={event => { event.preventDefault(); onClose(); }} onClick={event => { if (event.target === event.currentTarget) onClose(); }}>
    <div className="drawer-surface"><header className="drawer-heading"><h2 id="drawer-title">{title}</h2><button className="icon-button" autoFocus onClick={onClose} aria-label="Close details"><X size={24} aria-hidden="true" /></button></header>{children}</div>
  </dialog>;
}
