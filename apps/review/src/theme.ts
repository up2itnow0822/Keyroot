export type Theme = 'light' | 'dark';
export type ThemeChoice = Theme | 'system';
export const THEME_STORAGE_KEY = 'keyroot.theme';

export function normalizeThemeChoice(value: string | null): ThemeChoice {
  return value === 'light' || value === 'dark' ? value : 'system';
}

export interface ThemeEnvironment {
  storedChoice: string | null;
  systemDark: boolean;
  persist?: (choice: ThemeChoice) => void;
  apply?: (theme: Theme) => void;
}

/** Appearance owns no review or authority state. Storage is a best-effort preference. */
export function createThemeController(environment: ThemeEnvironment) {
  let choice = normalizeThemeChoice(environment.storedChoice);
  let systemDark = environment.systemDark;
  const theme = (): Theme => choice === 'system' ? (systemDark ? 'dark' : 'light') : choice;
  let applied = theme();
  environment.apply?.(applied);
  const update = () => {
    if (applied !== theme()) {
      applied = theme();
      environment.apply?.(applied);
    }
  };
  return {
    get choice() { return choice; },
    get theme() { return theme(); },
    choose(next: ThemeChoice) {
      choice = next;
      try { environment.persist?.(next); } catch { /* Preference remains usable with blocked storage. */ }
      update();
    },
    systemChanged(dark: boolean) { systemDark = dark; update(); },
  };
}
