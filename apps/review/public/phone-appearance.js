(() => {
  let choice = 'system';
  try { choice = localStorage.getItem('keyroot.theme') ?? 'system'; } catch { /* Storage may be unavailable. */ }
  const theme = choice === 'light' || choice === 'dark' ? choice : window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
})();
