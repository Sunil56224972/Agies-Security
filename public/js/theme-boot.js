// Applies the saved theme before first paint to avoid a flash. Loaded as a
// blocking script because the CSP does not allow inline scripts.
(function () {
  var t = null;
  try { t = localStorage.getItem('aegis.theme'); } catch (e) { /* storage blocked */ }
  if (!t) t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
})();