(() => {
  document.querySelectorAll('[data-language]').forEach(link => {
    link.addEventListener('click', () => localStorage.setItem('agentreins-language', link.dataset.language));
  });
  if (location.pathname !== '/') return;
  const saved = localStorage.getItem('agentreins-language');
  if (saved === 'zh-CN' || (!saved && navigator.language.toLowerCase().startsWith('zh'))) location.replace('/zh-CN/');
})();
