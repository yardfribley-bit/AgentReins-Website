(() => {
  const makeId = () => crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const visitorId = localStorage.getItem('agentreins-visitor') || makeId();
  localStorage.setItem('agentreins-visitor', visitorId);
  const sessionId = sessionStorage.getItem('agentreins-session') || makeId();
  sessionStorage.setItem('agentreins-session', sessionId);
  const common = () => ({visitorId, sessionId, path:location.pathname, referrer:document.referrer || null});
  const send = (endpoint, payload) => {
    const body = JSON.stringify({...common(), ...payload});
    if (navigator.sendBeacon) navigator.sendBeacon(endpoint, new Blob([body], {type:'application/json'}));
    else fetch(endpoint, {method:'POST', headers:{'content-type':'application/json'}, body, keepalive:true}).catch(()=>{});
  };
  const event = (name, value='') => send('/api/event', {name, value});
  send('/api/visit', {screen:`${screen.width}x${screen.height}`, language:navigator.language});
  setTimeout(() => event('engaged_30s'), 30000);

  const reached = new Set();
  addEventListener('scroll', () => {
    const max = document.documentElement.scrollHeight - innerHeight;
    const percent = max > 0 ? Math.round(scrollY / max * 100) : 100;
    [25,50,75,100].forEach(depth => {
      if (percent >= depth && !reached.has(depth)) { reached.add(depth); event('scroll_depth', String(depth)); }
    });
  }, {passive:true});

  const sections = [...document.querySelectorAll('section')];
  const sectionName = section => section.id || (section.classList.contains('hero') ? 'hero' : section.classList.contains('cta') ? 'cta' : 'section');
  if ('IntersectionObserver' in window) {
    const seen = new Set();
    const observer = new IntersectionObserver(entries => entries.forEach(entry => {
      const name = sectionName(entry.target);
      if (entry.isIntersecting && !seen.has(name)) { seen.add(name); event('section_view', name); observer.unobserve(entry.target); }
    }), {threshold:.45});
    sections.forEach(section => observer.observe(section));
  }

  document.addEventListener('click', eventObject => {
    const link = eventObject.target.closest('a'); if (!link) return;
    const url = new URL(link.href, location.href);
    if (url.pathname.startsWith('/download/')) {
      const value = url.pathname.includes('apple-silicon') ? 'Apple Silicon' : 'Intel';
      event('download_click', value);
      url.searchParams.set('vid', visitorId); url.searchParams.set('sid', sessionId); link.href = url.toString();
    } else if (url.hostname === 'github.com') event('outbound_click', 'github');
    else if (url.hostname === 'x.com') event('outbound_click', 'x');
    else if (link.dataset.language) event('language_switch', link.dataset.language);
    else if (url.hash) event('navigation_click', url.hash.slice(1));
  });
})();
