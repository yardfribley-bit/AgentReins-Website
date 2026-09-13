(() => {
  const payload = JSON.stringify({ path: location.pathname, referrer: document.referrer || null, screen: `${screen.width}x${screen.height}`, language: navigator.language });
  if (navigator.sendBeacon) navigator.sendBeacon('/api/visit', new Blob([payload], {type:'application/json'}));
  else fetch('/api/visit', {method:'POST',headers:{'content-type':'application/json'},body:payload,keepalive:true}).catch(()=>{});
})();
