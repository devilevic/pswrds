/* pswrds service worker.
   Keeps a copy of the app page and icons so the installed app opens even without a connection
   (it then shows "Server unreachable"). Vault data from api.php is never cached. */
const CACHE = "pswrds-v2";
const SHELL = ["/", "/index.html", "/manifest.webmanifest", "/img/icon.svg", "/img/icon-192.png", "/img/icon-512.png", "/img/icon-maskable-512.png", "/favicon.ico"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin || url.pathname.endsWith("/api.php")) return;
  // Network first, so updates arrive immediately; the cached copy is only for when offline.
  e.respondWith(
    fetch(e.request).then(res => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
      return res;
    }).catch(() => caches.match(e.request).then(r => r || caches.match("/index.html")))
  );
});
