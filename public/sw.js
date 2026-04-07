self.addEventListener('install', event => {
    console.log('Service Worker installé');
    self.skipWaiting();
});
self.addEventListener('fetch', event => {
    // Stratégie simple : réseau d'abord
    event.respondWith(fetch(event.request));
});