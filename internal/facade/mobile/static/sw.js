// lockhub service worker: makes the web app installable. It caches
// nothing (every answer comes fresh from the hub) and shows a generic
// notification on a push, which carries no data.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("push", (e) => {
  e.waitUntil(self.registration.showNotification("lockhub", { body: "A Lock ticket waits for you.", tag: "lockhub", renotify: true }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window" }).then((cs) => (cs.length ? cs[0].focus() : self.clients.openWindow("/"))));
});
