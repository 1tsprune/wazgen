/* WAZGEN offline cache */
var CACHE = "wazgen-v6";
var ASSETS = [
  "./",
  "./index.html",
  "./css/style.css?v=6",
  "./js/app.js?v=6",
  "./js/pro.js?v=6",
  "./tokens.css",
  "./LOGO.png",
  "./manifest.webmanifest",
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (cache) {
      return cache.addAll(ASSETS).catch(function () {
        /* partial cache ok */
      });
    }),
  );
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys
          .filter(function (k) {
            return k !== CACHE;
          })
          .map(function (k) {
            return caches.delete(k);
          }),
      );
    }),
  );
  self.clients.claim();
});

self.addEventListener("fetch", function (event) {
  if (event.request.method !== "GET") return;
  event.respondWith(
    caches.match(event.request).then(function (cached) {
      var network = fetch(event.request)
        .then(function (res) {
          if (res && res.status === 200 && res.type === "basic") {
            var copy = res.clone();
            caches.open(CACHE).then(function (cache) {
              cache.put(event.request, copy);
            });
          }
          return res;
        })
        .catch(function () {
          return cached || caches.match("./index.html");
        });
      return cached || network;
    }),
  );
});
