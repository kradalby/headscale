/* Run with node bridge-check.js; execute the real transport bridge in a fake browser. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const deliveries = [],
  requests = [],
  streams = [],
  lifecycle = {},
  visibility = {};
let command;
const logoRequests = [];
const logo = {
  set src(value) {
    logoRequests.push(new URL(value));
  },
};
const canvas = {
  getBoundingClientRect: () => ({ width: 900, height: 600, left: 20, top: 60 }),
  addEventListener() {},
};
class EventSource {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 2;
  constructor(url) {
    this.url = url;
    this.events = {};
    this.readyState = EventSource.CONNECTING;
    streams.push(this);
  }
  addEventListener(type, callback) {
    this.events[type] = callback;
  }
  close() {
    this.readyState = EventSource.CLOSED;
  }
}
const context = {
  URL,
  AbortController,
  EventSource,
  location: {
    href: "https://debug.example.test/debug/graph/?debugkey=a%26b&unrelated=secret",
    origin: "https://debug.example.test",
  },
  Elm: {
    Main: {
      init: () => ({
        ports: {
          request: {
            subscribe: (fn) => {
              command = fn;
            },
          },
          receive: { send: (value) => deliveries.push(value) },
        },
      }),
    },
  },
  ResizeObserver: class {
    observe() {}
  },
  document: {
    getElementById: () => canvas,
    querySelector: (selector) => (selector === "[data-headscale-logo]" ? logo : null),
    visibilityState: "visible",
    addEventListener: (type, fn) => {
      visibility[type] = fn;
    },
  },
  window: {
    addEventListener: (type, fn) => {
      lifecycle[type] = fn;
    },
  },
  fetch: (url, options) => new Promise((resolve) => requests.push({ url, options, resolve })),
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "app.js"), "utf8"), context);
const flush = () => new Promise((resolve) => setImmediate(resolve));
const scene = (generation, live = false) =>
  command({ action: "scene", generation, perspective: "world", search: "", focus: "node:1", live });

async function check() {
  assert.equal(logoRequests.length, 1, "logo loads once with its final authorized URL");
  assert.equal(logoRequests[0].pathname, "/debug/graph/logo.svg");
  assert.equal(logoRequests[0].origin, context.location.origin);
  assert.equal(logoRequests[0].searchParams.get("debugkey"), "a&b");
  assert.equal(logoRequests[0].searchParams.has("unrelated"), false);
  scene(1);
  assert.equal(requests[0].url.searchParams.get("debugkey"), "a&b");
  scene(2);
  assert.equal(requests[0].options.signal.aborted, true);
  requests[0].resolve({ ok: true, json: async () => ({ revision: "old" }) });
  requests[1].resolve({ ok: true, json: async () => ({ revision: "new" }) });
  await flush();
  assert.equal(deliveries.filter((v) => v.type === "snapshot").length, 1);
  assert.equal(deliveries.find((v) => v.type === "snapshot").data.revision, "new");

  command({ action: "detail", generation: 2, id: "node:1", revision: "new" });
  command({ action: "detail", generation: 2, id: "node:2", revision: "new" });
  assert.equal(requests[2].options.signal.aborted, true);
  requests[2].resolve({ ok: true, json: async () => ({ id: "node:1" }) });
  requests[3].resolve({ status: 409, ok: false });
  await flush();
  assert.equal(deliveries.filter((v) => v.type === "detail").length, 0);
  assert.equal(deliveries.find((v) => v.type === "detailError").data.id, "node:2");

  scene(3, true);
  const first = streams[0];
  assert.equal(first.url.searchParams.get("debugkey"), "a&b");
  first.onerror();
  assert.equal(deliveries.at(-1).type, "status");
  assert.equal(deliveries.at(-1).data, "Reconnecting");
  first.readyState = EventSource.CLOSED;
  first.onerror();
  assert.equal(deliveries.at(-1).type, "error");
  assert.match(deliveries.at(-1).data, /Retry/);

  scene(4, true);
  const active = streams[1];
  active.readyState = EventSource.OPEN;
  active.events.snapshot({ data: '{"revision":"fresh"}' });
  const beforeHide = deliveries.length;
  lifecycle.pagehide();
  assert.equal(active.readyState, EventSource.CLOSED);
  active.onerror();
  active.events.patch({ data: '{"revision":"stale"}' });
  assert.equal(deliveries.length, beforeHide);
  lifecycle.pageshow({ persisted: false });
  assert.equal(deliveries.length, beforeHide);
  lifecycle.pageshow({ persisted: true });
  assert.equal(deliveries.at(-1).type, "restore");
  assert.equal(deliveries.at(-1).generation, 4);
  assert.equal(streams.length, 2, "Elm must decide the next request and generation");
  scene(5, true);
  assert.equal(streams.length, 3);
  streams[2].events.snapshot({ data: '{"revision":"restored-baseline"}' });
  assert.equal(deliveries.at(-1).generation, 5);
  assert.equal(deliveries.at(-1).data.revision, "restored-baseline");
  active.events.snapshot({ data: '{"revision":"obsolete"}' });
  assert.equal(deliveries.at(-1).data.revision, "restored-baseline");

  command({ action: "stop", generation: 6 });
  assert.equal(streams[2].readyState, EventSource.CLOSED);
  lifecycle.pagehide();
  lifecycle.pageshow({ persisted: true });
  assert.equal(deliveries.at(-1).generation, 6);
  scene(7);
  assert.equal(streams.length, 3, "paused restoration must not open a stream");
  assert.equal(requests.at(-1).url.pathname, "/debug/graph/snapshot");

  const tab = (state) => {
    context.document.visibilityState = state;
    visibility.visibilitychange();
  };
  scene(8, true);
  const watched = streams.at(-1);
  tab("hidden");
  assert.equal(watched.readyState, EventSource.CLOSED, "a hidden tab gives up its live stream");
  const whileHidden = deliveries.length;
  watched.events.patch({ data: '{"revision":"hidden"}' });
  assert.equal(deliveries.length, whileHidden);
  tab("visible");
  assert.equal(deliveries.at(-1).type, "restore");
  assert.equal(deliveries.at(-1).generation, 8);
  tab("hidden");
  tab("visible");
  assert.equal(deliveries.length, whileHidden + 1, "only a stream closed by hiding is restored");
  scene(9);
  tab("hidden");
  tab("visible");
  assert.equal(deliveries.length, whileHidden + 1, "a paused snapshot survives a tab switch");
  scene(10, true);
  tab("hidden");
  lifecycle.pagehide();
  const cached = deliveries.length;
  tab("visible");
  assert.equal(deliveries.length, cached, "a cached page is restored by pageshow alone");
  lifecycle.pageshow({ persisted: true });
  assert.equal(deliveries.length, cached + 1);
  assert.equal(deliveries.at(-1).type, "restore");

  const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
  for (const location of [context.location, { href: "http://localhost/debug/graph/", origin: "http://localhost" }]) {
    const assets = [];
    const key = new URL(location.href).searchParams.get("debugkey");
    const bootstrap = {
      URL,
      location,
      document: {
        createElement: (tag) => ({ tag }),
        head: {
          appendChild: (element) => {
            const url = new URL(element.src || element.href);
            assert.equal(url.origin, location.origin);
            assert.equal(url.searchParams.get("debugkey"), key, "assets are authorized before insertion");
            assert.equal(url.searchParams.has("unrelated"), false);
            assets.push(element);
          },
        },
        getElementById: () => ({}),
      },
    };
    vm.runInNewContext(html.slice(html.indexOf("<script>") + 8, html.indexOf("</script>")), bootstrap);
    assert.equal(new URL(assets.find((a) => a.rel === "stylesheet").href).pathname, "/debug/graph/style.css");
    assert.equal(new URL(assets.find((a) => a.rel === "icon").href).pathname, "/debug/graph/favicon.png");
    const scripts = () => assets.filter((a) => a.tag === "script");
    assert.equal(scripts().length, 1);
    assert.equal(new URL(scripts()[0].src).pathname, "/debug/graph/elm.js");
    scripts()[0].onload();
    assert.equal(new URL(scripts()[1].src).pathname, "/debug/graph/app.js");
  }
  console.log(
    "PASS bridge runtime: lifecycle and hidden-tab restoration, terminal/reconnecting errors, protected assets, stale generations/details, conflicts and stream cleanup",
  );
}
check().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
