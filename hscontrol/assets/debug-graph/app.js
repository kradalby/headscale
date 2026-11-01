/* Elm owns application state; this bridge handles transport and browser geometry. */
(() => {
  "use strict";
  const app = Elm.Main.init({ node: document.getElementById("app") });
  const debugkey = new URL(location.href).searchParams.get("debugkey");
  let generation = 0;
  let stream = null;
  let snapshotRequest = null;
  let detailRequest = null;
  let detailSequence = 0;
  let hiddenStream = false;

  const url = (path, fields = {}) => {
    const result = new URL(`/debug/graph/${path}`, location.origin);
    for (const [name, value] of Object.entries(fields)) {
      if (value !== "") result.searchParams.set(name, value);
    }
    if (debugkey !== null) result.searchParams.set("debugkey", debugkey);
    return result;
  };
  const deliver = (requestGeneration, type, data) => {
    if (requestGeneration === generation) {
      app.ports.receive.send({ generation: requestGeneration, type, data });
    }
  };
  const stop = () => {
    if (stream) stream.close();
    if (snapshotRequest) snapshotRequest.abort();
    if (detailRequest) detailRequest.abort();
    stream = snapshotRequest = detailRequest = null;
    detailSequence += 1;
  };
  const json = async (target, controller) => {
    const response = await fetch(target, {
      signal: controller.signal,
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (response.status === 409)
      throw new Error(
        "Details are unavailable at this revision. Refresh the paused snapshot or wait for the next live update.",
      );
    if (!response.ok) throw new Error(`Request failed (${response.status}). Check debug access and retry.`);
    return response.json();
  };

  app.ports.request.subscribe((message) => {
    if (message.action === "scene" || message.action === "stop") {
      stop();
      hiddenStream = false;
      generation = message.generation;
      if (message.action === "stop") return;
      const fields = { perspective: message.perspective, search: message.search, focus: message.focus };
      if (message.live) {
        const connection = new EventSource(url("events", fields));
        stream = connection;
        connection.onopen = () => deliver(message.generation, "status", "Receiving baseline");
        connection.onerror = () => {
          if (stream !== connection) return;
          if (connection.readyState === EventSource.CLOSED) {
            deliver(
              message.generation,
              "error",
              "Live connection closed. Check debug access or close another live viewer, then Retry to reconnect.",
            );
          } else {
            deliver(message.generation, "status", "Reconnecting");
          }
        };
        for (const type of ["snapshot", "patch"]) {
          connection.addEventListener(type, (event) => {
            if (stream !== connection || generation !== message.generation) return;
            try {
              deliver(message.generation, type, JSON.parse(event.data));
            } catch {
              deliver(message.generation, "error", "Invalid stream response. Refresh to request a new baseline.");
            }
          });
        }
      } else {
        snapshotRequest = new AbortController();
        json(url("snapshot", fields), snapshotRequest)
          .then((data) => deliver(message.generation, "snapshot", data))
          .catch((error) => {
            if (error.name !== "AbortError") deliver(message.generation, "error", error.message);
          });
      }
    } else if (message.action === "detail" && message.generation === generation) {
      if (detailRequest) detailRequest.abort();
      detailRequest = new AbortController();
      const sequence = ++detailSequence;
      json(url("detail", { id: message.id, revision: message.revision }), detailRequest)
        .then((data) => {
          if (sequence === detailSequence) deliver(message.generation, "detail", data);
        })
        .catch((error) => {
          if (error.name !== "AbortError" && sequence === detailSequence) {
            deliver(message.generation, "detailError", {
              id: message.id,
              revision: message.revision,
              message: error.message,
            });
          }
        });
    }
  });

  // Measurements augment native events; camera and drag calculations stay in Elm.
  const canvas = document.getElementById("graph-canvas");
  const minimap = document.getElementById("graph-minimap");
  const measure = () => {
    const bounds = canvas.getBoundingClientRect();
    deliver(generation, "geometry", { width: Math.max(1, bounds.width), height: Math.max(1, bounds.height) });
  };
  new ResizeObserver(measure).observe(canvas);
  measure();
  canvas.addEventListener(
    "wheel",
    (event) => {
      const bounds = canvas.getBoundingClientRect();
      event.graphPoint = { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
    },
    { capture: true, passive: true },
  );
  minimap.addEventListener(
    "click",
    (event) => {
      const bounds = minimap.getBoundingClientRect();
      event.miniPoint = {
        x: (event.clientX - bounds.left) / bounds.width,
        y: (event.clientY - bounds.top) / bounds.height,
      };
    },
    true,
  );
  canvas.addEventListener(
    "pointerdown",
    (event) => {
      if (event.button !== 0) return;
      const target = event.target.closest(".vertex, .edge") || canvas;
      target.setPointerCapture(event.pointerId);
    },
    true,
  );
  const logo = document.querySelector("[data-headscale-logo]");
  if (logo) logo.src = url("logo.svg").href;
  const debugLink = document.querySelector(".brand");
  if (debugkey !== null && debugLink) {
    const target = new URL(debugLink.href);
    target.searchParams.set("debugkey", debugkey);
    debugLink.href = target.href;
  }
  // A hidden tab holds no live stream: the server admits only a few viewers.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      if (stream) {
        stop();
        hiddenStream = true;
      }
    } else if (hiddenStream) {
      hiddenStream = false;
      deliver(generation, "restore", null);
    }
  });
  window.addEventListener("pagehide", () => {
    stop();
    // pageshow restores a cached page; visibilitychange must not do it again.
    hiddenStream = false;
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) deliver(generation, "restore", null);
  });
})();
