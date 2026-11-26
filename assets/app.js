/* Progressive enhancement only. Briefings and sources remain readable without JavaScript. */
(() => {
  "use strict";

  const freshnessNote = document.getElementById("freshness-note");
  const digestDate = document.body.dataset.digestDate;
  if (freshnessNote && /^\d{4}-\d{2}-\d{2}$/.test(digestDate || "")) {
    const editionNoon = Date.parse(`${digestDate}T12:00:00Z`);
    const now = new Date();
    const todayNoon = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 12);
    if (Number.isFinite(editionNoon) && todayNoon - editionNoon > 2 * 86400000) {
      freshnessNote.textContent = "This edition is more than two days old. Check vendor advisories for current fixes before acting.";
      freshnessNote.hidden = false;
    }
  }

  const form = document.getElementById("filters");
  const cards = Array.from(document.querySelectorAll("article.briefing-item"));
  if (!form || !cards.length) return;

  const search = document.getElementById("search");
  const audience = document.getElementById("audience");
  const urgency = document.getElementById("urgency");
  const savedOnlyButton = document.getElementById("watchlist-toggle");
  const clearButton = document.getElementById("clear-filters");
  const resultCount = document.getElementById("result-count");
  const noResults = document.getElementById("no-results");
  const status = document.getElementById("watchlist-status");
  const savedCount = document.getElementById("saved-count");
  if (!search || !audience || !urgency || !savedOnlyButton || !clearButton) return;

  const storageKey = "patch-these.saved-products.v1";
  const validAudiences = new Set(["all", "end_users", "applications_and_servers"]);
  const validUrgencies = new Set(["all", "act_now", "act_soon", "monitor"]);
  let saved = new Set();
  let savedOnly = false;
  let storageAvailable = true;

  function readSaved() {
    try {
      const raw = JSON.parse(localStorage.getItem(storageKey) || "[]");
      return new Set(Array.isArray(raw) ? raw.filter((id) => typeof id === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id)) : []);
    } catch (_) {
      return new Set();
    }
  }

  function persistSaved() {
    try {
      localStorage.setItem(storageKey, JSON.stringify(Array.from(saved).sort()));
      storageAvailable = true;
    } catch (_) {
      storageAvailable = false;
    }
  }

  function normalize(value) {
    return value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLocaleLowerCase().trim();
  }

  function announce(message) {
    if (status) status.textContent = message;
  }

  function loadUrlFilters() {
    const params = new URLSearchParams(window.location.search);
    search.value = (params.get("q") || "").slice(0, 500);
    audience.value = validAudiences.has(params.get("audience")) ? params.get("audience") : "all";
    urgency.value = validUrgencies.has(params.get("urgency")) ? params.get("urgency") : "all";
  }

  function updateUrl() {
    try {
      const url = new URL(window.location.href);
      const values = { q: search.value.trim(), audience: audience.value, urgency: urgency.value };
      for (const [key, value] of Object.entries(values)) {
        if (value && value !== "all") url.searchParams.set(key, value);
        else url.searchParams.delete(key);
      }
      if (url.href !== window.location.href) history.replaceState(null, "", url);
    } catch (_) {
      // Local file previews and restricted contexts can still use filters.
    }
  }

  function matches(card) {
    const haystack = normalize(card.dataset.search || card.dataset.product || "");
    const terms = normalize(search.value).split(/\s+/).filter(Boolean);
    const audienceMatches = audience.value === "all" || card.dataset.audience === audience.value || card.dataset.audience === "both";
    const urgencyMatches = urgency.value === "all" || card.dataset.priority === urgency.value;
    const savedMatches = !savedOnly || saved.has(card.dataset.productId);
    return terms.every((term) => haystack.includes(term)) && audienceMatches && urgencyMatches && savedMatches;
  }

  function updateSavedButtons() {
    for (const button of document.querySelectorAll(".watch-button[data-watch-id]")) {
      const selected = saved.has(button.dataset.watchId);
      const card = button.closest(".briefing-item");
      const product = card ? card.dataset.product : "this product";
      button.setAttribute("aria-pressed", String(selected));
      button.setAttribute("aria-label", selected ? `Remove ${product} from saved products` : `Save ${product}`);
      const label = button.querySelector(".watch-label");
      if (label) label.textContent = selected ? "Saved" : "Save product";
      else button.textContent = selected ? "Saved" : "Save product";
    }
    if (savedCount) savedCount.textContent = String(saved.size);
    savedOnlyButton.setAttribute("aria-pressed", String(savedOnly));
  }

  function render(syncUrl = true) {
    let visible = 0;
    for (const card of cards) {
      const show = matches(card);
      card.hidden = !show;
      if (show) visible += 1;
    }
    const active = Boolean(search.value.trim()) || audience.value !== "all" || urgency.value !== "all" || savedOnly;
    document.body.classList.toggle("has-active-filters", active);
    if (resultCount) resultCount.textContent = `${visible} of ${cards.length} ${cards.length === 1 ? "item" : "items"} shown`;
    if (noResults) {
      noResults.hidden = visible !== 0;
      noResults.textContent = savedOnly && saved.size === 0
        ? "No saved products yet. Turn off Saved products, then choose Save product on the products you want to follow."
        : savedOnly
          ? "No saved products match these filters. Try clearing your search or showing all products."
          : "No items match these filters. Try another product name or clear the filters.";
    }
    updateSavedButtons();
    if (syncUrl) updateUrl();
  }

  function resetFilters() {
    search.value = "";
    audience.value = "all";
    urgency.value = "all";
    savedOnly = false;
  }

  function revealHashTarget() {
    if (!window.location.hash) return false;
    let target;
    try {
      target = document.getElementById(decodeURIComponent(window.location.hash.slice(1)));
    } catch (_) {
      return false;
    }
    const card = target && target.closest(".briefing-item");
    if (!card || matches(card)) return false;
    resetFilters();
    announce("Filters cleared to show the linked item.");
    return true;
  }

  saved = readSaved();
  loadUrlFilters();
  revealHashTarget();
  render();
  document.documentElement.classList.add("js");

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    render();
  });
  search.addEventListener("input", () => render());
  audience.addEventListener("change", () => render());
  urgency.addEventListener("change", () => render());
  savedOnlyButton.addEventListener("click", () => {
    savedOnly = !savedOnly;
    render();
  });
  clearButton.addEventListener("click", () => {
    resetFilters();
    render();
    search.focus();
  });

  for (const button of document.querySelectorAll(".watch-button[data-watch-id]")) {
    button.addEventListener("click", () => {
      const id = button.dataset.watchId;
      const card = button.closest(".briefing-item");
      const product = card ? card.dataset.product : "Product";
      const wasSaved = saved.has(id);
      if (wasSaved) saved.delete(id);
      else saved.add(id);
      persistSaved();
      render(false);
      announce(`${product} ${wasSaved ? "removed from" : "added to"} saved products.${storageAvailable ? "" : " This preference is available for this page visit only."}`);
      // A removed saved-only card disappears; leave focus on a visible control.
      if (savedOnly && wasSaved) savedOnlyButton.focus();
    });
  }

  window.addEventListener("popstate", () => {
    loadUrlFilters();
    savedOnly = false;
    const revealed = revealHashTarget();
    render(revealed);
  });
  window.addEventListener("hashchange", () => {
    if (revealHashTarget()) render();
  });
  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) {
      saved = readSaved();
      render(false);
    }
  });
})();
