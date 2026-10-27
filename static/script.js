/* =============================================================
   HomeNest - script.js (version 2)
   All frontend logic:
     - rendering property cards, search, filters, sorting, pagination
     - per-user favorites (login-aware)
     - property details with image gallery + owner contact
     - auth pages (password toggle, OTP boxes, resend countdown)
     - property form (photo previews + client-side validation)
   ============================================================= */

/* ---------- Tiny helpers ---------- */

/** Shortcut for document.querySelector. */
const $ = (selector) => document.querySelector(selector);

/** Escape data before inserting it into HTML (prevents XSS). */
function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** 42000 -> "₹42,000" using Indian digit grouping. */
function formatRent(amount) {
  return "₹" + Number(amount).toLocaleString("en-IN");
}

/** Shorten long text for card descriptions. */
function truncate(text, length = 110) {
  const value = String(text || "");
  return value.length > length ? value.slice(0, length).trimEnd() + "..." : value;
}

/**
 * Small wrapper around fetch that:
 *  - adds the CSRF token header to every state-changing request
 *  - always parses the JSON body
 *  - converts HTTP errors (400/404/409/500...) into JavaScript errors
 *    with a friendly message taken from the API response.
 */
async function fetchJSON(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  if (method !== "GET" && window.HOMENEST?.csrfToken) {
    options.headers = {
      ...(options.headers || {}),
      "X-CSRF-Token": window.HOMENEST.csrfToken,
    };
  }

  let response;
  try {
    response = await fetch(url, options);
  } catch (networkError) {
    throw new Error("Cannot reach the server. Is Flask running?");
  }

  let data = {};
  try {
    data = await response.json();
  } catch (parseError) {
    /* empty body - leave data as {} */
  }

  if (!response.ok) {
    const error = new Error(data.error || data.message || `Request failed (HTTP ${response.status}).`);
    error.status = response.status;
    error.details = data.details;
    throw error;
  }
  return data;
}

/** Show a short popup message at the bottom of the screen. */
function showToast(message) {
  const toast = $("#toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove("show"), 2600);
}

/** Send guests to the login page remembering where they wanted to go. */
function redirectToLogin() {
  const next = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.href = `/login?next=${next}`;
}

/* ---------- Favorites state (per user) ---------- */

const favoritesState = { ids: new Set(), properties: [] };

/** Fetch the logged-in user's favorites from the API and cache them. */
async function loadFavorites() {
  const data = await fetchJSON("/api/favorites");
  favoritesState.properties = data.favorites;
  favoritesState.ids = new Set(data.favorites.map((p) => p.id));
  updateFavBadge();
}

/** Update the little number next to "Favorites" in the navbar. */
function updateFavBadge() {
  const badge = $("#favCount");
  if (!badge) return;
  badge.textContent = favoritesState.ids.size;
  badge.classList.toggle("visible", favoritesState.ids.size > 0);
}

/* Heart icons (inline SVG - outline when not saved, filled when saved) */
const HEART_OUTLINE = `
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor"
       stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 0 0 0-7.8z"/>
  </svg>`;

const HEART_FILLED = `
  <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true">
    <path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 0 0 0-7.8z"/>
  </svg>`;

/** Add/remove a property from favorites by calling the REST API. */
async function toggleFavorite(propertyId) {
  const id = Number(propertyId);
  try {
    if (favoritesState.ids.has(id)) {
      await fetchJSON(`/api/favorites/${id}`, { method: "DELETE" });
      favoritesState.ids.delete(id);
      favoritesState.properties = favoritesState.properties.filter((p) => p.id !== id);
      showToast("Removed from favorites");
    } else {
      await fetchJSON("/api/favorites", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ property_id: id }),
      });
      favoritesState.ids.add(id);
      showToast("Saved to favorites");
    }
    updateFavBadge();
    refreshHeartButtons();

    const page = document.body.dataset.page;
    if (page === "favorites") renderFavoritesPage();
    if (page === "details") updateDetailsHeartButton();
  } catch (error) {
    if (error.status === 401) {
      showToast("Please log in to save favorites");
      setTimeout(redirectToLogin, 700);
      return;
    }
    showToast(error.message);
  }
}

/* ---------- Property cards (OLX-style) ---------- */

/** Build the HTML for one property card. */
function propertyCardHTML(property) {
  const title = escapeHTML(property.title);
  const location = [property.locality, property.city].filter(Boolean).join(", ");
  const furnishing = property.furnishing ? escapeHTML(property.furnishing) : "";
  const statusBadge = property.status === "rented"
    ? '<span class="status-badge status-rented">Rented</span>'
    : "";

  return `
    <article class="property-card" data-id="${property.id}">
      <div class="card-media">
        <img src="${escapeHTML(property.image_url)}" alt="Photo of ${title}" loading="lazy"
             onerror="this.onerror=null;this.src='/static/images/placeholder.svg';" />
        <span class="type-badge">${escapeHTML(property.property_type)}</span>
        ${statusBadge}
        <button class="heart-btn" data-id="${property.id}" aria-label="Toggle favorite">
          ${favoritesState.ids.has(property.id) ? HEART_FILLED : HEART_OUTLINE}
        </button>
      </div>
      <div class="card-body">
        <p class="card-rent">${formatRent(property.rent)}<span> / month</span></p>
        <h3 class="card-title">${title}</h3>
        <p class="card-location">&#128205; ${escapeHTML(location)}</p>
        <p class="card-furnishing">${furnishing}${property.area_sqft ? ` &middot; ${property.area_sqft} sq.ft` : ""}</p>
        <p class="card-desc">${escapeHTML(truncate(property.description))}</p>
        <div class="card-meta">
          <span>&#128719; ${property.bedrooms} Bed${property.bedrooms > 1 ? "s" : ""}</span>
          <span>&#128703; ${property.bathrooms} Bath${property.bathrooms > 1 ? "s" : ""}</span>
          <span class="card-owner">by ${escapeHTML(property.owner_name || "HomeNest")}</span>
        </div>
        <button class="card-view-btn" type="button">View details</button>
      </div>
    </article>`;
}

/** Sync every heart button on the page with the favorites state. */
function refreshHeartButtons() {
  document.querySelectorAll(".heart-btn").forEach((btn) => {
    const active = favoritesState.ids.has(Number(btn.dataset.id));
    btn.classList.toggle("active", active);
    btn.innerHTML = active ? HEART_FILLED : HEART_OUTLINE;
  });
}

/**
 * One click listener for a whole card grid (event delegation):
 *  - clicking the heart toggles favorites
 *  - clicking anywhere else opens the details page
 */
function bindGridClick(gridElement) {
  gridElement.addEventListener("click", (event) => {
    const heart = event.target.closest(".heart-btn");
    if (heart) {
      event.stopPropagation();
      toggleFavorite(heart.dataset.id);
      return;
    }
    const card = event.target.closest(".property-card");
    if (card) {
      window.location.href = `/property/${card.dataset.id}`;
    }
  });
}

/** Show the mobile hamburger menu / hide it again. */
function bindNavToggle() {
  const toggle = $("#navToggle");
  const links = $("#navLinks");
  if (toggle && links) {
    toggle.addEventListener("click", () => links.classList.toggle("open"));
  }
}

/** Auto-dismiss flash messages after a few seconds. */
function bindFlashAutoDismiss() {
  document.querySelectorAll(".flash").forEach((flash) => {
    const close = () => flash.remove();
    flash.querySelector(".flash-close")?.addEventListener("click", close);
    setTimeout(close, 6000);
  });
}

/** Ask for confirmation on any form that declares data-confirm. */
function bindConfirmForms() {
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
}

/* =============================================================
   INDEX PAGE - search, filters, sorting and the property grid
   ============================================================= */

const listState = { page: 1, pages: 1 };

/** Fill the datalist (cities) and the type dropdown from the API. */
async function loadFilterOptions() {
  try {
    const [cityData, typeData] = await Promise.all([
      fetchJSON("/api/cities"),
      fetchJSON("/api/property-types"),
    ]);
    $("#citySuggestions").innerHTML = cityData.cities
      .map((c) => `<option value="${escapeHTML(c)}"></option>`)
      .join("");
    $("#typeSelect").innerHTML =
      '<option value="">Any type</option>' +
      typeData.types.map((t) => `<option value="${escapeHTML(t)}">${escapeHTML(t)}</option>`).join("");
  } catch (error) {
    /* Dropdowns still work manually - suggestions are a bonus. */
  }
}

/** Restore search + filters from the URL so filtered links are shareable. */
function readFiltersFromURL() {
  const params = new URLSearchParams(window.location.search);
  $("#cityInput").value = params.get("city") || "";
  $("#minRentInput").value = params.get("min_rent") || "";
  $("#maxRentInput").value = params.get("max_rent") || "";
  $("#bedroomSelect").value = params.get("bedrooms") || "";
  $("#furnishingSelect").value = params.get("furnishing") || "";
  $("#statusSelect").value = params.get("status") || "";
  $("#sortSelect").value = params.get("sort") || "newest";

  const type = params.get("type") || "";
  const hasOption = [...$("#typeSelect").options].some((o) => o.value === type);
  if (hasOption) $("#typeSelect").value = type;
}

/** Build the query string for the API from the current input values. */
function currentFilterParams() {
  const params = new URLSearchParams();
  const city = $("#cityInput").value.trim();
  const minRent = $("#minRentInput").value.trim();
  const maxRent = $("#maxRentInput").value.trim();
  const bedrooms = $("#bedroomSelect").value;
  const type = $("#typeSelect").value;
  const furnishing = $("#furnishingSelect").value;
  const status = $("#statusSelect").value;
  const sort = $("#sortSelect").value;

  if (city) params.set("city", city);
  if (minRent !== "") params.set("min_rent", minRent);
  if (maxRent !== "") params.set("max_rent", maxRent);
  if (bedrooms !== "") params.set("bedrooms", bedrooms);
  if (type) params.set("type", type);
  if (furnishing) params.set("furnishing", furnishing);
  if (status) params.set("status", status);
  if (sort && sort !== "newest") params.set("sort", sort);
  if (listState.page > 1) params.set("page", String(listState.page));
  return params;
}

/** Show exactly one of: loading / empty / error / results. */
function showListState(state) {
  $("#loadingState").classList.toggle("hidden", state !== "loading");
  $("#emptyState").classList.toggle("hidden", state !== "empty");
  $("#errorState").classList.toggle("hidden", state !== "error");
  const showResults = state === "results";
  $("#resultsHeader").classList.toggle("hidden", !showResults);
  $("#propertyGrid").classList.toggle("hidden", !showResults);
  $("#pagination").classList.toggle("hidden", !showResults || listState.pages <= 1);
}

/** Fetch properties from the API using the current filters and render them. */
async function loadProperties(page = 1) {
  listState.page = page;

  // Client-side validation (the API validates again - never trust the client)
  const min = parseFloat($("#minRentInput").value);
  const max = parseFloat($("#maxRentInput").value);
  if (!Number.isNaN(min) && !Number.isNaN(max) && min > max) {
    $("#errorMessage").textContent = "Minimum rent cannot be greater than maximum rent.";
    showListState("error");
    return;
  }

  const params = currentFilterParams();
  history.replaceState(null, "", params.toString() ? `/?${params.toString()}` : "/");

  showListState("loading");
  try {
    const data = await fetchJSON(`/api/properties?${params.toString()}`);
    renderPropertyList(data, params);
  } catch (error) {
    $("#errorMessage").textContent = error.message;
    showListState("error");
  }
}

function renderPropertyList(data, params) {
  listState.pages = data.pages || 1;
  const city = params.get("city");
  $("#resultsHeading").textContent = city ? `Rental homes in "${city}"` : "Browse rental homes";
  const count = data.total;
  $("#resultsCount").textContent =
    `${count} ${count === 1 ? "home" : "homes"} found` +
    (listState.pages > 1 ? ` - page ${data.page} of ${listState.pages}` : "");

  if (count === 0) {
    $("#emptyMessage").textContent = city
      ? `We could not find any homes in "${city}" with the selected filters.`
      : "Try a different city or remove some filters.";
    showListState("empty");
    return;
  }

  $("#propertyGrid").innerHTML = data.properties.map(propertyCardHTML).join("");
  refreshHeartButtons();
  showListState("results");

  $("#pageInfo").textContent = `Page ${data.page} of ${listState.pages}`;
  $("#prevPageBtn").disabled = data.page <= 1;
  $("#nextPageBtn").disabled = data.page >= listState.pages;
}

/** Clear every input and reload all properties. */
function resetFilters() {
  $("#cityInput").value = "";
  $("#minRentInput").value = "";
  $("#maxRentInput").value = "";
  $("#bedroomSelect").value = "";
  $("#typeSelect").value = "";
  $("#furnishingSelect").value = "";
  $("#statusSelect").value = "";
  $("#sortSelect").value = "newest";
  loadProperties(1);
}

async function initIndexPage() {
  bindNavToggle();
  bindFlashAutoDismiss();
  bindGridClick($("#propertyGrid"));

  await loadFilterOptions();   // dropdown options first...
  readFiltersFromURL();        // ...then restore values from the URL

  if (window.HOMENEST?.loggedIn) {
    try {
      await loadFavorites();   // hearts need the favorites list
    } catch (error) {
      /* favorites are optional for browsing */
    }
  }

  $("#heroSearchForm").addEventListener("submit", (e) => {
    e.preventDefault();
    loadProperties(1);
  });

  $("#filterForm").addEventListener("submit", (e) => {
    e.preventDefault();
    loadProperties(1);
  });

  $("#resetFiltersBtn").addEventListener("click", resetFilters);
  $("#emptyResetBtn").addEventListener("click", resetFilters);
  $("#retryBtn").addEventListener("click", () => loadProperties(listState.page));
  $("#prevPageBtn").addEventListener("click", () => loadProperties(listState.page - 1));
  $("#nextPageBtn").addEventListener("click", () => loadProperties(listState.page + 1));

  await loadProperties(1);
}

/* =============================================================
   DETAILS PAGE - gallery, contact, owner actions
   ============================================================= */

function updateDetailsHeartButton() {
  const btn = $("#detailHeartBtn");
  if (!btn || !btn.dataset.id) return;
  const active = favoritesState.ids.has(Number(btn.dataset.id));
  btn.classList.toggle("active", active);
  btn.innerHTML = active
    ? `${HEART_FILLED} Saved to favorites`
    : `${HEART_OUTLINE} Save to favorites`;
}

function renderGallery(gallery) {
  const mainImage = $("#detailImage");
  const thumbs = $("#detailThumbs");
  if (!gallery.length) return;

  mainImage.src = gallery[0];
  if (gallery.length <= 1) {
    thumbs.innerHTML = "";
    return;
  }
  thumbs.innerHTML = gallery
    .map((url, index) => `
      <img src="${escapeHTML(url)}" alt="Photo ${index + 1}" class="${index === 0 ? "active" : ""}"
           onerror="this.onerror=null;this.src='/static/images/placeholder.svg';" />
    `)
    .join("");
  thumbs.querySelectorAll("img").forEach((thumb, index) => {
    thumb.addEventListener("click", () => {
      mainImage.src = gallery[index];
      thumbs.querySelectorAll("img").forEach((t) => t.classList.remove("active"));
      thumb.classList.add("active");
    });
  });
}

function renderPropertyDetails(property) {
  document.title = `${property.title} | HomeNest`;

  $("#detailBadge").textContent = property.property_type;
  $("#detailTitle").textContent = property.title;
  $("#detailCity").textContent = `\uD83D\uDCCD ${[property.locality, property.city].filter(Boolean).join(", ")}`;
  $("#detailBeds").textContent = `${property.bedrooms} Bedroom${property.bedrooms > 1 ? "s" : ""}`;
  $("#detailBaths").textContent = `${property.bathrooms} Bathroom${property.bathrooms > 1 ? "s" : ""}`;
  $("#detailType").textContent = property.property_type;
  $("#detailFurnishing").textContent = property.furnishing || "-";
  if (property.area_sqft) {
    $("#detailArea").textContent = `${property.area_sqft} sq.ft`;
    $("#detailAreaChip").classList.remove("hidden");
  }
  $("#detailDescription").textContent = property.description;
  $("#detailRent").textContent = formatRent(property.rent);
  $("#detailAddress").textContent = property.address;

  // Deposit line
  if (property.deposit && property.deposit > 0) {
    $("#detailDeposit").textContent = `Security deposit: ${formatRent(property.deposit)}`;
    $("#detailDeposit").classList.remove("hidden");
  }

  // Availability line
  if (property.available_from) {
    const availableDate = new Date(property.available_from + "T00:00:00");
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    $("#detailAvailableFrom").textContent = availableDate <= today
      ? "Available now"
      : `Available from ${availableDate.toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}`;
  }

  // Status badge
  if (property.status === "rented") {
    const badge = $("#detailStatus");
    badge.textContent = "Rented out";
    badge.className = "status-badge status-rented";
  }

  // Amenities (server already converted ids to readable labels)
  $("#detailAmenities").innerHTML = (property.amenity_list || [])
    .map((item) => `<li>&#10003; ${escapeHTML(item)}</li>`)
    .join("");

  // Gallery
  renderGallery(property.gallery || [property.image_url]);

  // Owner contact card
  $("#detailOwnerName").textContent = property.owner_name || "HomeNest";
  if (property.created_at) {
    $("#detailMemberSince").textContent =
      `member since ${property.created_at.slice(0, 10)}`;
  }
  $("#detailContactName").textContent = `Contact: ${property.contact?.name || "-"}`;
  const phoneElement = $("#detailContactPhone");
  if (property.contact?.revealed) {
    phoneElement.textContent = `\uD83D\uDCDE ${property.contact.phone}`;
  } else {
    phoneElement.textContent = property.contact?.phone
      ? `\uD83D\uDCDE ${property.contact.phone} (log in to see)`
      : "";
    $("#detailLoginCta")?.classList.remove("hidden");
  }

  // Owner actions
  if (property.viewer?.is_owner) {
    const editLink = $("#detailEditLink");
    editLink.href = `/property/${property.id}/edit`;
    editLink.classList.remove("hidden");
  }

  // Favorite button
  const heartBtn = $("#detailHeartBtn");
  heartBtn.dataset.id = property.id;
  if (property.viewer?.favorited) favoritesState.ids.add(property.id);
  updateDetailsHeartButton();

  $("#detailLoading").classList.add("hidden");
  $("#detailContent").classList.remove("hidden");
}

async function initDetailsPage() {
  bindNavToggle();
  bindFlashAutoDismiss();

  const propertyId = window.DETAIL_PROPERTY_ID
    || Number(window.location.pathname.split("/").pop());
  try {
    if (window.HOMENEST?.loggedIn) {
      try {
        await loadFavorites();
      } catch (favoritesError) {
        /* heart state is optional; the property still renders */
      }
    }
    const data = await fetchJSON(`/api/properties/${propertyId}`);
    renderPropertyDetails(data.property);
  } catch (error) {
    $("#detailLoading").classList.add("hidden");
    $("#detailError").classList.remove("hidden");
    $("#detailErrorMessage").textContent =
      error.status === 404
        ? "This property may have been removed or the link is wrong."
        : error.message;
  }

  $("#detailHeartBtn").addEventListener("click", () => {
    const btn = $("#detailHeartBtn");
    if (btn.dataset.id) toggleFavorite(btn.dataset.id);
  });
}

/* =============================================================
   FAVORITES PAGE
   ============================================================= */

function renderFavoritesPage() {
  $("#favLoading").classList.add("hidden");
  const list = favoritesState.properties;
  const count = list.length;

  $("#favCountText").textContent =
    count > 0 ? `${count} saved ${count === 1 ? "home" : "homes"}` : "";

  $("#favGrid").classList.toggle("hidden", count === 0);
  $("#favEmpty").classList.toggle("hidden", count !== 0);
  $("#favGrid").innerHTML = list.map(propertyCardHTML).join("");
  refreshHeartButtons();
}

async function initFavoritesPage() {
  bindNavToggle();
  bindFlashAutoDismiss();
  bindGridClick($("#favGrid"));

  try {
    await loadFavorites();
    renderFavoritesPage();
  } catch (error) {
    if (error.status === 401) {
      redirectToLogin();
      return;
    }
    $("#favLoading").classList.add("hidden");
    $("#favError").classList.remove("hidden");
    $("#favErrorMessage").textContent = error.message;
  }

  $("#favRetryBtn").addEventListener("click", () => {
    $("#favError").classList.add("hidden");
    $("#favLoading").classList.remove("hidden");
    initFavoritesPage();
  });
}

/* =============================================================
   AUTH PAGES - login, register, OTP
   ============================================================= */

/** Show / hide password fields (both auth forms + reset form). */
function bindPasswordToggles() {
  document.querySelectorAll(".pw-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.target);
      if (!input) return;
      input.type = input.type === "password" ? "text" : "password";
    });
  });
}

/** 6 OTP boxes: auto-advance, backspace-move and paste support. */
function initOtpInputs() {
  const container = $("#otpInputs");
  if (!container) return;
  const boxes = [...container.querySelectorAll(".otp-box")];

  boxes[0]?.focus();

  boxes.forEach((box, index) => {
    box.addEventListener("input", () => {
      box.value = box.value.replace(/\D/g, "").slice(0, 1);
      if (box.value && index < boxes.length - 1) boxes[index + 1].focus();
    });

    box.addEventListener("keydown", (event) => {
      if (event.key === "Backspace" && !box.value && index > 0) {
        boxes[index - 1].focus();
      }
    });

    box.addEventListener("paste", (event) => {
      event.preventDefault();
      const text = (event.clipboardData.getData("text") || "").replace(/\D/g, "");
      if (!text) return;
      for (let i = 0; i < boxes.length; i += 1) {
        boxes[i].value = text[i] || "";
      }
      boxes[Math.min(text.length, boxes.length) - 1].focus();
    });
  });
}

/** Resend button with a cooldown countdown (verification page). */
function initResendButton() {
  const button = $("#resendOtpBtn");
  if (!button) return;
  const timerLabel = $("#resendTimer");
  const messageLabel = $("#resendMessage");
  let cooldown = 0;
  let timer = null;

  const tick = () => {
    cooldown -= 1;
    if (cooldown <= 0) {
      clearInterval(timer);
      timer = null;
      timerLabel?.classList.add("hidden");
      button.disabled = false;
      return;
    }
    if (timerLabel) {
      timerLabel.textContent = `(${cooldown}s)`;
      timerLabel.classList.remove("hidden");
    }
  };

  const startCooldown = (seconds) => {
    if (seconds <= 0) return;
    cooldown = seconds;
    button.disabled = true;
    tick();
    timer = setInterval(tick, 1000);
  };

  button.addEventListener("click", async () => {
    button.disabled = true;
    if (messageLabel) messageLabel.textContent = "Sending a new code...";
    try {
      const data = await fetchJSON(window.OTP_RESEND_URL || "/resend-otp", {
        method: "POST",
      });
      if (messageLabel) {
        messageLabel.textContent = data.message || "A new code has been sent.";
        messageLabel.style.color = "var(--primary)";
      }
      if (data.dev_otp) {
        let devBanner = document.querySelector(".otp-dev-banner");
        if (devBanner) {
          devBanner.innerHTML = `<strong>Development Mode:</strong> Your verification code is <strong style="font-size:1.25rem; letter-spacing:3px; color:#15803d; margin:0 6px;">${data.dev_otp}</strong>
          <div style="margin-top:8px;">
            <button type="button" class="btn btn-outline" style="padding:4px 12px; font-size:0.85rem;" onclick="(function(){
              const code = '${data.dev_otp}';
              for (let i = 1; i <= 6; i++) {
                const el = document.querySelector('input[name=otp_digit' + i + ']');
                if (el) el.value = code[i-1] || '';
              }
            })()">Autofill Code</button>
          </div>`;
        }
      }
      startCooldown(data.retry_after || 60);
    } catch (error) {
      if (messageLabel) {
        messageLabel.textContent = error.message;
        messageLabel.style.color = "#dc2626";
      }
      startCooldown(error.details ? 60 : 10);
    }
  });
}

function initAuthPage() {
  bindNavToggle();
  bindFlashAutoDismiss();
  bindPasswordToggles();
  initOtpInputs();
  initResendButton();
}

/* =============================================================
   PROPERTY FORM - photo previews + client-side validation
   ============================================================= */

function initPropertyForm() {
  bindNavToggle();
  bindFlashAutoDismiss();
  bindConfirmForms();

  const input = $("#photos");
  const previewBox = $("#photoPreviews");
  if (!input || !previewBox) return;

  const MAX_IMAGES = 8;
  const MAX_SIZE_MB = 5;
  const ALLOWED = ["image/jpeg", "image/png", "image/webp"];

  input.addEventListener("change", () => {
    previewBox.innerHTML = "";
    const files = [...input.files];

    for (const file of files) {
      if (!ALLOWED.includes(file.type)) {
        showToast(`"${file.name}" is not a JPG/PNG/WEBP image`);
        input.value = "";
        return;
      }
      if (file.size > MAX_SIZE_MB * 1024 * 1024) {
        showToast(`"${file.name}" is larger than ${MAX_SIZE_MB} MB`);
        input.value = "";
        return;
      }
    }
    if (files.length > MAX_IMAGES) {
      showToast(`You can upload at most ${MAX_IMAGES} photos`);
      input.value = "";
      return;
    }

    files.forEach((file) => {
      const reader = new FileReader();
      reader.onload = (event) => {
        const img = document.createElement("img");
        img.src = event.target.result;
        img.alt = `Preview of ${file.name}`;
        previewBox.appendChild(img);
      };
      reader.readAsDataURL(file);
    });
  });
}

/* =============================================================
   PAGE ROUTER - runs the right initialiser for the current page
   ============================================================= */
document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "index") initIndexPage();
  else if (page === "details") initDetailsPage();
  else if (page === "favorites") initFavoritesPage();
  else if (page === "property-form") initPropertyForm();
  else if (["login", "register", "verify-otp", "forgot-password",
    "reset-password"].includes(page)) initAuthPage();
  else if (page === "my-listings") {
    bindNavToggle();
    bindFlashAutoDismiss();
    bindConfirmForms();
  }
});

