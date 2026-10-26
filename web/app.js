const form = document.querySelector("#scan-form");
const pathInput = document.querySelector("#repo-path");
const scanButton = document.querySelector("#scan-button");
const statusEl = document.querySelector("#status");
const resultsEl = document.querySelector("#results");
const findingsEl = document.querySelector("#findings");
const exportButton = document.querySelector("#export-button");
let lastReport = null;
let activeFilter = "all";

function setStatus(message, type = "") {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`.trim();
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}
function renderFindings() {
  if (!lastReport) return;
  const items = lastReport.findings.filter(item => activeFilter === "all" || item.severity === activeFilter);
  findingsEl.innerHTML = items.length ? items.map(item => `
    <article class="finding">
      <div class="finding-top">
        <span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
        <h4>${escapeHtml(item.title)}</h4>
        <span class="category">${escapeHtml(item.category)}</span>
      </div>
      <p>${escapeHtml(item.details)}</p>
      <p class="recommendation">${escapeHtml(item.recommendation)}</p>
      ${item.file ? `<span class="file-ref">${escapeHtml(item.file)}${item.line ? `:${item.line}` : ""}</span>` : ""}
    </article>`).join("") : `<article class="finding"><p>No findings in this filter.</p></article>`;
}
form.addEventListener("submit", async event => {
  event.preventDefault();
  const path = pathInput.value.trim();
  if (!path) return;
  scanButton.disabled = true;
  scanButton.querySelector("span").textContent = "Scanning…";
  resultsEl.classList.add("hidden");
  setStatus("Scanning local files. Large repositories may take a little longer.");
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.hint ? `${data.error}: ${data.hint}` : data.error || "Scan failed");
    lastReport = data;
    activeFilter = "all";
    document.querySelectorAll(".filter").forEach(button => button.classList.toggle("active", button.dataset.filter === "all"));
    document.querySelector("#repo-name").textContent = data.repository;
    document.querySelector("#report-meta").textContent = `${data.checked_files.toLocaleString()} files checked${data.truncated ? " · scan truncated" : ""}`;
    document.querySelector("#score").textContent = data.score;
    document.querySelector("#critical").textContent = data.summary.critical;
    document.querySelector("#warning").textContent = data.summary.warning;
    document.querySelector("#info").textContent = data.summary.info;
    const ring = document.querySelector(".score-ring");
    ring.style.borderColor = data.score >= 80 ? "var(--accent)" : data.score >= 50 ? "var(--yellow)" : "var(--red)";
    document.querySelector("#score-caption").textContent = data.score >= 80 ? "Good baseline — review findings below" : "Address the highest-severity findings first";
    renderFindings();
    resultsEl.classList.remove("hidden");
    setStatus("Scan complete. Findings are local to this session.", "success");
  } catch (error) {
    setStatus(error.message || "Something went wrong. Check that the server is running.", "error");
  } finally {
    scanButton.disabled = false;
    scanButton.querySelector("span").textContent = "Scan repository";
  }
});
document.querySelectorAll(".filter").forEach(button => button.addEventListener("click", () => {
  activeFilter = button.dataset.filter;
  document.querySelectorAll(".filter").forEach(item => item.classList.toggle("active", item === button));
  renderFindings();
}));
exportButton.addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `repo-guardian-${lastReport.repository.replace(/[^a-z0-9_-]/gi, "-")}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
});
