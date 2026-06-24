// Guardian approval UI. Polls the daemon (via the Tauri `pending` command) and
// relays the user's allow/deny through `respond`. No policy logic here — the UI
// only renders state and sends the human's decision.
const { invoke } = window.__TAURI__.core;

const queue = document.getElementById("queue");
const status = document.getElementById("status");

// Traffic-light colour for the advisory risk score (display only).
function riskColor(risk) {
  if (risk >= 80) return "#e74c3c"; // red
  if (risk >= 40) return "#f1c40f"; // yellow
  return "#2ecc71"; // green
}

async function resolve(id, approve) {
  try {
    await invoke("respond", { id, approve });
  } catch (e) {
    status.textContent = "Failed to send your decision: " + e;
  }
  refresh();
}

async function refresh() {
  let items;
  try {
    items = await invoke("pending");
  } catch (e) {
    status.textContent = "Cannot reach the Guardian daemon (" + e + "). Is it running?";
    return;
  }

  status.textContent = items.length
    ? `${items.length} action(s) awaiting your review`
    : "No actions awaiting review.";

  queue.innerHTML = "";
  for (const item of items) {
    const card = document.createElement("div");
    card.className = "card";

    const badge = document.createElement("div");
    badge.className = "badge";
    badge.style.background = riskColor(item.risk);
    badge.textContent = "risk " + item.risk;

    const tool = document.createElement("div");
    tool.className = "tool";
    tool.textContent = item.tool;

    const text = document.createElement("div");
    text.className = "text";
    text.textContent = item.plain_text;

    const actions = document.createElement("div");
    actions.className = "actions";
    const deny = document.createElement("button");
    deny.className = "deny";
    deny.textContent = "Deny";
    deny.onclick = () => resolve(item.id, false);
    const allow = document.createElement("button");
    allow.className = "allow";
    allow.textContent = "Allow";
    allow.onclick = () => resolve(item.id, true);
    actions.append(deny, allow);

    card.append(badge, tool, text, actions);
    queue.appendChild(card);
  }
}

setInterval(refresh, 1500);
refresh();
