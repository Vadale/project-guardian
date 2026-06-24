// Guardian approval UI (desktop). Polls the daemon via the Tauri `pending`
// command and relays allow/deny through `respond`. No business logic here —
// it only renders state and sends the human's decision. Matches the TUI theme.
const { invoke } = window.__TAURI__.core;

const queue = document.getElementById("queue");
const status = document.getElementById("status");

function riskColor(risk) {
  if (risk >= 80) return "var(--red)";
  if (risk >= 40) return "var(--yellow)";
  return "var(--green)";
}

// ASCII risk meter, matching the terminal cockpit.
function riskBar(risk) {
  const filled = Math.min(10, Math.round(risk / 10));
  return "[" + "▓".repeat(filled) + "░".repeat(10 - filled) + "]";
}

async function resolve(id, approve) {
  try {
    await invoke("respond", { id, approve });
  } catch (e) {
    status.textContent = "failed to send decision: " + e;
    status.className = "err";
  }
  refresh();
}

async function refresh() {
  let items;
  try {
    items = await invoke("pending");
  } catch (e) {
    status.textContent = "cannot reach the daemon (" + e + ")";
    status.className = "err";
    return;
  }

  if (items.length === 0) {
    status.textContent = "0 pending";
    status.className = "ok";
  } else {
    status.textContent = items.length + " pending";
    status.className = "";
  }

  queue.innerHTML = "";

  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.innerHTML = "[ all clear ]<small>no actions are waiting for your review</small>";
    queue.appendChild(empty);
    return;
  }

  for (const item of items) {
    const card = document.createElement("div");
    card.className = "card";

    const row = document.createElement("div");
    row.className = "row";
    const tool = document.createElement("span");
    tool.className = "tool";
    tool.textContent = item.tool;
    const risk = document.createElement("span");
    risk.className = "risk";
    risk.style.color = riskColor(item.risk);
    risk.textContent = `risk ${riskBar(item.risk)} ${item.risk}`;
    row.append(tool, risk);

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

    card.append(row, text, actions);
    queue.appendChild(card);
  }
}

setInterval(refresh, 1500);
refresh();
