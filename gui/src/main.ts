import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

// ------------------------------------------------------------------ types

interface Host {
  id: string;
  name: string;
  hostname: string;
  port: number;
  user: string;
  identity: string | null;
}

interface IdentityInfo {
  path: string;
  name: string;
  fingerprint: string;
}

interface HostTrustedPayload {
  hostId: string;
  label: string;
  fingerprint: string;
}

interface SessionOutputPayload {
  id: string;
  data: string; // base64
}

interface SessionExitPayload {
  id: string;
  message: string;
}

interface SessionEntry {
  id: string;
  hostId: string;
  hostName: string;
  term: Terminal;
  fit: FitAddon;
  tabEl: HTMLElement;
  paneEl: HTMLElement;
  alive: boolean;
}

// ------------------------------------------------------------------ state

let hosts: Host[] = [];
let identities: IdentityInfo[] = [];
const sessions = new Map<string, SessionEntry>();
let activeSessionId: string | null = null;
// The backend starts streaming session-output the instant the pty session
// opens — before connect_host's promise resolves and the entry below exists.
// Anything that arrives that early is buffered here and flushed once the
// entry is registered.
const pendingOutput = new Map<string, Uint8Array[]>();

const hostList = byId("host-list");
const identityList = byId("identity-list");
const tabBar = byId("tab-bar");
const termStack = byId("term-stack");
const emptyState = byId("empty-state");
const overlayRoot = byId("overlay-root");

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}

// -------------------------------------------------------------- bytes/b64

function b64encode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ------------------------------------------------------------------ toast

function toast(message: string, kind: "info" | "error" = "info") {
  const stack =
    document.querySelector<HTMLElement>(".toast-stack") ??
    (() => {
      const s = document.createElement("div");
      s.className = "toast-stack";
      document.body.appendChild(s);
      return s;
    })();
  const el = document.createElement("div");
  el.className = `toast${kind === "error" ? " error" : ""}`;
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

// ------------------------------------------------------------------ modal

function openModal(title: string, body: HTMLElement, actions: HTMLElement[]): () => void {
  const backdrop = document.createElement("div");
  backdrop.className = "overlay-backdrop";
  const modal = document.createElement("div");
  modal.className = "modal";
  const h2 = document.createElement("h2");
  h2.textContent = title;
  const actionsRow = document.createElement("div");
  actionsRow.className = "modal-actions";
  const right = document.createElement("div");
  right.className = "right";
  actions.forEach((a) => right.appendChild(a));
  actionsRow.appendChild(right);

  modal.appendChild(h2);
  modal.appendChild(body);
  modal.appendChild(actionsRow);
  backdrop.appendChild(modal);
  overlayRoot.appendChild(backdrop);

  const close = () => backdrop.remove();
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  return close;
}

function field(labelText: string, input: HTMLInputElement | HTMLSelectElement): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const label = document.createElement("label");
  label.textContent = labelText;
  wrap.appendChild(label);
  wrap.appendChild(input);
  return wrap;
}

// ------------------------------------------------------------- host modal

function openHostModal(existing?: Host) {
  const name = document.createElement("input");
  name.placeholder = "e.g. prod-gateway";
  name.value = existing?.name ?? "";

  const hostname = document.createElement("input");
  hostname.placeholder = "hostname or IP";
  hostname.value = existing?.hostname ?? "";

  const port = document.createElement("input");
  port.type = "number";
  port.value = String(existing?.port ?? 2222);

  const user = document.createElement("input");
  user.placeholder = "login user";
  user.value = existing?.user ?? "";

  const identitySelect = document.createElement("select");
  const defaultOpt = document.createElement("option");
  defaultOpt.value = "";
  defaultOpt.textContent = "Default (~/.shh or ~/.ssh)";
  identitySelect.appendChild(defaultOpt);
  for (const id of identities) {
    const opt = document.createElement("option");
    opt.value = id.path;
    opt.textContent = id.name;
    identitySelect.appendChild(opt);
  }
  identitySelect.value = existing?.identity ?? "";

  const body = document.createElement("div");
  body.appendChild(field("Name", name));
  body.appendChild(field("Hostname", hostname));
  const row = document.createElement("div");
  row.className = "field-row";
  row.appendChild(field("Port", port));
  row.appendChild(field("User", user));
  body.appendChild(row);
  body.appendChild(field("Identity", identitySelect));

  const hint = document.createElement("p");
  hint.className = "empty-hint";
  hint.style.margin = "0 0 10px";
  hint.textContent =
    "A new host's key is trusted on first connect and recorded to ~/.shh/known_hosts, shared with the shh CLI. A key that later changes is always refused.";
  body.appendChild(hint);

  const errorEl = document.createElement("div");
  errorEl.className = "error";
  errorEl.style.display = "none";
  body.appendChild(errorEl);

  const cancelBtn = document.createElement("button");
  cancelBtn.className = "secondary-btn";
  cancelBtn.textContent = "Cancel";

  const saveBtn = document.createElement("button");
  saveBtn.className = "primary-btn";
  saveBtn.textContent = existing ? "Save" : "Add host";

  const actions: HTMLElement[] = [];
  if (existing) {
    const delBtn = document.createElement("button");
    delBtn.className = "danger-btn";
    delBtn.textContent = "Delete";
    delBtn.addEventListener("click", async () => {
      await invoke("delete_host", { id: existing.id });
      hosts = hosts.filter((h) => h.id !== existing.id);
      renderHosts();
      close();
    });
    actions.push(delBtn);
  }
  actions.push(cancelBtn, saveBtn);

  const close = openModal(existing ? "Edit host" : "Add host", body, actions);
  cancelBtn.addEventListener("click", close);

  saveBtn.addEventListener("click", async () => {
    if (!name.value.trim() || !hostname.value.trim() || !user.value.trim()) {
      errorEl.textContent = "Name, hostname, and user are required.";
      errorEl.style.display = "block";
      return;
    }
    const host: Host = {
      id: existing?.id ?? "",
      name: name.value.trim(),
      hostname: hostname.value.trim(),
      port: Number(port.value) || 2222,
      user: user.value.trim(),
      identity: identitySelect.value || null,
    };
    try {
      const saved = await invoke<Host>("save_host", { host });
      const idx = hosts.findIndex((h) => h.id === saved.id);
      if (idx >= 0) hosts[idx] = saved;
      else hosts.push(saved);
      renderHosts();
      close();
    } catch (e) {
      errorEl.textContent = String(e);
      errorEl.style.display = "block";
    }
  });
}

// --------------------------------------------------------- identity modal

function openGenerateIdentityModal() {
  const name = document.createElement("input");
  name.placeholder = "id_ed25519";
  name.value = "id_ed25519";

  const passphrase = document.createElement("input");
  passphrase.type = "password";
  passphrase.placeholder = "leave empty for none";

  const body = document.createElement("div");
  body.appendChild(field("File name (in ~/.shh)", name));
  body.appendChild(field("Passphrase", passphrase));

  const errorEl = document.createElement("div");
  errorEl.className = "error";
  errorEl.style.display = "none";
  body.appendChild(errorEl);

  const cancelBtn = document.createElement("button");
  cancelBtn.className = "secondary-btn";
  cancelBtn.textContent = "Cancel";
  const genBtn = document.createElement("button");
  genBtn.className = "primary-btn";
  genBtn.textContent = "Generate";

  const close = openModal("Generate Ed25519 key", body, [cancelBtn, genBtn]);
  cancelBtn.addEventListener("click", close);
  genBtn.addEventListener("click", async () => {
    try {
      const id = await invoke<IdentityInfo>("generate_identity", {
        name: name.value.trim() || "id_ed25519",
        passphrase: passphrase.value || null,
      });
      identities.push(id);
      renderIdentities();
      toast(`Generated ${id.name}`);
      close();
    } catch (e) {
      errorEl.textContent = String(e);
      errorEl.style.display = "block";
    }
  });
}

// ------------------------------------------------------------- host list

function renderHosts() {
  hostList.innerHTML = "";
  if (hosts.length === 0) {
    const hint = document.createElement("li");
    hint.className = "empty-hint";
    hint.textContent = "No hosts yet — add one to get started.";
    hostList.appendChild(hint);
    return;
  }
  for (const host of hosts) {
    const li = document.createElement("li");
    li.className = "host-row";
    const isConnected = [...sessions.values()].some((s) => s.hostId === host.id && s.alive);
    if (isConnected) li.classList.add("connected");

    const dot = document.createElement("span");
    dot.className = "dot";

    const meta = document.createElement("div");
    meta.className = "meta";
    const nameEl = document.createElement("div");
    nameEl.className = "name";
    nameEl.textContent = host.name;
    const targetEl = document.createElement("div");
    targetEl.className = "target";
    targetEl.textContent = `${host.user}@${host.hostname}:${host.port}`;
    meta.appendChild(nameEl);
    meta.appendChild(targetEl);

    const editBtn = document.createElement("button");
    editBtn.className = "edit-btn";
    editBtn.textContent = "⚙";
    editBtn.title = "Edit host";
    editBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      openHostModal(host);
    });

    li.appendChild(dot);
    li.appendChild(meta);
    li.appendChild(editBtn);
    li.addEventListener("click", () => connectHost(host));
    hostList.appendChild(li);
  }
}

function renderIdentities() {
  identityList.innerHTML = "";
  if (identities.length === 0) {
    const hint = document.createElement("li");
    hint.className = "empty-hint";
    hint.textContent = "No keys found in ~/.shh.";
    identityList.appendChild(hint);
    return;
  }
  for (const id of identities) {
    const li = document.createElement("li");
    li.className = "identity-row";
    const nameEl = document.createElement("div");
    nameEl.className = "name";
    nameEl.textContent = id.name;
    const fpEl = document.createElement("div");
    fpEl.className = "fp";
    fpEl.textContent = id.fingerprint;
    li.appendChild(nameEl);
    li.appendChild(fpEl);
    identityList.appendChild(li);
  }
}

// ---------------------------------------------------------------- terminal

const TERMINAL_THEME = {
  background: "#0e1113",
  foreground: "#e6e8ea",
  cursor: "#3ae28a",
  cursorAccent: "#0e1113",
  selectionBackground: "#2a9d6355",
  black: "#0e1113",
  green: "#3ae28a",
  brightGreen: "#5cf2a5",
};

async function connectHost(host: Host) {
  const term = new Terminal({
    fontFamily: "ui-monospace, SF Mono, Menlo, monospace",
    fontSize: 13,
    theme: TERMINAL_THEME,
    cursorBlink: true,
    scrollback: 5000,
  });
  const fit = new FitAddon();
  term.loadAddon(fit);

  const paneEl = document.createElement("div");
  paneEl.className = "term-pane";
  termStack.appendChild(paneEl);
  term.open(paneEl);

  const tabEl = document.createElement("div");
  tabEl.className = "tab";
  const statusDot = document.createElement("span");
  statusDot.className = "status-dot";
  const label = document.createElement("span");
  label.textContent = host.name;
  const closeBtn = document.createElement("span");
  closeBtn.className = "close";
  closeBtn.textContent = "×";
  tabEl.appendChild(statusDot);
  tabEl.appendChild(label);
  tabEl.appendChild(closeBtn);
  tabBar.appendChild(tabEl);

  const entry: SessionEntry = {
    id: "",
    hostId: host.id,
    hostName: host.name,
    term,
    fit,
    tabEl,
    paneEl,
    alive: true,
  };

  tabEl.addEventListener("click", () => activate(entry.id));
  closeBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    closeSession(entry.id);
  });

  // Make this pane visible (real dimensions) *before* sizing the pty —
  // fit() against a display:none container collapses to 0 cols/rows, and
  // anything xterm writes at 0 cols is silently dropped.
  for (const s of sessions.values()) {
    s.paneEl.classList.remove("active");
    s.tabEl.classList.remove("active");
  }
  paneEl.classList.add("active");
  tabEl.classList.add("active");
  emptyState.classList.remove("visible");
  fit.fit();

  term.writeln(`connecting to ${host.user}@${host.hostname}:${host.port} ...`);

  let sessionId: string;
  try {
    sessionId = await invoke<string>("connect_host", {
      hostId: host.id,
      cols: term.cols,
      rows: term.rows,
    });
  } catch (e) {
    term.writeln(`\r\n\x1b[31mconnection failed: ${String(e)}\x1b[0m`);
    entry.alive = false;
    tabEl.classList.add("dead");
    return;
  }

  entry.id = sessionId;
  sessions.set(sessionId, entry);
  term.clear();
  const buffered = pendingOutput.get(sessionId);
  if (buffered) {
    for (const chunk of buffered) term.write(chunk);
    pendingOutput.delete(sessionId);
  }

  term.onData((data) => {
    invoke("send_input", { sessionId, data: b64encode(new TextEncoder().encode(data)) }).catch(
      () => {},
    );
  });
  term.onResize(({ cols, rows }) => {
    invoke("resize_session", { sessionId, cols, rows }).catch(() => {});
  });

  activate(sessionId);
  renderHosts();
}

function activate(sessionId: string) {
  activeSessionId = sessionId;
  for (const s of sessions.values()) {
    const active = s.id === sessionId;
    s.paneEl.classList.toggle("active", active);
    s.tabEl.classList.toggle("active", active);
    if (active) {
      s.fit.fit();
      s.term.focus();
      invoke("resize_session", { sessionId, cols: s.term.cols, rows: s.term.rows }).catch(
        () => {},
      );
    }
  }
  emptyState.classList.toggle("visible", sessions.size === 0);
}

function closeSession(sessionId: string) {
  const entry = sessions.get(sessionId);
  if (!entry) return;
  invoke("disconnect_session", { sessionId }).catch(() => {});
  entry.term.dispose();
  entry.paneEl.remove();
  entry.tabEl.remove();
  sessions.delete(sessionId);
  if (activeSessionId === sessionId) {
    const next = [...sessions.keys()].pop();
    if (next) activate(next);
    else {
      activeSessionId = null;
      emptyState.classList.add("visible");
    }
  }
  renderHosts();
}

// -------------------------------------------------------------- listeners

async function wireEvents() {
  await listen<SessionOutputPayload>("session-output", (evt) => {
    const entry = sessions.get(evt.payload.id);
    const bytes = b64decode(evt.payload.data);
    if (entry) {
      entry.term.write(bytes);
    } else {
      const buf = pendingOutput.get(evt.payload.id) ?? [];
      buf.push(bytes);
      pendingOutput.set(evt.payload.id, buf);
    }
  });

  await listen<SessionExitPayload>("session-exit", (evt) => {
    const entry = sessions.get(evt.payload.id);
    if (!entry) return;
    entry.alive = false;
    entry.tabEl.classList.add("dead");
    entry.term.writeln(`\r\n\x1b[90m[session closed: ${evt.payload.message}]\x1b[0m`);
    renderHosts();
  });

  await listen<HostTrustedPayload>("host-trusted", (evt) => {
    toast(`Trusted new host key for ${evt.payload.label} (${evt.payload.fingerprint})`);
  });
}

window.addEventListener("resize", () => {
  if (activeSessionId) {
    const entry = sessions.get(activeSessionId);
    entry?.fit.fit();
  }
});

// ------------------------------------------------------------------- boot

async function boot() {
  byId("add-host-btn").addEventListener("click", () => openHostModal());
  byId("empty-add-host-btn").addEventListener("click", () => openHostModal());
  byId("add-identity-btn").addEventListener("click", () => openGenerateIdentityModal());

  try {
    hosts = await invoke<Host[]>("list_hosts");
  } catch (e) {
    toast(`Failed to load hosts: ${String(e)}`, "error");
  }
  try {
    identities = await invoke<IdentityInfo[]>("list_identities");
  } catch (e) {
    toast(`Failed to load identities: ${String(e)}`, "error");
  }
  renderHosts();
  renderIdentities();
  emptyState.classList.add("visible");
  await wireEvents();
}

boot();
