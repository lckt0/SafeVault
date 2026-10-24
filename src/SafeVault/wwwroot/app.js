"use strict";

// All server data is rendered with textContent, never innerHTML, so stored text cannot execute as markup.
let token = null;

const $ = (id) => document.getElementById(id);
const status = (message) => { $("status").textContent = message; };

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { ...options, headers });
  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    const details = body && body.errors ? Object.values(body.errors).flat().join(" ") : "";
    throw new Error(details || (body && body.detail) || `Request failed (${response.status})`);
  }
  return body;
}

const formData = (form) => Object.fromEntries(new FormData(form).entries());

async function refreshNotes() {
  const notes = await api("/api/notes");
  const list = $("notes");
  list.replaceChildren(...notes.map((note) => {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = note.title;
    const content = document.createElement("p");
    content.textContent = note.content;
    item.append(title, content);
    return item;
  }));
}

$("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/auth/register", { method: "POST", body: JSON.stringify(formData(event.target)) });
    event.target.reset();
    status("Account created. You can sign in now.");
  } catch (error) { status(error.message); }
});

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/api/auth/login", { method: "POST", body: JSON.stringify(formData(event.target)) });
    token = result.accessToken;
    const me = await api("/api/users/me");
    $("whoami").textContent = `${me.username} (${me.role})`;
    $("auth").hidden = true;
    $("vault").hidden = false;
    event.target.reset();
    status("");
    await refreshNotes();
  } catch (error) { status(error.message); }
});

$("note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/notes", { method: "POST", body: JSON.stringify(formData(event.target)) });
    event.target.reset();
    await refreshNotes();
  } catch (error) { status(error.message); }
});

$("logout").addEventListener("click", () => {
  token = null;
  $("notes").replaceChildren();
  $("vault").hidden = true;
  $("auth").hidden = false;
});
