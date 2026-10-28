// Smoke test of the page logic with a minimal DOM stub: load the embedded sample, render, press the edit button.
const fs = require("fs"), vm = require("vm");
const html = fs.readFileSync(process.argv[2], "utf8");
const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const els = {};
const el = id => els[id] || (els[id] = { id, innerHTML: "", classList: { add() {}, remove() {} }, addEventListener(ev, fn) { this["on_" + ev] = fn; } });
const ctx = { TextEncoder, crypto: require("crypto").webcrypto, console, Uint8Array, JSON, Object, Array, Set, Number, String, Math, window: {},
  document: { getElementById: el }, alert: m => { throw new Error("alert: " + m); } };
vm.createContext(ctx);
for (const s of scripts) vm.runInContext(s, ctx);
(async () => {
  await els.sample.on_click();
  await new Promise(r => setTimeout(r, 200));
  const first = els.out.innerHTML;
  console.log(/Hash chain intact; all \d+ signatures verify/.test(first) ? "clean render ok" : "UNEXPECTED: " + first.slice(0, 200));
  await els.tamper.onclick();
  const second = els.out.innerHTML;
  console.log(/Hash chain BROKEN at entry \d+/.test(second) ? "tamper render ok" : "UNEXPECTED: " + second.slice(0, 200));
})();
