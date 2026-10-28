// Runs the checker functions from web/verify.html under node and prints a JSON summary.
// usage: node tests/web_check.js web/verify.html bundle.json
const fs = require("fs");
const vm = require("vm");
const html = fs.readFileSync(process.argv[2], "utf8");
const script = html.split("<script>")[1].split("</script>")[0];
const code = script.split("const drop = document")[0];
const ctx = { TextEncoder, crypto: require("crypto").webcrypto, console, Uint8Array, JSON, Object, Array, Set, Number, String, Math };
vm.createContext(ctx);
vm.runInContext(code + "\nthis.check = check;", ctx);
const bundle = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
ctx.check(bundle).then(r => {
  console.log(JSON.stringify({ problems: r.problems, first: r.first, sig: r.rows.map(x => x.sig), chain: r.rows.map(x => x.chain) }));
});
