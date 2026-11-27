// Verifies the JS/TS framework claims in references/language-framework-checklists.md.
// Run from a throwaway dir that has express, react, react-dom installed:
//   mkdir /tmp/jsbox && cd /tmp/jsbox && npm init -y && npm i express react react-dom
//   cp <this file> /tmp/jsbox/ && node verify_js_claims.mjs
// Synthetic marker only; local ephemeral server on 127.0.0.1.
import express from "express";
import React from "react";
import { renderToString } from "react-dom/server";
import { execFileSync } from "node:child_process";

let ok = true;
const check = (label, cond) => { console.log((cond ? "PASS " : "FAIL ") + label); ok &&= !!cond; };
const MARK = "<b id=mark>";

const app = express();
app.get("/raw", (req, res) => res.send(`<p>${req.query.q}</p>`));        // string concatenation into HTML
app.get("/json", (req, res) => res.json({ q: req.query.q }));             // JSON body, JSON content type
const server = app.listen(0, "127.0.0.1", async () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  const raw = await fetch(`${base}/raw?q=${encodeURIComponent(MARK)}`);
  const rawBody = await raw.text();
  check("express res.send(template string) reflects markup unescaped as text/html",
        rawBody.includes(MARK) && raw.headers.get("content-type").startsWith("text/html"));
  const js = await fetch(`${base}/json?q=${encodeURIComponent(MARK)}`);
  check("express res.json answers application/json", js.headers.get("content-type").startsWith("application/json"));

  const el = React.createElement("p", null, MARK);
  check("React JSX text child is escaped by renderToString", !renderToString(el).includes(MARK) && renderToString(el).includes("&lt;b id=mark&gt;"));
  const dang = React.createElement("p", { dangerouslySetInnerHTML: { __html: MARK } });
  check("React dangerouslySetInnerHTML is NOT escaped", renderToString(dang).includes(MARK));

  // exec-with-shell vs execFile: metacharacters are inert without a shell
  const viaArgv = execFileSync("echo", ["a; echo INJECTED"]).toString().trim();
  check("execFile passes metacharacters as one literal argument", viaArgv === "a; echo INJECTED");
  const viaShell = execFileSync("sh", ["-c", "echo a; echo INJECTED"]).toString().trim().split("\n");
  check("shell string runs the second command (why exec(`...${input}`) is flagged)", viaShell[1] === "INJECTED");
  server.close();
  process.exit(ok ? 0 : 1);
});
