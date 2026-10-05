"use strict";

// Page text is written with textContent (the server's CSP allows only same-origin script and
// style). Every word the screen shows comes from interaction-model.json, so the screen and its
// declared model cannot say different things. Case data is read once from the server.
(() => {
  const byId = (id) => document.getElementById(id);
  const make = (tag, text, cls) => Object.assign(document.createElement(tag), { textContent: text, className: cls || "" });
  const get = async (path) => { const res = await fetch(path); if (!res.ok) throw new Error(path); return res.json(); };
  let model, cases, pending = false, generation = 0;

  function show(screen, ...nodes) {
    document.body.dataset.screen = screen;
    byId("answer").replaceChildren(...nodes);
  }
  const ready = () => show("ready", make("p", model.screens.ready.message, "hint"));
  function refused(code) {
    const verdict = make("p", model.screens.refused.label, "verdict");
    verdict.dataset.outcome = "REFUSED";
    show("refused", verdict, make("p", model.screens.refused.message, "says"), ...(typeof code === "string" ? [make("p", model.reason + code, "cite")] : []));
  }
  function answer(result) {
    const outcome = model.outcomes[result.outcome];
    const verdict = make("p", outcome.word, "verdict");
    verdict.dataset.outcome = result.outcome;
    const nodes = [verdict, make("p", outcome.says, "says")];
    if (result.fixes.length) {
      const list = make("ol", "", "fixes");
      for (const fix of result.fixes) {
        const item = make("li", fix.text);
        if (fix.citation) item.append(make("span", model.citation + fix.citation, "cite"));
        list.append(item);
      }
      nodes.push(make("h2", model.fixes_heading), list);
    }
    show("answer", ...nodes);
  }

  async function check(event) {
    event.preventDefault();
    if (pending) return;
    const mine = ++generation, chosen = cases[byId("case").selectedIndex], button = byId("check");
    pending = true;
    button.setAttribute("aria-disabled", "true");
    let reply = null;
    try {
      const res = await fetch("/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ request: chosen.request, bundle: chosen.bundle }) });
      reply = { ok: res.ok, body: await res.json() };
    } catch (_) { /* transport failure: refused, without a reason */ }
    pending = false;
    button.removeAttribute("aria-disabled");
    if (mine !== generation) return; // another case was picked while this one was checking
    if (reply && reply.ok && model.outcomes[reply.body.outcome]) answer(reply.body);
    else refused(reply && reply.body.error);
  }

  Promise.all([get("/interaction-model.json"), get("/cases")]).then(([loadedModel, loadedCases]) => {
    model = loadedModel;
    cases = loadedCases;
    byId("case").replaceChildren(...cases.map((c) => make("option", c.id.replace(/-/g, " ").replace(/^./, (s) => s.toUpperCase()))));
    byId("case").disabled = byId("check").disabled = false;
    byId("case").addEventListener("change", () => { generation += 1; ready(); });
    byId("form").addEventListener("submit", check);
    ready();
  }, () => { /* the page already says to reload */ });
})();
