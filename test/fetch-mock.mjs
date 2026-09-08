// Replace global fetch for contract runs, injected with node --import.
//
// The production code gets no switch for this: a way to redirect the server's
// only outbound door would be exactly the hole the door exists to close. The
// substitution happens in the runtime, before the server is loaded, and only
// when the test harness asks for it.

const PROTOKOLL = process.env.FETCH_MOCK_LOG;
const ANTWORTEN = JSON.parse(process.env.FETCH_MOCK_RESPONSES ?? '{}');

function antwort(koerper, status = 200) {
  const text = typeof koerper === 'string' ? koerper : JSON.stringify(koerper);
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    headers: new Headers({ 'content-type': 'application/json' }),
    text: async () => text,
    json: async () => JSON.parse(text),
  };
}

globalThis.fetch = async (url, optionen = {}) => {
  const u = String(url instanceof URL ? url.href : url);
  if (PROTOKOLL) {
    const { appendFileSync } = await import('node:fs');
    appendFileSync(PROTOKOLL, JSON.stringify({
      url: u, method: optionen.method ?? 'GET',
      body: typeof optionen.body === 'string' ? optionen.body.slice(0, 4000) : null,
      redirect: optionen.redirect ?? null,
    }) + '\n');
  }
  if (process.env.FETCH_MOCK_FAIL) {
    throw new Error(process.env.FETCH_MOCK_FAIL);
  }
  for (const [muster, wert] of Object.entries(ANTWORTEN)) {
    if (u.includes(muster)) {
      return antwort(wert.body ?? {}, wert.status ?? 200);
    }
  }
  return antwort({});
};
