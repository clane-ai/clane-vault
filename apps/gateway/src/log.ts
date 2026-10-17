import { scrub, variantsOf } from "./outbound/scrub.js";

export { variantsOf };

/** Secret values currently in use in this process; every log line is scrubbed of all of their forms. */
export class HeldSecrets {
  private counts = new Map<string, number>();

  hold(value: string, basicUser?: string): () => void {
    const vs = variantsOf(value, basicUser);
    for (const v of vs) this.counts.set(v, (this.counts.get(v) ?? 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      for (const v of vs) {
        const n = (this.counts.get(v) ?? 1) - 1;
        if (n > 0) this.counts.set(v, n); else this.counts.delete(v);
      }
    };
  }

  redact(text: string): string {
    return this.counts.size ? scrub(text, [...this.counts.keys()]).text : text;
  }
}

export interface Logger { info(f: Record<string, unknown>): void; error(f: Record<string, unknown>): void }

export function createLogger(held: HeldSecrets, write?: (line: string) => void): Logger {
  // Strings are redacted before JSON escaping can change a secret's form; the line is redacted again to cover keys.
  const line = (f: Record<string, unknown>) => held.redact(JSON.stringify(f, (_k, v: unknown) => (typeof v === "string" ? held.redact(v) : v)));
  const out = write ?? ((l: string) => process.stdout.write(l + "\n"));
  const err = write ?? ((l: string) => process.stderr.write(l + "\n"));
  return { info: (f) => out(line(f)), error: (f) => err(line(f)) };
}

const className = (e: unknown) => (e instanceof Error ? e.name : typeof e);

/** Class and redacted message only: a stack can hold values from any frame. */
export function safeError(e: unknown, held: HeldSecrets): { class: string; message: string } {
  return { class: className(e), message: held.redact(e instanceof Error ? e.message : String(e)) };
}

export function installCrashHandlers(proc: Pick<NodeJS.Process, "on">, log: Logger, exit: (code: number) => void): void {
  const crash = (e: unknown) => {
    log.error({ event: "crash", class: className(e) });
    exit(1);
  };
  proc.on("uncaughtException", crash);
  proc.on("unhandledRejection", crash);
}

// Unanchored within NODE_OPTIONS (Node strips quotes there), so any quoting fails closed. "report-" covers the
// --report-on-* flags: diagnostic reports include the environment, GATEWAY_API_TOKEN among it.
const DEBUG_FLAG = /(^|[\s"'])--(inspect|heapsnapshot|heap-prof|cpu-prof|report-)/;

/** A debugger, a heap/CPU profile or a diagnostic report would expose keys and secrets, so the gateway refuses to run with one. */
export function assertNoInspector(execArgv: string[], nodeOptions: string | undefined): void {
  // Node treats "_" and "-" alike in flag names.
  for (const a of [...execArgv, nodeOptions ?? ""]) {
    const m = DEBUG_FLAG.exec(a.replace(/_/g, "-"));
    if (m) throw new Error(`refusing to start with --${m[2]}…: it exposes process memory`);
  }
}
