import { url as inspectorUrl } from "node:inspector";
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

// An allowlist, because Node's NODE_OPTIONS parser strips quotes and backslashes mid-token, so no denylist of spellings holds.
const ALLOWED_ARGV = new Set(["--disable-sigusr1", "--enable-source-maps", "--no-deprecation", "--disallow-code-generation-from-strings"]);
const MEMORY = "it could expose process memory or the environment";

/**
 * A debugger, a heap/CPU profile or a diagnostic report (which holds the environment, GATEWAY_API_TOKEN among it)
 * would expose keys and secrets, so the gateway refuses to start unless the runtime is known safe.
 */
export function assertSafeRuntime(proc: Pick<NodeJS.Process, "execArgv" | "env" | "report">, openInspectorUrl: () => string | undefined = inspectorUrl): void {
  // NODE_DEBUG: undici's debug log prints request paths, which can hold a query-injected secret. NODE_V8_COVERAGE: coverage files.
  for (const k of ["NODE_OPTIONS", "NODE_DEBUG", "NODE_V8_COVERAGE"]) if (proc.env[k]) throw new Error(`${k} is not allowed for the gateway`);
  // Node treats "_" and "-" alike in flag names.
  const argv = proc.execArgv.map((a) => a.replace(/_/g, "-"));
  if (argv.some((a) => !ALLOWED_ARGV.has(a)))
    throw new Error(`refusing to start with a Node flag outside ${[...ALLOWED_ARGV].join(", ")}: ${MEMORY}`);
  // Without it, SIGUSR1 opens the inspector at runtime.
  if (!argv.includes("--disable-sigusr1")) throw new Error("refusing to start without --disable-sigusr1; run the gateway as: node --disable-sigusr1 dist/server.js");
  // Backstops, whatever got the runtime into this state.
  if (openInspectorUrl() !== undefined) throw new Error(`refusing to start with the inspector open: ${MEMORY}`);
  const r = proc.report;
  if (r && (r.reportOnFatalError || r.reportOnSignal || r.reportOnUncaughtException)) throw new Error(`refusing to start with diagnostic reports on: ${MEMORY}`);
}
