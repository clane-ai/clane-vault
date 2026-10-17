import type { IncomingMessage, ServerResponse } from "node:http";

export class HttpError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

export const send = (res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}) => {
  if (body === undefined) { res.writeHead(status, headers).end(); return; }
  res.writeHead(status, { ...headers, "content-type": "application/json" }).end(JSON.stringify(body));
};

export async function readJson(req: IncomingMessage, max: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req as AsyncIterable<Buffer>) {
    size += c.length;
    if (size > max) throw new HttpError(413, "request_too_large");
    chunks.push(c);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new HttpError(400, "invalid_request"); }
}
