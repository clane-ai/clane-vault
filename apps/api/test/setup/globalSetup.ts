import { execSync } from "node:child_process";
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";

let container: StartedPostgreSqlContainer;

export async function setup() {
  container = await new PostgreSqlContainer("postgres:16-alpine").start();
  // IPv4 loopback, not "localhost": Prisma's engine tries ::1 first, and Docker Desktop's IPv6 port proxy (Windows) can
  // accept a burst of parallel connections without relaying them, so a new pool connection hangs until Prisma's 5 s
  // connect timeout (P1001 "Can't reach database server") and the request using it fails with a 500.
  const u = new URL(container.getConnectionUri());
  if (u.hostname === "localhost") u.hostname = "127.0.0.1";
  const url = u.toString();
  process.env.TEST_DATABASE_URL = url;
  // Backup tests run pg_dump/psql inside this container when the host has no Postgres client tools.
  process.env.TEST_PG_CONTAINER = container.getId();
  execSync("npx prisma migrate deploy", { env: { ...process.env, DATABASE_URL: url }, stdio: "inherit" });
}

export async function teardown() {
  await container?.stop();
}
