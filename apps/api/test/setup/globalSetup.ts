import { execSync } from "node:child_process";
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";

let container: StartedPostgreSqlContainer;

export async function setup() {
  container = await new PostgreSqlContainer("postgres:16-alpine").start();
  const url = container.getConnectionUri();
  process.env.TEST_DATABASE_URL = url;
  // Backup tests run pg_dump/psql inside this container when the host has no Postgres client tools.
  process.env.TEST_PG_CONTAINER = container.getId();
  execSync("npx prisma migrate deploy", { env: { ...process.env, DATABASE_URL: url }, stdio: "inherit" });
}

export async function teardown() {
  await container?.stop();
}
