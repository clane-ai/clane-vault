import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import * as sessionModule from "@/lib/session";
import BackupsPage from "./BackupsPage";
import { BackupBanner } from "./BackupBanner";
import { backupAlert, formatBytes, restoreFrom, type BackupRun, type BackupStatus } from "./backups";

const ADMIN = { user: { id: "a1", name: "Admin", role: "admin" } } as never;
const session = vi.spyOn(sessionModule, "useSession").mockReturnValue(ADMIN);
// Backups are instance-level: only instance admins (default org owner / INSTANCE_ADMIN_EMAILS) see them.
let instanceAdmin = true;
beforeEach(() => { instanceAdmin = true; server.use(http.get("/api/v1/me/orgs", () => HttpResponse.json({ orgs: [], invitations: [], allowOrgCreation: true, instanceAdmin }))); });
const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>);

const NOW = Date.now();
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();
const run = (o: Partial<BackupRun>): BackupRun => ({ id: crypto.randomUUID(), startedAt: iso(3600e3), finishedAt: iso(3590e3), status: "success", trigger: "schedule", bytes: 1_572_864,
  destinations: [{ type: "s3", bucket: "vault-bk", prefix: "clane-vault/" }], objectKey: "clane-vault-public-20261006-023000.dump.age", error: null, ...o });
const status = (o: Partial<BackupStatus> = {}): BackupStatus => {
  const runs = o.runs ?? [run({})];
  return { enabled: true, schedule: "30 2 * * *", timezone: "UTC", nextRun: new Date(NOW + 5 * 3600e3).toISOString(), retentionDays: 14, schema: "public",
    destinations: [{ type: "s3", bucket: "vault-bk", prefix: "clane-vault/", endpoint: "abc.r2.cloudflarestorage.com" }, { type: "local", dir: "/backups" }],
    running: false, lastSuccess: runs.find((r) => r.status === "success") ?? null, lastRun: runs[0] ?? null, runs, ...o };
};

describe("Backups page", () => {
  it("shows status, destinations, runs, restore commands and the .env reminder", async () => {
    server.use(http.get("/api/v1/admin/backups", () => HttpResponse.json(status({ runs: [run({ trigger: "manual" }), run({ status: "failed", bytes: null, objectKey: null, error: "pg_dump exited with code 1: permission denied", startedAt: iso(864e5) })] }))));
    wrap(<BackupsPage />);
    const card = await screen.findByRole("region", { name: "Backup status" });
    expect(within(card).getByText("1.5 MB", { exact: false })).toBeInTheDocument();
    expect(within(card).getByText("s3://vault-bk/clane-vault/")).toBeInTheDocument();
    expect(within(card).getByText("/backups")).toBeInTheDocument();
    expect(within(card).getByText("abc.r2.cloudflarestorage.com")).toBeInTheDocument();
    expect(within(card).getByText(/in 5 hours/)).toBeInTheDocument();
    const rows = within(screen.getByRole("region", { name: "Recent backups" })).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]!).getByText("Succeeded")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("Manual")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("Failed")).toBeInTheDocument();
    expect(within(rows[2]!).getByText(/permission denied/)).toBeInTheDocument();
    expect(screen.getByText(/Back up your \.env separately — SERVER_SECRET protects everyone's 2FA/)).toBeInTheDocument();
    const restore = screen.getByRole("region", { name: "Restore" });
    // The key is piped in (the image has no shell or rm to clean up a copied file).
    expect(within(restore).getByText(/exec -T clane-vault node dist\/src\/scripts\/restore\.js --from clane-vault\/clane-vault-public-20261006-023000\.dump\.age --identity - --target-schema public_restored < backup-key\.txt/)).toBeInTheDocument();
    expect(within(restore).queryByText(/\brm\b/)).not.toBeInTheDocument();
    const write = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText: write }, configurable: true });
    await userEvent.click(within(restore).getByRole("button", { name: "Copy step 1" }));
    expect(write).toHaveBeenCalledWith(expect.stringContaining("restore.js --list"));
  });

  it("starts a backup, disables the button while it runs, and says so on 409", async () => {
    let s = status();
    let posts = 0;
    server.use(
      http.get("/api/v1/admin/backups", () => HttpResponse.json(s)),
      http.post("/api/v1/admin/backups/run", () => {
        posts++;
        if (posts > 1) return HttpResponse.json({ error: "backup_running" }, { status: 409 });
        s = status({ running: true, runs: [run({ status: "running", finishedAt: null, bytes: null, objectKey: null, trigger: "manual" }), ...s.runs] });
        return HttpResponse.json({ id: "r1", status: "running" }, { status: 202 });
      }),
    );
    wrap(<BackupsPage />);
    const btn = await screen.findByRole("button", { name: "Back up now" });
    await userEvent.click(btn);
    await waitFor(() => expect(screen.getByRole("button", { name: /Backing up/ })).toBeDisabled());
    expect(posts).toBe(1);
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("explains how to turn backups on when they are off", async () => {
    server.use(http.get("/api/v1/admin/backups", () => HttpResponse.json(status({ enabled: false, nextRun: null, runs: [] }))));
    wrap(<BackupsPage />);
    expect(await screen.findByRole("heading", { name: "Backups are off" })).toBeInTheDocument();
    expect(screen.getByText(/BACKUP_AGE_RECIPIENT=age1/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Back up now" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Restore" })).not.toBeInTheDocument();
  });
});

describe("backup banner", () => {
  it("decides when to warn", () => {
    expect(backupAlert(undefined)).toBeNull();
    expect(backupAlert(status({ enabled: false }))).toEqual({ kind: "off" });
    expect(backupAlert(status())).toBeNull();
    expect(backupAlert(status({ runs: [run({ finishedAt: iso(27 * 3600e3), startedAt: iso(27 * 3600e3) })] }))?.kind).toBe("stale");
    expect(backupAlert(status({ runs: [run({ finishedAt: iso(25 * 3600e3), startedAt: iso(25 * 3600e3) })] }))).toBeNull();
    expect(backupAlert(status({ runs: [run({ status: "failed", error: "boom" }), run({})] }))).toMatchObject({ kind: "failed", error: "boom" });
    expect(backupAlert(status({ runs: [] }))).toBeNull();
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(20 * 1024 * 1024)).toBe("20 MB");
    expect(restoreFrom({ type: "local", dir: "/backups/" }, "x.dump.age")).toBe("/backups/x.dump.age");
  });

  it("warns admins about a failed run and opens the page", async () => {
    server.use(http.get("/api/v1/admin/backups", () => HttpResponse.json(status({ runs: [run({ status: "failed", startedAt: iso(7200e3), finishedAt: iso(7200e3) })] }))));
    const onOpen = vi.fn();
    wrap(<BackupBanner onOpen={onOpen} />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The last database backup failed 2 hours ago.");
    await userEvent.click(within(alert).getByRole("button", { name: "View backups" }));
    expect(onOpen).toHaveBeenCalled();
  });

  it("warns when the last success is older than 26 hours", async () => {
    server.use(http.get("/api/v1/admin/backups", () => HttpResponse.json(status({ runs: [run({ startedAt: iso(3 * 864e5), finishedAt: iso(3 * 864e5) })] }))));
    wrap(<BackupBanner onOpen={() => undefined} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("No successful database backup since 3 days ago.");
  });

  it("shows a dismissable hint when backups are off, and nothing when healthy", async () => {
    server.use(http.get("/api/v1/admin/backups", () => HttpResponse.json(status({ enabled: false, runs: [] }))));
    const { unmount } = wrap(<BackupBanner onOpen={() => undefined} />);
    const hint = await screen.findByRole("status");
    expect(hint).toHaveTextContent("Backups are off.");
    await userEvent.click(within(hint).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    unmount();
    localStorage.clear();
    server.use(http.get("/api/v1/admin/backups", () => HttpResponse.json(status())));
    wrap(<BackupBanner onOpen={() => undefined} />);
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("never asks the browsers of people who aren't instance admins (org admins included) for backup status", async () => {
    session.mockReturnValue({ user: { id: "m1", name: "Mia", role: "admin" } } as never);
    instanceAdmin = false;
    let asked = false;
    server.use(http.get("/api/v1/admin/backups", () => { asked = true; return HttpResponse.json(status({ enabled: false })); }));
    try {
      wrap(<BackupBanner onOpen={() => undefined} />);
      await new Promise((r) => setTimeout(r, 50));
      expect(asked).toBe(false);
      expect(screen.queryByRole("status")).not.toBeInTheDocument();
    } finally { session.mockReturnValue(ADMIN); }
  });
});
