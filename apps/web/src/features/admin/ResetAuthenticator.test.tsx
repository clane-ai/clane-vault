import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import { ResetAuthenticatorCard } from "./ResetAuthenticator";

const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>);

describe("Server → Accounts: Reset someone's authenticator", () => {
  it("asks for confirmation with your own authenticator code, then resets by email address and says what happened", async () => {
    const posts: unknown[] = [];
    let orgHeader: string | null = "unset";
    server.use(http.post("/api/v1/admin/instance/users/reset-2fa", async ({ request }) => {
      posts.push(await request.json()); orgHeader = request.headers.get("x-org-id");
      return HttpResponse.json({ ok: true, email: "owner@acme.test", emailed: true });
    }));
    wrap(<ResetAuthenticatorCard />);
    const card = screen.getByRole("region", { name: "Reset someone's authenticator" });
    await userEvent.type(within(card).getByLabelText("Their email address"), "Owner@Acme.test");
    await userEvent.click(within(card).getByRole("button", { name: "Reset authenticator" }));
    // Nothing happens before the confirmation.
    const dialog = await screen.findByRole("dialog", { name: "Reset the authenticator of owner@acme.test?" });
    expect(posts).toEqual([]);
    // The code comes first: the button waits for 6 digits.
    expect(within(dialog).getByRole("button", { name: "Reset authenticator" })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Your authenticator code"), "12a3456");
    await userEvent.click(within(dialog).getByRole("button", { name: "Reset authenticator" }));
    expect(await within(card).findByRole("status")).toHaveTextContent("owner@acme.test is signed out everywhere and will set up a new authenticator at their next sign-in. They were emailed about it.");
    expect(posts).toEqual([{ email: "owner@acme.test", code: "123456" }]);
    expect(orgHeader).toBeNull();
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(within(card).getByLabelText("Their email address")).toHaveValue("");
  });

  it("explains refusals, including your own account, and a cancelled confirmation sends nothing", async () => {
    let posts = 0;
    server.use(http.post("/api/v1/admin/instance/users/reset-2fa", () => { posts++; return HttpResponse.json({ error: "self" }, { status: 400 }); }));
    wrap(<ResetAuthenticatorCard />);
    const card = screen.getByRole("region", { name: "Reset someone's authenticator" });
    await userEvent.type(within(card).getByLabelText("Their email address"), "me@server.test");
    await userEvent.click(within(card).getByRole("button", { name: "Reset authenticator" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(posts).toBe(0);
    await userEvent.click(within(card).getByRole("button", { name: "Reset authenticator" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Your authenticator code"), "654321");
    await userEvent.click(within(dialog).getByRole("button", { name: "Reset authenticator" }));
    expect(await within(card).findByRole("alert")).toHaveTextContent("That's your own account. Reset your own authenticator with the reset-2fa command on the server.");
    expect(posts).toBe(1);
  });

  it("keeps the confirmation open with the error when your own code is wrong or your account is locked", async () => {
    const codes: string[] = [];
    server.use(
      // A 401 makes the client refresh its session once and try again, as for every request.
      http.post("/api/v1/auth/refresh", () => HttpResponse.json({ accessToken: "fresh" })),
      http.post("/api/v1/admin/instance/users/reset-2fa", async ({ request }) => {
        const { code } = await request.json() as { code: string };
        codes.push(code);
        return code === "000000" ? HttpResponse.json({ error: "totp_invalid" }, { status: 401 }) : HttpResponse.json({ error: "locked", retryAfterSeconds: 900 }, { status: 423 });
      }),
    );
    wrap(<ResetAuthenticatorCard />);
    const card = screen.getByRole("region", { name: "Reset someone's authenticator" });
    await userEvent.type(within(card).getByLabelText("Their email address"), "owner@acme.test");
    await userEvent.click(within(card).getByRole("button", { name: "Reset authenticator" }));
    const dialog = await screen.findByRole("dialog");
    const code = within(dialog).getByLabelText("Your authenticator code");
    await userEvent.type(code, "000000");
    await userEvent.click(within(dialog).getByRole("button", { name: "Reset authenticator" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("That code didn't work. Wait for the next code from your authenticator and try again.");
    expect(code).toHaveValue("");
    await userEvent.type(code, "111111");
    await userEvent.click(within(dialog).getByRole("button", { name: "Reset authenticator" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Too many failed attempts. Your account is locked for 15 minutes.");
    expect(within(card).queryByRole("status")).not.toBeInTheDocument();
    expect(new Set(codes)).toEqual(new Set(["000000", "111111"]));
  });
});

