import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import { ResetAuthenticatorCard } from "./ResetAuthenticator";

const wrap = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>);

describe("Server → Accounts: Reset someone's authenticator", () => {
  it("asks for confirmation, then resets by email address and says what happened", async () => {
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
    await userEvent.click(within(dialog).getByRole("button", { name: "Reset authenticator" }));
    expect(await within(card).findByRole("status")).toHaveTextContent("owner@acme.test is signed out everywhere and will set up a new authenticator at their next sign-in. They were emailed about it.");
    expect(posts).toEqual([{ email: "owner@acme.test" }]);
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
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Reset authenticator" }));
    expect(await within(card).findByRole("alert")).toHaveTextContent("That's your own account. Reset your own authenticator with the reset-2fa command on the server.");
    expect(posts).toBe(1);
  });
});

