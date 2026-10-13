import { render, screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { SignInForm } from "./SignIn";

function setup(signIn = vi.fn()) {
  render(<MemoryRouter><SignInForm signIn={signIn} onDone={vi.fn()} onNeedsSetup={vi.fn()} /></MemoryRouter>);
  return signIn;
}
async function enterEmail(email: string) {
  await userEvent.type(screen.getByLabelText("Email address"), email);
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
}

describe("SignInForm", () => {
  it("asks for the email first, then the master password", async () => {
    setup();
    expect(screen.queryByLabelText("Master password")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument();
    await enterEmail("  sara@clane.ai ");
    expect(screen.getByLabelText("Master password")).toHaveFocus();
    expect(screen.getByText("sara@clane.ai")).toBeInTheDocument();
    expect(screen.queryByLabelText("Email address")).not.toBeInTheDocument();
  });

  it("checks the email before moving on", async () => {
    const signIn = setup();
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter your email address.");
    await enterEmail("not-an-email");
    expect(screen.getByRole("alert")).toHaveTextContent("That doesn't look like an email address.");
    expect(screen.queryByLabelText("Master password")).not.toBeInTheDocument();
    expect(signIn).not.toHaveBeenCalled();
  });

  it("Change goes back to the email step with the email kept", async () => {
    setup();
    await enterEmail("sara@clane.ai");
    await userEvent.type(screen.getByLabelText("Master password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: /^Change/ }));
    expect(screen.getByLabelText("Email address")).toHaveValue("sara@clane.ai");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByLabelText("Master password")).toHaveValue("");
  });

  it("asks for the 2FA code after the password is accepted", async () => {
    const signIn = setup(vi.fn().mockResolvedValueOnce({ kind: "error", code: "totp_required" }).mockResolvedValueOnce({ kind: "ok" }));
    await enterEmail("sara@clane.ai");
    await userEvent.type(screen.getByLabelText("Master password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(signIn).toHaveBeenLastCalledWith("sara@clane.ai", "pw", undefined);
    await userEvent.type(await screen.findByLabelText("6-digit code from your authenticator app"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(signIn).toHaveBeenLastCalledWith("sara@clane.ai", "pw", "123456");
  });

  it("shows clear errors", async () => {
    setup(vi.fn().mockResolvedValue({ kind: "error", code: "invalid_credentials" }));
    await enterEmail("a@b.co");
    await userEvent.type(screen.getByLabelText("Master password"), "x");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Email or master password is not right.");
  });

  it("Need help? offers the recovery kit and the authenticator note; no admin option while the policy is off", async () => {
    setup();
    await userEvent.click(screen.getByRole("button", { name: "Need help?" }));
    expect(await screen.findByRole("menuitem", { name: "Forgot master password? Use your recovery kit" })).toBeInTheDocument();
    expect(screen.queryByRole("menuitem", { name: "Ask an admin to reset my password" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Lost authenticator?" }));
    expect(screen.getByRole("note", { name: "Lost authenticator?" })).toHaveTextContent(/admin to reset two-step sign-in/);
    expect(screen.getByRole("note", { name: "Lost authenticator?" })).toHaveTextContent(/recovery kit/);
  });

  it("Forgot master password? opens the kit recovery with the email filled in", async () => {
    render(<MemoryRouter initialEntries={["/sign-in"]}><Routes>
      <Route path="/sign-in" element={<SignInForm signIn={vi.fn()} onDone={vi.fn()} onNeedsSetup={vi.fn()} />} />
      <Route path="/recover" element={<RecoverProbe />} />
    </Routes></MemoryRouter>);
    await enterEmail("sara@clane.ai");
    await userEvent.click(screen.getByRole("button", { name: "Need help?" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Forgot master password? Use your recovery kit" }));
    expect(await screen.findByTestId("recover-probe")).toHaveTextContent("email=sara%40clane.ai");
  });

  it("Ask an admin: shows when the policy is on and answers the same for any email", async () => {
    const asked: unknown[] = [];
    server.use(
      http.get("/api/v1/auth/recovery/options", () => HttpResponse.json({ adminRecoveryEnabled: true })),
      http.post("/api/v1/auth/recovery/admin/request", async ({ request }) => { asked.push(await request.json()); return HttpResponse.json({ ok: true }, { status: 202 }); }),
    );
    setup();
    await enterEmail("sara@clane.ai");
    await userEvent.click(screen.getByRole("button", { name: "Need help?" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Ask an admin to reset my password" }));
    const note = screen.getByRole("note", { name: "Ask an admin to reset my password" });
    expect(within(note).getByLabelText("Email address for the reset request")).toHaveValue("sara@clane.ai");
    await userEvent.click(within(note).getByRole("button", { name: "Ask admin" }));
    expect(await within(note).findByRole("status")).toHaveTextContent(/If that account exists/);
    expect(asked).toEqual([{ email: "sara@clane.ai" }]);
  });
});

function RecoverProbe() {
  const loc = useLocation();
  return <p data-testid="recover-probe">{loc.search}</p>;
}
