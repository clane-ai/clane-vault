import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { RegisterForm } from "./Register";

describe("RegisterForm", () => {
  it("requires a long enough master password that matches", async () => {
    const submit = vi.fn();
    render(<RegisterForm email="sara@clane.ai" onSubmit={submit} />);
    await userEvent.type(screen.getByLabelText("Your name"), "Sara");
    await userEvent.type(screen.getByLabelText("Master password"), "short");
    await userEvent.type(screen.getByLabelText("Repeat master password"), "short");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Use at least 12 characters.");
    await userEvent.clear(screen.getByLabelText("Master password"));
    await userEvent.type(screen.getByLabelText("Master password"), "a long master password");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByRole("alert")).toHaveTextContent("The passwords don't match.");
    await userEvent.clear(screen.getByLabelText("Repeat master password"));
    await userEvent.type(screen.getByLabelText("Repeat master password"), "a long master password");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(submit).toHaveBeenCalledWith({ name: "Sara", password: "a long master password" });
  });

  it("explains that nobody can look the master password up, and points to the recovery kit", () => {
    render(<RegisterForm email="sara@clane.ai" onSubmit={vi.fn()} />);
    expect(screen.getByText(/Nobody can look it up for you/i)).toHaveTextContent(/recovery kit/);
    expect(screen.queryByRole("note", { name: "Admin recovery" })).not.toBeInTheDocument();
  });

  it("discloses admin recovery when the organisation has it on", () => {
    render(<RegisterForm email="sara@clane.ai" onSubmit={vi.fn()} adminRecovery />);
    expect(screen.getByRole("note", { name: "Admin recovery" })).toHaveTextContent(/Your organisation's admins can restore your access to it\..*Admins can't open your private items/);
  });
});
