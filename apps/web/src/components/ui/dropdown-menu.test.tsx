import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "./dropdown-menu";

describe("DropdownMenu (Radix API)", () => {
  it("opens from an asChild trigger and calls onSelect", async () => {
    const spy = vi.fn();
    const user = userEvent.setup();
    render(
      <DropdownMenu>
        <DropdownMenuTrigger asChild><button>Open</button></DropdownMenuTrigger>
        <DropdownMenuContent><DropdownMenuItem onSelect={spy}>Copy</DropdownMenuItem></DropdownMenuContent>
      </DropdownMenu>,
    );
    screen.getByRole("button", { name: "Open" }).focus();
    await user.keyboard("{Enter}");
    await user.click(await screen.findByRole("menuitem", { name: "Copy" }));
    expect(spy).toHaveBeenCalledOnce();
  });
});
