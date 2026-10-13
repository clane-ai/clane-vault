import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

/** Opens the sidebar's account menu (bottom left) and returns it. */
export async function openAccountMenu(): Promise<HTMLElement> {
  await userEvent.click(screen.getByRole("button", { name: /^Account menu/ }));
  return screen.findByRole("menu");
}

/** Picks an item (Settings, Sign out, People & groups...) from the account menu. */
export async function chooseFromAccountMenu(name: string): Promise<void> {
  const menu = await openAccountMenu();
  await userEvent.click(within(menu).getByRole("menuitem", { name }));
}
