import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import * as sessionModule from "@/lib/session";
import { offlineEnabled, setOfflineEnabled } from "@/lib/offline";
import { DeviceSection } from "./DeviceSection";

describe("DeviceSection", () => {
  it("shows the offline copy on by default and turns it off and on through the session", async () => {
    setOfflineEnabled(true);
    const setOfflineCopy = vi.fn();
    vi.spyOn(sessionModule, "useSession").mockReturnValue({ setOfflineCopy } as never);
    render(<DeviceSection />);
    const sw = screen.getByRole("switch", { name: "Offline copy" });
    expect(sw).toBeChecked();
    expect(offlineEnabled()).toBe(true);
    await userEvent.click(sw);
    expect(setOfflineCopy).toHaveBeenLastCalledWith(false);
    expect(sw).not.toBeChecked();
    await userEvent.click(sw);
    expect(setOfflineCopy).toHaveBeenLastCalledWith(true);
  });
});
