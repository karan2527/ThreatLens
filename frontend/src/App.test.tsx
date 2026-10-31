import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "./App";

vi.mock("./api", () => ({
  apiErrorMessage: () => "The scan could not be completed.",
  createScan: vi.fn(),
  getDashboard: vi.fn(),
  getHistory: vi.fn(),
  getScanResults: vi.fn(),
  getScanStatus: vi.fn(),
}));

describe("App", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    window.location.hash = "";
  });

  it("renders the scanner workspace and supported indicator hint", () => {
    render(<App />);

    expect(screen.getByRole("heading", { name: /see the signal/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/paste a url/i)).toBeInTheDocument();
    expect(screen.getByText(/url\s*\/\s*domain\s*\/\s*ip\s*\/\s*hash/i)).toBeInTheDocument();
  });

  it("shows a validation message before submitting an invalid indicator", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: /^Investigate$/ }));

    expect(screen.getByRole("alert")).toHaveTextContent("Indicator is required");
  });

  it("switches to the about view through the navigation hash", async () => {
    render(<App />);

    fireEvent.click(screen.getByRole("link", { name: /^About$/ }));

    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: /clarity for careful investigation/i }),
      ).toBeInTheDocument(),
    );
  });
});
