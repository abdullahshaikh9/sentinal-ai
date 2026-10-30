import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, requestPasswordReset, resetPassword, verifyPasswordResetCode } from "../lib/api";
import { ForgotPasswordPage } from "./AuthPages";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    requestPasswordReset: vi.fn(),
    verifyPasswordResetCode: vi.fn(),
    resetPassword: vi.fn(),
  };
});
describe("ForgotPasswordPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders request reset form and submits email", async () => {
    vi.mocked(requestPasswordReset).mockResolvedValue({
      reset_token: "mock-reset-token-123",
      resend_after_seconds: 60,
      message: "If an account exists with that email, a password reset code has been sent.",
    });

    render(
      <MemoryRouter initialEntries={["/forgot-password"]}>
        <Routes>
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByRole("heading", { name: "Reset your password" })).toBeInTheDocument();
    expect(screen.getByLabelText(/Email/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send reset code" })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: "user@example.com" } });
    fireEvent.submit(screen.getByRole("button", { name: "Send reset code" }).closest("form")!);

    await waitFor(() => {
      expect(requestPasswordReset).toHaveBeenCalledWith("user@example.com");
    });

    expect(await screen.findByRole("heading", { name: "Enter reset code" })).toBeInTheDocument();
    expect(screen.getByText("u***@example.com")).toBeInTheDocument();
  });

  it("handles request reset error gracefully without enumeration leak", async () => {
    vi.mocked(requestPasswordReset).mockRejectedValue(
      new ApiError(429, "Rate limit exceeded. Please try again later."),
    );

    render(
      <MemoryRouter initialEntries={["/forgot-password"]}>
        <Routes>
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        </Routes>
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: "user@example.com" } });
    fireEvent.submit(screen.getByRole("button", { name: "Send reset code" }).closest("form")!);

    expect(await screen.findByRole("alert")).toHaveTextContent("Rate limit exceeded. Please try again later.");
  });

  it("completes the full flow: request -> verify code -> set new password -> success", async () => {
    vi.mocked(requestPasswordReset).mockResolvedValue({
      reset_token: "mock-reset-token-123",
      resend_after_seconds: 60,
      message: "If an account exists with that email, a password reset code has been sent.",
    });

    vi.mocked(verifyPasswordResetCode).mockResolvedValue({
      password_reset_token: "single-use-prt-456",
      message: "Code verified successfully.",
    });

    vi.mocked(resetPassword).mockResolvedValue({
      message: "Password reset successfully. Please log in with your new password.",
    });

    render(
      <MemoryRouter initialEntries={["/forgot-password"]}>
        <Routes>
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        </Routes>
      </MemoryRouter>,
    );

    // Step 1: Request
    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: "user@example.com" } });
    fireEvent.submit(screen.getByRole("button", { name: "Send reset code" }).closest("form")!);

    // Step 2: Verify Code
    expect(await screen.findByRole("heading", { name: "Enter reset code" })).toBeInTheDocument();
    const codeInput = screen.getByLabelText("Verification code");

    // Test rejection of non-6-digit code
    fireEvent.change(codeInput, { target: { value: "123" } });
    fireEvent.submit(screen.getByRole("button", { name: "Verify code" }).closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter the six-digit verification code.");

    // Enter valid 6-digit code
    fireEvent.change(codeInput, { target: { value: "654321" } });
    fireEvent.submit(screen.getByRole("button", { name: "Verify code" }).closest("form")!);

    await waitFor(() => {
      expect(verifyPasswordResetCode).toHaveBeenCalledWith("mock-reset-token-123", "654321");
    });

    // Step 3: Set New Password
    expect(await screen.findByRole("heading", { name: "Set new password" })).toBeInTheDocument();

    const newPass = screen.getByLabelText("New password");
    const confirmPass = screen.getByLabelText("Confirm new password");

    // Test weak password validation
    fireEvent.change(newPass, { target: { value: "short" } });
    fireEvent.change(confirmPass, { target: { value: "short" } });
    fireEvent.submit(screen.getByRole("button", { name: "Reset password" }).closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("Use at least 12 characters with upper, lower, and numeric characters.");

    // Test mismatch
    fireEvent.change(newPass, { target: { value: "StrongPassword123!" } });
    fireEvent.change(confirmPass, { target: { value: "DifferentPassword123!" } });
    fireEvent.submit(screen.getByRole("button", { name: "Reset password" }).closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("Passwords do not match.");

    // Valid password
    fireEvent.change(confirmPass, { target: { value: "StrongPassword123!" } });
    fireEvent.submit(screen.getByRole("button", { name: "Reset password" }).closest("form")!);

    await waitFor(() => {
      expect(resetPassword).toHaveBeenCalledWith("single-use-prt-456", "StrongPassword123!");
    });

    // Step 4: Success
    expect(await screen.findByRole("heading", { name: "Password reset complete" })).toBeInTheDocument();
    expect(screen.getByText(/All previous active sessions were signed out/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in with new password" })).toBeInTheDocument();
  });
});
