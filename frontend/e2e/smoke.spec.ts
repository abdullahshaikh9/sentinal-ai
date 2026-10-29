import { expect, test, type Page } from "@playwright/test";

const email = process.env.SENTINEL_E2E_EMAIL!;
const password = process.env.SENTINEL_E2E_PASSWORD!;

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("textbox", { name: "Password" }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
}

test("public landing links to the actual login and registration routes", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /See what your security checks actually observed/ })).toBeVisible();
  await page.getByRole("link", { name: "Sign in" }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await page.goto("/");
  await page.getByRole("link", { name: /Create account/ }).first().click();
  await expect(page).toHaveURL(/\/register$/);
});

test("invalid login is rejected with the application error state", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("missing-user@example.test");
  await page.getByRole("textbox", { name: "Password" }).fill("ThisIsNotARealPassword123!");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Invalid email or password");
  await expect(page).toHaveURL(/\/login$/);
});

test("an isolated verified test account reaches persisted dashboard data", async ({ page }) => {
  await signIn(page);
  await expect(page.getByText("No security scans yet")).toBeVisible();
  await expect(page.getByRole("link", { name: /Registered assets/ })).toHaveAttribute("href", "/domains");
});

test("dashboard API failure is visible and retry recovers", async ({ page }) => {
  let attempts = 0;
  await page.route("**/*", async (route) => {
    if (!new URL(route.request().url()).pathname.endsWith("/api/v1/dashboard/overview")) {
      await route.continue();
      return;
    }
    attempts += 1;
    if (attempts <= 2) {
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "Isolated dashboard test failure." }) });
    } else {
      await route.continue();
    }
  });

  await signIn(page);
  expect(attempts).toBe(2);
  await expect(page.getByRole("alert")).toContainText("Isolated dashboard test failure.");
  await expect(page.getByText("No security scans yet")).toHaveCount(0);
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText("No security scans yet")).toBeVisible();
  expect(attempts).toBe(3);
});

test("logout revokes access to protected pages", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
});

test("Assistant explains the unavailable-provider state", async ({ page }) => {
  await signIn(page);
  await page.goto("/assistant");
  await expect(page.getByRole("heading", { name: "Defensive Guidance", exact: true })).toBeVisible();
  await expect(page.getByText(/No AI provider is configured/)).toBeVisible();
  await expect(page.getByText("Select a saved scan to enable local defensive guidance.", { exact: true })).toBeVisible();
});
