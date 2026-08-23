import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

const tokenFile = process.env.VEYRA_E2E_TOKEN_FILE;

test("real local transaction is operable at desktop and narrow viewports", async ({
  page,
}, testInfo) => {
  test.skip(
    tokenFile === undefined,
    "set VEYRA_E2E_TOKEN_FILE to a running local instance token",
  );
  const token = (await readFile(tokenFile!, "utf8")).trim();
  await page.addInitScript(
    ({ apiUrl, localToken }) => {
      localStorage.setItem("veyra.apiUrl", apiUrl);
      localStorage.setItem("veyra.token", localToken);
      localStorage.setItem("veyra.theme", "dark");
    },
    {
      apiUrl: process.env.VEYRA_E2E_API_URL ?? "http://127.0.0.1:7843/v1/",
      localToken: token,
    },
  );

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(
    page.getByRole("heading", {
      name: "Make the next side effect inspectable.",
    }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Create transaction" }).click();
  await expect(
    page.getByRole("button", { name: "Review effects" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review effects" }).click();
  await expect(
    page.getByRole("heading", { name: "Authorize this exact effect" }),
  ).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("approval-desktop.png"),
    fullPage: true,
  });

  await page.setViewportSize({ width: 760, height: 900 });
  await expect(page.getByText("Exact resource scope")).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("approval-narrow.png"),
    fullPage: true,
  });

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole("button", { name: "Grant approval" }).click();
  await expect(
    page.getByRole("button", { name: "Execute transaction" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Execute transaction" }).click();
  await expect(
    page.getByText("Committed", { exact: true }).first(),
  ).toBeVisible();
  await expect(page.getByText("Postconditions satisfied")).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("committed-desktop.png"),
    fullPage: true,
  });

  await page.getByRole("button", { name: "Roll back" }).click();
  await expect(
    page.getByText("Rolled back", { exact: true }).first(),
  ).toBeVisible();
});
