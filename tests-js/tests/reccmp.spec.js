import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test.describe('Table display options', () => {
  test('Hide 100%', async ({ page }) => {
    // TODO: Should use 'cell' role
    const matched = page.getByRole('table').getByText('100.00%');

    // Make sure we have a row with 100% on the current page.
    await expect(matched).not.toHaveCount(0);

    // Check the box to hide 100% rows
    const checkbox = page.getByRole('checkbox', { name: /Hide 100%/ });
    await checkbox.click();
    await expect(checkbox).toBeChecked();

    // Make sure the 100% rows are gone.
    await expect(matched).toHaveCount(0);

    // Uncheck the box.
    await checkbox.click();
    await expect(checkbox).not.toBeChecked();

    // The rows should return.
    await expect(matched).not.toHaveCount(0);
  });

  test('Hide stubs', async ({ page }) => {
    // TODO: Should use 'cell' role
    const stubs = page.getByRole('table').getByText('stub').filter();

    // Make sure we have a stub on the current page.
    await expect(stubs).not.toHaveCount(0);

    // Check the box to hide 100% rows
    const checkbox = page.getByRole('checkbox', { name: /Hide stubs/ });
    await checkbox.click();
    await expect(checkbox).toBeChecked();

    // Make sure the stubs are gone.
    await expect(stubs).toHaveCount(0);

    // Uncheck the box.
    await checkbox.click();
    await expect(checkbox).not.toBeChecked();

    // The rows should return.
    await expect(stubs).not.toHaveCount(0);
  });

  test('Show recomp', async ({ page }) => {
    // TODO: columnheader role?
    const recompHeader = page.getByRole('rowgroup').getByText(/Recomp/);

    // Recomp header is not displayed at the start.
    await expect(recompHeader).not.toBeVisible();

    // Check the box to display the recomp column.
    const checkbox = page.getByRole('checkbox', { name: /Show recomp/ });
    await checkbox.click();
    await expect(checkbox).toBeChecked();

    // Should now see the column header.
    await expect(recompHeader).toBeVisible();

    // Uncheck the box.
    await checkbox.click();
    await expect(checkbox).not.toBeChecked();

    // Recomp header is gone.
    await expect(recompHeader).not.toBeVisible();

    // TODO: not inspecting column data. Should we do that?
  });
});

test.describe('Page flipping', () => {
  test('Type', async ({ page }) => {
    const btnPrev = page.getByRole('button').getByText(/prev/);
    const btnNext = page.getByRole('button').getByText(/next/);

    // Should start on page one.
    await expect(btnPrev).toBeDisabled();
    await expect(btnNext).not.toBeDisabled();
  });
});

test.describe('Search bar text', () => {
  test('Type', async ({ page }) => {
    const rowEntity = page.getByRole('table').getByText(/MxEntity/);
    const rowScore = page.getByRole('table').getByText(/Score/);

    await expect(rowEntity).not.toHaveCount(0);
    await expect(rowScore).not.toHaveCount(0);

    await page.getByRole('searchbox').fill('Score');
    
    await expect(rowEntity).toHaveCount(0);
    await expect(rowScore).not.toHaveCount(0);
  });
});

test.describe('Search bar placeholder', () => {
  test('Option 1', async ({ page }) => {
    await expect(page.getByRole('searchbox')).toHaveValue('');
    // Change and change back
    await expect(page.getByPlaceholder('Search for offset or function name...')).toBeAttached();
    await page.getByRole('radio', { name: 'Asm diffs only' }).click();
    await page.getByRole('radio', { name: 'Name/address' }).click();
    await expect(page.getByPlaceholder('Search for offset or function name...')).toBeAttached();
  })

  test('Option 2', async ({ page }) => {
    await page.getByRole('radio', { name: 'Asm output' }).click();
    await expect(page.getByPlaceholder('Search for instruction...')).toBeAttached();
  })

  test('Option 3', async ({ page }) => {
    await page.getByRole('radio', { name: 'Asm diffs only' }).click();
    await expect(page.getByPlaceholder('Search for instruction...')).toBeAttached();
  })
});
