import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
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

test.describe('Search bar', () => {
  test('Search by name', async ({ page }) => {
    const query = 'IsleApp'
    const searchbox = page.getByRole('searchbox')

    // Locators for rows matching and not matching our intended query.
    // TODO: use better locator for table rows/cells
    const notMatchRows = page.locator('func-row').filter({ hasNotText: query });
    const matchRows = page.locator('func-row').filter({ hasText: query });

    // Should have a variety of rows to start.
    await expect(notMatchRows).not.toHaveCount(0);
    await expect(matchRows).not.toHaveCount(0);

    // Fill out the search bar. (Assumes name search enabled by default.)
    await searchbox.fill(query);

    // Non-matching rows are gone.
    await expect(notMatchRows).toHaveCount(0);
    await expect(matchRows).not.toHaveCount(0);

    // Clear the box.
    await searchbox.clear();

    // All rows should return.
    await expect(notMatchRows).not.toHaveCount(0);
    await expect(matchRows).not.toHaveCount(0);
  });

  test('Search by address', async ({ page }) => {
    const searchbox = page.getByRole('searchbox')

    // TODO: use better locator for table rows/cells
    const rows = page.locator('func-row');

    // Make sure we have rows displayed.
    await expect(rows).not.toHaveCount(0);

    // Should match the first row's orig address.
    await searchbox.fill('0x401000');
    
    // Only one row should appear.
    await expect(rows).toHaveCount(1);
  });

  test('Changing filter type re-runs search', async ({ page }) => {
    const searchbox = page.getByRole('searchbox')
    const radio = page.getByRole('radio', { name: 'Asm output' })

    // TODO: use better locator for table rows/cells
    const rows = page.locator('func-row');

    // Make sure we have some rows
    await expect(rows).not.toHaveCount(0);

    // Run a search that we know will not match any names
    await searchbox.fill('mov eax');

    // Should filter out all rows.
    await expect(rows).toHaveCount(0);

    // Search on asm output instead
    await radio.click();

    // We should now have some results.
    await expect(rows).not.toHaveCount(0);
  });

  test('Changing filter type changes placeholder', async ({ page }) => {
    const searchbox = page.getByRole('searchbox')
    const namePlaceholder = page.getByPlaceholder('Search for offset or function name')
    const asmPlaceholder = page.getByPlaceholder('Search for instruction')

    // Should start with name placeholder
    await expect(searchbox.and(namePlaceholder)).toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).not.toBeAttached();

    // Select another filter option
    await page.getByRole('radio', { name: 'Asm diffs only' }).click();

    // Should change placeholder
    await expect(searchbox.and(namePlaceholder)).not.toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).toBeAttached();

    // Change back to name filtering
    await page.getByRole('radio', { name: 'Name/address' }).click();

    // Restore default placeholder
    await expect(searchbox.and(namePlaceholder)).toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).not.toBeAttached();

    // Same behavior for asm diff option
    await page.getByRole('radio', { name: 'Asm diffs only' }).click();
    await expect(searchbox.and(namePlaceholder)).not.toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).toBeAttached();
  });
});
