import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Search bar', () => {
  test('Search by name', async ({ page }) => {
    const query = 'IsleApp';
    const searchbox = page.getByRole('searchbox');

    // Locators for rows matching and not matching our intended query.
    // TODO: use better locator for table rows/cells
    const notMatchRows = page.locator('tr[data-address]').filter({ hasNotText: query });
    const matchRows = page.locator('tr[data-address]').filter({ hasText: query });

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
    const searchbox = page.getByRole('searchbox');

    // TODO: use better locator for table rows/cells
    const rows = page.locator('tr[data-address]');

    // Make sure we have rows displayed.
    await expect(rows).not.toHaveCount(0);

    // Should match the first row's orig address.
    await searchbox.fill('0x401000');

    // Only one row should appear.
    await expect(rows).toHaveCount(1);
  });

  test('Changing filter type re-runs search', async ({ page }) => {
    const searchbox = page.getByRole('searchbox');
    const radio = page.getByRole('radio', { name: 'Asm output' });

    // TODO: use better locator for table rows/cells
    const rows = page.locator('tr[data-address]');

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
    const searchbox = page.getByRole('searchbox');
    const namePlaceholder = page.getByPlaceholder('Search for offset or function name');
    const asmPlaceholder = page.getByPlaceholder('Search for instruction');

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

  test('Should trim whitespace', async ({ page }) => {
    const searchbox = page.getByRole('searchbox');
    const rowLocator = page.getByRole('row').filter({ hasText: 'IsleApp::IsleApp' });

    // The row should be visible to start.
    await expect(rowLocator).toBeAttached();

    // The row should be there if we start typing text that matches its name.
    await searchbox.fill('Isle');
    await expect(rowLocator).toBeAttached();

    // The row should still be there even if we add leading or trailing spaces
    // (i.e. the whitespace is trimmed)
    await searchbox.fill('Isle   ');
    await expect(rowLocator).toBeAttached();

    await searchbox.fill('   Isle');
    await expect(rowLocator).toBeAttached();

    await searchbox.fill('   Isle   ');
    await expect(rowLocator).toBeAttached();

    // The row should not be there if the space is enclosed in non-space characters.
    // i.e. we do not remove *all* spaces
    await searchbox.fill('Isle App');
    await expect(rowLocator).not.toBeAttached();
  });

  test('Should match if space included', async ({ page }) => {
    const searchbox = page.getByRole('searchbox');
    // Example row that contains a space in its name.
    const rowLocator = page.getByRole('row').filter({ hasText: 'list<ROI *,allocator<ROI *> >::_Buynode' });

    // The row should be visible to start.
    await expect(rowLocator).toBeAttached();

    // The row should be there if we type part of the name.
    await searchbox.fill('ROI');
    await expect(rowLocator).toBeAttached();

    // The row should not disappear when we add the space.
    await searchbox.fill('ROI ');
    await expect(rowLocator).toBeAttached();

    // The row should still be there after the space is included.
    await searchbox.fill('ROI *');
    await expect(rowLocator).toBeAttached();

    // However... we do not remove spaces from the *row* when searching.
    // This should not match.
    await searchbox.fill('ROI*');
    await expect(rowLocator).not.toBeAttached();
  });

  test('Should run case-insensitive search', async ({ page }) => {
    const searchbox = page.getByRole('searchbox');
    const rowLocator = page.getByRole('row').filter({ hasText: 'IsleApp::IsleApp' });

    // The row should appear regardless of case used in the search string.
    await searchbox.fill('IsleApp');
    await expect(rowLocator).toBeAttached();

    await searchbox.fill('isleapp');
    await expect(rowLocator).toBeAttached();

    await searchbox.fill('ISLEAPP');
    await expect(rowLocator).toBeAttached();
  });
});
