import { CanCopy, DiffDisplay, DiffDisplayOptions, ListingOptions, ListingTable, SortIndicator } from './components';
import { ReccmpProvider } from './provider';

// reccmp-pack-begin
window.onload = () => {
  window.customElements.define('reccmp-provider', ReccmpProvider);
  window.customElements.define('listing-table', ListingTable);
  window.customElements.define('listing-options', ListingOptions);
  window.customElements.define('diff-display', DiffDisplay);
  window.customElements.define('diff-display-options', DiffDisplayOptions);
  window.customElements.define('sort-indicator', SortIndicator);
  window.customElements.define('can-copy', CanCopy);
};
