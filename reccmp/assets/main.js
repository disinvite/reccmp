import { CanCopy, DiffDisplay, DiffDisplayOptions, ListingOptions, ListingTable, SortIndicator } from './components';
import HidePerfect from './components/hidePerfect';
import HideStub from './components/hideStub';
import SearchBar from './components/searchbar';
import ShowRecomp from './components/showRecomp';
import { ReccmpProvider } from './provider';

// reccmp-pack-begin
window.onload = () => {
  window.customElements.define('reccmp-provider', ReccmpProvider);
  window.customElements.define('listing-table', ListingTable);
  window.customElements.define('listing-options', ListingOptions);
  window.customElements.define('diff-display', DiffDisplay);
  window.customElements.define('diff-display-options', DiffDisplayOptions);
  window.customElements.define('sort-indicator', SortIndicator);
  window.customElements.define('search-bar', SearchBar);
  window.customElements.define('hide-perfect', HidePerfect);
  window.customElements.define('hide-stub', HideStub);
  window.customElements.define('show-recomp', ShowRecomp);
  window.customElements.define('can-copy', CanCopy);
};
