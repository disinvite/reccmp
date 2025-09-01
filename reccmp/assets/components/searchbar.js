// reccmp-pack-begin
class SearchBar extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<input type="search"></input>`;
    this.querySelector('input[type=search]').addEventListener('input', (evt) => {
      this.dispatchEvent(new CustomEvent('setQuery', { bubbles: true, detail: evt.target.value }));
    });

    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.update.bind(this) });
    this.dispatchEvent(event);
  }

  update({ query, filterType }) {
    const input = this.querySelector('input[type=search]');
    input.value = query;
    input.placeholder = filterType === 1 ? 'Search for offset or function name...' : 'Search for instruction...';
  }
}
// reccmp-pack-end

export default SearchBar;
