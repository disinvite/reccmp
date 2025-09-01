// reccmp-pack-begin
class PageNumberOf extends window.HTMLElement {
  connectedCallback() {
    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.update.bind(this) });
    this.dispatchEvent(event);
  }

  update({ pageNumber, maxPageNumber }) {
    this.textContent = `Page ${pageNumber + 1} of ${maxPageNumber + 1}`
  }
};

// reccmp-pack-end
export default PageNumberOf;
