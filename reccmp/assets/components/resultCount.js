// reccmp-pack-begin
class ResultCount extends window.HTMLElement {
  connectedCallback() {
    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.update.bind(this) });
    this.dispatchEvent(event);
  }

  update({ results }) {
    this.textContent = results.length
  }
};

// reccmp-pack-end
export default ResultCount;
