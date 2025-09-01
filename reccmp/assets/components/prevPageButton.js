// reccmp-pack-begin
class PrevPageButton extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<button>prev</button>`;
    this.querySelector('button').addEventListener('click', () => {
      this.dispatchEvent(new CustomEvent('prevPage', { bubbles: true }));
    });

    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.update.bind(this) });
    this.dispatchEvent(event);
  }

  update({ pageNumber }) {
    const button = this.querySelector('button');
    if (pageNumber === 0) {
      button.setAttribute('disabled', '');
    } else {
      button.removeAttribute('disabled');
    }
  }
};

// reccmp-pack-end
export default PrevPageButton;
