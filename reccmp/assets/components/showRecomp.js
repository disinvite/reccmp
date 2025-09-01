// reccmp-pack-begin
class ShowRecomp extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<label><input type="checkbox" />Show recomp address</label>`;
    this.querySelector('input[type=checkbox]').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setShowRecomp', { bubbles: true, detail: evt.target.checked }));
    });

    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.update.bind(this) });
    this.dispatchEvent(event);
  }

  update({ showRecomp }) {
    this.querySelector('input[type=checkbox]').checked = showRecomp;
  }
};

// reccmp-pack-end
export default ShowRecomp;
