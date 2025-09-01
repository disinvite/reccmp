// reccmp-pack-begin
class HidePerfect extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<label><input type="checkbox" />Hide 100% match</label>`;
    this.querySelector('input[type=checkbox]').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setHidePerfect', { bubbles: true, detail: evt.target.checked }));
    });

    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.update.bind(this) });
    this.dispatchEvent(event);
  }

  update({ hidePerfect }) {
    this.querySelector('input[type=checkbox]').checked = hidePerfect;
  }
};

// reccmp-pack-end
export default HidePerfect;
