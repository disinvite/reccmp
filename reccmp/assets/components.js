import {
  copyToClipboard,
  countDiffs,
  formatAsm,
  getDataByAddr,
  getMatchPercentText,
  setBooleanAttribute,
} from './globals';

// reccmp-pack-begin

// Sets sort indicator arrow based on element attributes.
class SortIndicator extends window.HTMLElement {
  static observedAttributes = ['data-sort'];

  attributeChangedCallback(_name, _oldValue, newValue) {
    if (newValue === null) {
      // Reserve space for blank indicator so column width stays the same
      this.innerHTML = '&nbsp;';
    } else {
      this.innerHTML = newValue === 'asc' ? '&#9650;' : '&#9660;';
    }
  }
}

class CanCopy extends window.HTMLElement {
  connectedCallback() {
    this.addEventListener('mouseout', () => {
      this.copied = false;
    });

    this.addEventListener('click', (evt) => {
      copyToClipboard(evt.target.textContent);
      this.copied = true;
    });
  }

  get copied() {
    return this.getAttribute('copied');
  }

  set copied(value) {
    if (value) {
      setTimeout(() => {
        this.copied = false;
      }, 2000);
    }
    setBooleanAttribute(this, 'copied', value);
  }
}

class DiffDisplayOptions extends window.HTMLElement {
  static observedAttributes = ['data-option'];

  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const shadow = this.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        fieldset {
          align-items: center;
          display: flex;
          margin-bottom: 20px;
        }

        label {
          margin-right: 10px;
          user-select: none;
        }

        label, input {
          cursor: pointer;
        }
      </style>
      <fieldset>
        <legend>Address display:</legend>
        <input type="radio" id="showNone" name="addrDisplay" value=0>
        <label for="showNone">None</label>
        <input type="radio" id="showOrig" name="addrDisplay" value=1>
        <label for="showOrig">Original</label>
        <input type="radio" id="showBoth" name="addrDisplay" value=2>
        <label for="showBoth">Both</label>
      </fieldset>`;

    shadow.querySelectorAll('input[type=radio]').forEach((radio) => {
      const checked = this.option === radio.getAttribute('value');
      setBooleanAttribute(radio, 'checked', checked);

      radio.addEventListener('change', (evt) => {
        this.option = evt.target.value;
      });
    });
  }

  set option(value) {
    this.setAttribute('data-option', parseInt(value));
  }

  get option() {
    return this.getAttribute('data-option') ?? 1;
  }

  attributeChangedCallback(name, _oldValue, _newValue) {
    if (name !== 'data-option') {
      return;
    }

    this.dispatchEvent(new Event('change'));
  }
}

class DiffDisplay extends window.HTMLElement {
  static observedAttributes = ['data-option'];

  connectedCallback() {
    if (this.querySelector('diff-display-options') !== null) {
      return;
    }

    const optControl = new DiffDisplayOptions();
    optControl.option = this.option;
    optControl.addEventListener('change', (evt) => {
      this.option = evt.target.option;
    });
    this.appendChild(optControl);

    const div = document.createElement('div');
    const obj = getDataByAddr(this.address);

    const createHeaderLine = (text, className) => {
      const div = document.createElement('div');
      div.textContent = text;
      div.className = className;
      return div;
    };

    const groups = obj.diff;
    groups.forEach(([slug, subgroups]) => {
      const secondTable = document.createElement('table');
      secondTable.classList.add('diffTable');

      const hdr = document.createElement('div');
      hdr.appendChild(createHeaderLine('---', 'diffneg'));
      hdr.appendChild(createHeaderLine('+++', 'diffpos'));
      hdr.appendChild(createHeaderLine(slug, 'diffslug'));
      div.appendChild(hdr);

      const tbody = document.createElement('tbody');
      secondTable.appendChild(tbody);

      const diffs = formatAsm(subgroups, this.option);
      for (const el of diffs) {
        tbody.appendChild(el);
      }

      div.appendChild(secondTable);
    });

    this.appendChild(div);
  }

  get address() {
    return this.getAttribute('data-address');
  }

  set address(value) {
    this.setAttribute('data-address', value);
  }

  get option() {
    return this.getAttribute('data-option') ?? 1;
  }

  set option(value) {
    this.setAttribute('data-option', value);
  }
}

class ListingOptions extends window.HTMLElement {
  constructor() {
    super();

    this.querySelector('button#pagePrev').addEventListener('click', () => {
      this.dispatchEvent(new CustomEvent('prevPage', { bubbles: true }));
    });

    this.querySelector('button#pageNext').addEventListener('click', () => {
      this.dispatchEvent(new CustomEvent('nextPage', { bubbles: true }));
    });
  }

  connectedCallback() {
    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.onUpdate.bind(this) });
    this.dispatchEvent(event);
  }

  onUpdate(appState) {
    // Disable prev/next buttons on first/last page
    setBooleanAttribute(this.querySelector('button#pagePrev'), 'disabled', appState.pageNumber === 0);
    setBooleanAttribute(
      this.querySelector('button#pageNext'),
      'disabled',
      appState.pageNumber === appState.maxPageNumber,
    );
  }
}

// Main application.
class ListingTable extends window.HTMLElement {
  diffRow(obj, showRecomp) {
    let contents;

    if ('stub' in obj) {
      contents = document.createElement('div');
      contents.setAttribute('class', 'no-diff');
      contents.textContent = 'Stub. No diff.';
    } else if (obj.diff.length === 0) {
      contents = document.createElement('div');
      contents.setAttribute('class', 'no-diff');
      contents.textContent = 'Identical function - no diff';
    } else {
      contents = document.createElement('diff-display');
      contents.setAttribute('data-option', '1');
      contents.setAttribute('data-address', obj.address);
    }

    const td = document.createElement('td');
    td.setAttribute('colspan', showRecomp ? 5 : 4);
    td.append(contents);

    const tr = document.createElement('tr');
    tr.setAttribute('data-diff', obj.address);
    tr.append(td);
    return tr;
  }

  funcRow(obj, showRecomp) {
    const createColumn = (dataCol, canCopy, textContent) => {
      const td = document.createElement('td');
      td.setAttribute('data-col', dataCol);
      if (canCopy) {
        const copy = document.createElement('can-copy');
        copy.textContent = textContent;
        td.append(copy);
      } else {
        td.append(textContent);
      }

      return td;
    };

    const cols = {
      address: createColumn('address', true, obj.address),
      recomp: createColumn('recomp', true, obj.recomp),
      name: createColumn('name', false, obj.name),
      diffs: createColumn('diffs', false, countDiffs(obj)),
      matching: createColumn('matching', false, getMatchPercentText(obj)),
    };

    if (!showRecomp) {
      delete cols.recomp;
    }

    const tr = document.createElement('tr');
    tr.setAttribute('data-address', obj.address);
    tr.append(...Object.values(cols));
    return tr;
  }

  headerRow(showRecomp, sortCol, sortDesc) {
    const cols = {
      address: 'Address',
      recomp: 'Recomp',
      name: 'Name',
      diffs: '',
      matching: 'Matching',
    };

    if (!showRecomp) {
      delete cols.recomp;
    }

    const headers = Object.entries(cols).map(([key, name]) => {
      if (key === 'diffs') {
        const th = document.createElement('th');
        th.setAttribute('data-col', 'diffs');
        th.setAttribute('data-no-sort', true);
        return th;
      }

      const sort_indicator = document.createElement('sort-indicator');
      if (key === sortCol) {
        sort_indicator.setAttribute('data-sort', sortDesc ? 'desc' : 'asc');
      }

      const th = document.createElement('th');
      th.setAttribute('data-col', key);
      const div = document.createElement('div');
      const span = document.createElement('span');
      span.textContent = name;
      div.append(span, sort_indicator);
      th.append(div);
      return th;
    });

    const tr = document.createElement('tr');
    tr.append(...headers);
    return tr;
  }

  setDiffRow(appState) {
    const tbody = this.querySelector('tbody');

    for (const obj of appState.currentPage) {
      const address = obj.address;
      const funcrow = tbody.querySelector(`tr[data-address="${address}"]`);
      if (funcrow === null) {
        continue;
      }

      const existing = tbody.querySelector(`tr[data-diff="${address}"]`);
      const isExpanded = existing !== null;
      const shouldExpand = address in appState.expanded;

      if (!isExpanded && shouldExpand) {
        // Insert the diff row after the parent func row.
        funcrow.insertAdjacentElement('afterend', this.diffRow(obj, appState.showRecomp));
      } else if (isExpanded && !shouldExpand) {
        tbody.removeChild(existing);
      }
    }
  }

  connectedCallback() {
    this.addEventListener('name-click', (evt) => {
      this.dispatchEvent(new CustomEvent('toggleExpanded', { bubbles: true, detail: evt.detail }));
    });

    this.innerHTML = '<table id="listing"><thead></thead><tbody></tbody></table>';

    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.somethingChanged.bind(this) });
    this.dispatchEvent(event);
    this.dispatchEvent(new CustomEvent('reccmp-table', { bubbles: true, detail: this.setDiffRow.bind(this) }));
  }

  somethingChanged(appState) {
    const header_row = this.headerRow(appState.showRecomp, appState.sortCol, appState.sortDesc);

    const rows = [];

    // Create rows for this page.
    for (const obj of appState.currentPage) {
      rows.push(this.funcRow(obj, appState.showRecomp));
      if (obj.address in appState.expanded) {
        rows.push(this.diffRow(obj, appState.showRecomp));
      }
    }

    this.querySelector('thead').replaceChildren(header_row);
    this.querySelector('tbody').replaceChildren(...rows);

    this.querySelectorAll('th:not([data-no-sort])').forEach((th) => {
      const col = th.getAttribute('data-col');
      if (col) {
        const span = th.querySelector('span');
        if (span) {
          span.addEventListener('click', () => {
            this.dispatchEvent(new CustomEvent('setSortCol', { bubbles: true, detail: col }));
          });
        }
      }
    });

    this.querySelectorAll('tr[data-address]').forEach((row) => {
      // Clicking the name column toggles the diff detail row.
      // This is added or removed without replacing the entire <tbody>.
      row.querySelector('td[data-col="name"]').addEventListener('click', () => {
        this.dispatchEvent(new CustomEvent('name-click', { detail: row.getAttribute('data-address') }));
      });
    });
  }
}

// reccmp-pack-end

export { CanCopy, DiffDisplay, DiffDisplayOptions, ListingOptions, ListingTable, SortIndicator };
