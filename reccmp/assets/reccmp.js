// reccmp.js
/* global data */

// Unwrap array of functions into a dictionary with address as the key.
const dataDict = Object.fromEntries(global_reccmp_data.map((row) => [row.address, row]));

function getDataByAddr(addr) {
  return dataDict[addr];
}

//
// Pure functions
//

function formatAsm(entries, _addrOption) {
  const output = [];

  const createTh = (text) => {
    const th = document.createElement('th');
    th.innerText = text;
    return th;
  };

  const createTd = (text, className = '') => {
    const td = document.createElement('td');
    td.innerText = text;
    td.className = className;
    return td;
  };

  entries.forEach((obj) => {
    // These won't all be present. You get "both" for an equal node
    // and orig/recomp for a diff.
    const { both = [], orig = [], recomp = [] } = obj;

    output.push(
      ...both.map(([addr, line, recompAddr]) => {
        const tr = document.createElement('tr');
        tr.appendChild(createTh(addr));
        tr.appendChild(createTh(recompAddr));
        tr.appendChild(createTd(line));
        return tr;
      }),
    );

    output.push(
      ...orig.map(([addr, line]) => {
        const tr = document.createElement('tr');
        tr.appendChild(createTh(addr));
        tr.appendChild(createTh(''));
        tr.appendChild(createTd(`-${line}`, 'diffneg'));
        return tr;
      }),
    );

    output.push(
      ...recomp.map(([addr, line]) => {
        const tr = document.createElement('tr');
        tr.appendChild(createTh(''));
        tr.appendChild(createTh(addr));
        tr.appendChild(createTd(`+${line}`, 'diffpos'));
        return tr;
      }),
    );
  });

  return output;
}

function getCppClass(str) {
  const idx = str.indexOf('::');
  if (idx !== -1) {
    return str.slice(0, idx);
  }

  return str;
}

// Clamp string length to specified length and pad with ellipsis
function stringTruncate(str, maxlen = 20) {
  str = getCppClass(str);
  if (str.length > maxlen) {
    return `${str.slice(0, maxlen)}...`;
  }

  return str;
}

function getMatchPercentText(row) {
  if ('stub' in row) {
    return 'stub';
  }

  if ('effective' in row) {
    return '100.00%*';
  }

  return `${(row.matching * 100).toFixed(2)}%`;
}

function countDiffs(row) {
  const { diff = '' } = row;
  if (diff === '') {
    return '';
  }

  const diffs = diff.flatMap(([_slug, subgroups]) => subgroups);
  const diffLength = diffs.filter((d) => !('both' in d)).length;
  const diffWord = diffLength === 1 ? 'diff' : 'diffs';
  return diffLength === 0 ? '' : `${diffLength} ${diffWord}`;
}

// Helper for this set/remove attribute block
function setBooleanAttribute(element, attribute, value) {
  if (value) {
    element.setAttribute(attribute, '');
  } else {
    element.removeAttribute(attribute);
  }
}

function pageHeadings(pages, sortCol) {
  return pages.map((page, index) => {
    const first = page[0];
    const last = page[page.length - 1];

    let start = first[sortCol];
    let end = last[sortCol];

    if (sortCol === 'matching') {
      start = getMatchPercentText(first);
      end = getMatchPercentText(last);
    }

    return [index, stringTruncate(start), stringTruncate(end)];
  });
}

function copyToClipboard(value) {
  navigator.clipboard.writeText(value);
}

/*****************************************************************************/
// state.js

// Special internal values to ensure this sort order for matching column:
// 1. Stub
// 2. Any match percentage [0.0, 1.0)
// 3. Effective match
// 4. Actual 100% match

function getRowSortValue(row) {
  // Stubs appear at the bottom, below even a 0% match.
  if ('stub' in row) {
    return -1;
  }

  // An effective match sorts near the top
  // but under a non-effective match.
  if ('effective' in row) {
    return 1.0;
  }

  // Boost non-effective match so they appear at the top.
  if (row.matching === 1.0) {
    return 1000;
  }

  return row.matching;
}

function createSortFunction({ sortCol, sortDesc }) {
  return (rowA, rowB) => {
    const valA = sortCol === 'matching' ? getRowSortValue(rowA) : rowA[sortCol];
    const valB = sortCol === 'matching' ? getRowSortValue(rowB) : rowB[sortCol];

    if (valA > valB) {
      return sortDesc ? -1 : 1;
    } else if (valA < valB) {
      return sortDesc ? 1 : -1;
    }

    return 0;
  };
}

function createFilterFunction({ hidePerfect, hideStub, query, filterType }) {
  const queryNormalized = query.toLowerCase().trim();

  return (row) => {
    // Destructuring sets defaults for optional values from this object.
    const { effective = false, stub = false, diff = '', name, address, matching } = row;

    if (hidePerfect && (effective || matching >= 1)) {
      return false;
    }

    if (hideStub && stub) {
      return false;
    }

    if (queryNormalized === '') {
      return true;
    }

    // Name/addr search
    if (filterType === 1) {
      return address.includes(queryNormalized) || name.toLowerCase().includes(queryNormalized);
    }

    // no diff for review.
    if (diff === '') {
      return false;
    }

    // special matcher for combined diff
    const anyLineMatch = ([_addr, line]) => line.toLowerCase().trim().includes(queryNormalized);

    // Flatten all diff groups for the search
    const diffs = diff.flatMap(([_slug, subgroups]) => subgroups);
    for (const subgroup of diffs) {
      const { both = [], orig = [], recomp = [] } = subgroup;

      // If search includes context
      if (filterType === 2 && both.some(anyLineMatch)) {
        return true;
      }

      if (orig.some(anyLineMatch) || recomp.some(anyLineMatch)) {
        return true;
      }
    }

    return false;
  };
}

function batched(input, chunkSize) {
  function* gen(arr, n) {
    for (let i = 0; i < arr.length; i += n) {
      yield arr.slice(i, i + n);
    }
  }

  return [...gen(input, Math.max(1, chunkSize))];
}

class ReccmpState {
  constructor(dataset) {
    // Full dataset and filtered list (before paging)
    this.dataset = dataset;
    this.pageSize = 200;
    this.state = {
      // Filtered list of entities
      results: this.dataset,
      pages: [],

      // Sort column and direction
      sortCol: 'address',
      sortDesc: false,

      // Query text and which fields to search.
      query: '',
      filterType: 1,

      // Row filtering
      hidePerfect: false,
      hideStub: false,

      // Column hiding
      showRecomp: false,

      // Rows with detail row (keyed by address)
      expanded: {},

      // Paging
      currentPage: [],
      pageNumber: 0,
      maxPageNumber: 0,
    };

    this.updateResults();
  }

  updateResults() {
    const filterFn = createFilterFunction(this.state);
    const sortFn = createSortFunction(this.state);

    this.state.results = this.dataset.filter(filterFn).sort(sortFn);
    this.state.pages = batched(this.state.results, this.pageSize);
    this.state.maxPageNumber = Math.max(0, this.state.pages.length - 1);
    this.state.pageNumber = Math.min(this.state.pageNumber, this.state.maxPageNumber);

    if (this.state.pages.length > 0) {
      this.state.currentPage = this.state.pages[this.state.pageNumber];
    } else {
      this.state.currentPage = [];
    }
  }

  setPageNumber(page) {
    // Clamp page to what's available
    this.state.pageNumber = Math.max(0, Math.min(page, this.state.maxPageNumber));
    const startIdx = this.state.pageNumber * this.pageSize;
    const endIdx = (this.state.pageNumber + 1) * this.pageSize;
    this.state.currentPage = this.state.results.slice(startIdx, endIdx);
  }

  setFilterType(value) {
    const filterType = parseInt(value); // coerce int
    if (filterType >= 1 && filterType <= 3) {
      this.state.filterType = filterType;
    }

    this.updateResults();
  }

  setQuery(query) {
    this.state.query = query;
    this.updateResults();
  }

  setShowRecomp(value) {
    // Don't sort by the recomp column we are about to hide
    if (!value && this.state.sortCol === 'recomp') {
      this.state.sortCol = 'address';
    }

    this.state.showRecomp = value;
  }

  setSortCol(column) {
    if (column === this.state.sortCol) {
      this.state.sortDesc = !this.state.sortDesc;
    } else {
      this.state.sortCol = column;
    }
    this.state.sortCol = column;
    this.updateResults();
  }

  setHidePerfect(value) {
    this.state.hidePerfect = value;
    this.updateResults();
  }

  setHideStub(value) {
    this.state.hideStub = value;
    this.updateResults();
  }

  toggleExpanded(addr) {
    if (addr in this.state.expanded) {
      delete this.state.expanded[addr];
    } else {
      this.state.expanded[addr] = true;
    }
  }
}

/*****************************************************************************/
// provider.js

class ReccmpProvider extends window.HTMLElement {
  constructor() {
    super();
    this.reccmp = new ReccmpState(global_reccmp_data);
    this.listeners = [];

    this.addEventListener('reccmp-register', (evt) => {
      evt.stopImmediatePropagation();
      this.listeners.push(evt.detail);
      // Call the listener immediately after registering.
      // This populates the component with data.
      evt.detail(this.reccmp.state);
    });

    this.addEventListener('setHidePerfect', (evt) => {
      this.reccmp.setHidePerfect(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setHideStub', (evt) => {
      this.reccmp.setHideStub(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setShowRecomp', (evt) => {
      this.reccmp.setShowRecomp(evt.detail);
      this.callListeners();
    });

    this.addEventListener('prevPage', () => {
      this.reccmp.setPageNumber(this.reccmp.state.pageNumber - 1);
      this.callListeners();
    });

    this.addEventListener('nextPage', () => {
      this.reccmp.setPageNumber(this.reccmp.state.pageNumber + 1);
      this.callListeners();
    });

    this.addEventListener('setPage', (evt) => {
      this.reccmp.setPageNumber(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setQuery', (evt) => {
      this.reccmp.setQuery(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setFilterType', (evt) => {
      this.reccmp.setFilterType(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setSortCol', (evt) => {
      this.reccmp.setSortCol(evt.detail);
      this.callListeners();
    });

    this.addEventListener('toggleExpanded', (evt) => {
      this.reccmp.toggleExpanded(evt.detail);
      this.callListeners();
    });
  }

  callListeners() {
    for (const fn of this.listeners) {
      fn(this.reccmp.state);
    }
  }
}

/*****************************************************************************/

//
// Custom elements
//

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

    const input = this.querySelector('input[type=search]');
    input.addEventListener('input', (evt) => {
      this.dispatchEvent(new CustomEvent('setQuery', { bubbles: true, detail: evt.target.value }));
    });

    this.querySelector('input#cbHidePerfect').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setHidePerfect', { bubbles: true, detail: evt.target.checked }));
    });

    this.querySelector('input#cbHideStub').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setHideStub', { bubbles: true, detail: evt.target.checked }));
    });

    this.querySelector('input#cbShowRecomp').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setShowRecomp', { bubbles: true, detail: evt.target.checked }));
    });

    this.querySelector('button#pagePrev').addEventListener('click', () => {
      this.dispatchEvent(new CustomEvent('prevPage', { bubbles: true }));
    });

    this.querySelector('button#pageNext').addEventListener('click', () => {
      this.dispatchEvent(new CustomEvent('nextPage', { bubbles: true }));
    });

    this.querySelector('select#pageSelect').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setPage', { bubbles: true, detail: evt.target.value }));
    });

    this.querySelectorAll('input[name=filterType]').forEach((radio) => {
      radio.addEventListener('change', () => {
        this.dispatchEvent(new CustomEvent('setFilterType', { bubbles: true, detail: radio.getAttribute('value') }));
      });
    });
  }

  connectedCallback() {
    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.onUpdate.bind(this) });
    this.dispatchEvent(event);
  }

  onUpdate(appState) {
    // Update input placeholder based on search type
    this.querySelector('input[type=search]').placeholder =
      appState.filterType === 1 ? 'Search for offset or function name...' : 'Search for instruction...';

    this.querySelectorAll('input[name=filterType]').forEach((radio) => {
      const checked = appState.filterType === parseInt(radio.getAttribute('value'));
      radio.checked = checked;
    });

    // Update page number and max page
    this.querySelector('fieldset#pageDisplay > legend').textContent =
      `Page ${appState.pageNumber + 1} of ${appState.maxPageNumber + 1}`;

    // Disable prev/next buttons on first/last page
    setBooleanAttribute(this.querySelector('button#pagePrev'), 'disabled', appState.pageNumber === 0);
    setBooleanAttribute(
      this.querySelector('button#pageNext'),
      'disabled',
      appState.pageNumber === appState.maxPageNumber,
    );

    // Update page select dropdown
    const pageSelect = this.querySelector('select#pageSelect');
    setBooleanAttribute(pageSelect, 'disabled', appState.results.length === 0);
    pageSelect.innerHTML = '';

    if (appState.results.length === 0) {
      const opt = document.createElement('option');
      opt.textContent = '- no results -';
      pageSelect.appendChild(opt);
    } else {
      for (const row of pageHeadings(appState.pages, appState.sortCol)) {
        const opt = document.createElement('option');
        opt.value = row[0];
        if (appState.pageNumber === row[0]) {
          opt.setAttribute('selected', '');
        }

        const [start, end] = [row[1], row[2]];

        opt.textContent = `${appState.sortCol}: ${start} to ${end}`;
        pageSelect.appendChild(opt);
      }
    }

    // Update row count
    this.querySelector('#rowcount').textContent = `${appState.results.length}`;
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

  connectedCallback() {
    this.addEventListener('name-click', (evt) => {
      this.dispatchEvent(new CustomEvent('toggleExpanded', { bubbles: true, detail: evt.detail }));
    });

    this.innerHTML = '<table id="listing"><thead></thead><tbody></tbody></table>';

    const event = new CustomEvent('reccmp-register', { bubbles: true, detail: this.somethingChanged.bind(this) });
    this.dispatchEvent(event);
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

window.onload = () => {
  window.customElements.define('reccmp-provider', ReccmpProvider);
  window.customElements.define('listing-table', ListingTable);
  window.customElements.define('listing-options', ListingOptions);
  window.customElements.define('diff-display', DiffDisplay);
  window.customElements.define('diff-display-options', DiffDisplayOptions);
  window.customElements.define('sort-indicator', SortIndicator);
  window.customElements.define('can-copy', CanCopy);
};
