import * as global_report from '../../webui/testdata.json';

const global_reccmp_data = global_report.data;

// reccmp-pack-begin

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

// reccmp-pack-end

export {
  global_reccmp_data,
  countDiffs,
  formatAsm,
  getMatchPercentText,
  setBooleanAttribute,
  pageHeadings,
  getDataByAddr,
  copyToClipboard,
};
