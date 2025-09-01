// reccmp-pack-begin
const global_reccmp_data = window.global_reccmp_report.data;

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

// Helper for this set/remove attribute block
function setBooleanAttribute(element, attribute, value) {
  if (value) {
    element.setAttribute(attribute, '');
  } else {
    element.removeAttribute(attribute);
  }
}

// reccmp-pack-end

export { global_reccmp_data, formatAsm, setBooleanAttribute, getDataByAddr };
