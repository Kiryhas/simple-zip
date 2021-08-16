const fileHeaderSignature = 0x504b_0304, fileHeaderLength = 30; // PK
const centralDirectorySignature = 0x504b_0102, centralDirectoryLength = 46;
const endOfCentralDirectorySignature = 0x504b_0506, endOfCentralDirectoryLength = 22;
const version = 0x0a00; // 1.0 (0a = 10, 00 = 0)
const platformVersion = 0x030a; // UNIX ZIP 1.0
const dosTime = date => date.getSeconds() >> 1
  | date.getMinutes() << 5
  | date.getHours() << 11;

const dosDate = date => date.getDate()
  | (date.getMonth() + 1) << 5
  | (date.getFullYear() - 1980) << 9;

const modTime = dosTime(new Date());
const modDate = dosDate(new Date());

const bufferOfLength = length => new DataView(new ArrayBuffer(length));

// https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art008
const crc32 = data => {
  const divisor = 0xEDB88320;
  let crc = 0 ^ (-1);

  for (let i = 0; i < data.length; i++) {
    crc ^= data.charCodeAt(i);
    for (let k = 8; k; k--) {
      crc = crc & 1 ? (crc >>> 1) ^ divisor : crc >>> 1;
    }
  }

  return (crc ^ (-1)) >>> 0;
};

// Good breakdown of the PKZIP file structure with examples: https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
const fileHeader = (fileName, fileData) => {
  const fileHeader = bufferOfLength(fileHeaderLength + fileName.length + fileData.length);

  fileHeader.setUint32(0, fileHeaderSignature);
  fileHeader.setUint16(4, version);
  fileHeader.setUint16(10, modTime, true);
  fileHeader.setUint16(12, modDate, true);
  fileHeader.setUint32(14, crc32(fileData), true);
  fileHeader.setUint32(18, fileData.length, true);
  fileHeader.setUint32(22, fileData.length, true);
  fileHeader.setUint16(26, fileName.length, true);

  for (let i = 0; i < fileName.length; i++) {
    fileHeader.setUint8(fileHeaderLength + i, fileName.charCodeAt(i), true);
  };

  for (let i = 0; i < fileData.length; i++) {
    fileHeader.setUint8(fileHeaderLength + fileName.length + i, fileData.charCodeAt(i), true);
  };

  return fileHeader;
};

const centralDirectoryFileHeader = (fileName, fileData, offset) => {
  const buffer = bufferOfLength(centralDirectoryLength + fileName.length);

  buffer.setUint32(0, centralDirectorySignature);
  buffer.setUint16(4, platformVersion, true);
  buffer.setUint32(12, modTime, true);
  buffer.setUint32(14, modDate, true);
  buffer.setUint32(16, crc32(fileData), true);
  buffer.setUint32(20, fileData.length, true);
  buffer.setUint32(24, fileData.length, true);
  buffer.setUint32(28, fileName.length, true);
  buffer.setUint32(36, 1, true);
  buffer.setUint32(42, offset, true);

  for (let i = 0; i < fileName.length; i++) {
    buffer.setUint8(centralDirectoryLength + i, fileName.charCodeAt(i), true);
  };

  return buffer;
};

const endOfCentralDirectory = (centralDirectorySize, offset) => {
  const buffer = bufferOfLength(endOfCentralDirectoryLength);

  buffer.setUint32(0, endOfCentralDirectorySignature);
  buffer.setUint16(8, 1, true);
  buffer.setUint16(10, 1, true);
  buffer.setUint32(12, centralDirectorySize, true);
  buffer.setUint32(16, offset, true);

  return buffer;
};

const zipFiles = files => {
  const fileHeaders = [], centralDirHeaders = [];
  let offset = 0, centralDirSize = 0;

  for (const { name, data } of files) {
    const header = fileHeader(name, data);
    const centralDirHeader = centralDirectoryFileHeader(name, data, offset);

    offset += header.buffer.byteLength;
    centralDirSize += centralDirHeader.buffer.byteLength;

    fileHeaders.push(header);
    centralDirHeaders.push(centralDirHeader);
  };

  return new Blob([...fileHeaders, ...centralDirHeaders, endOfCentralDirectory(centralDirSize, offset)], { type: 'application/zip' });
};

const downloadBlob = blob => {
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  Object.assign(a, {
    href: url,
    download: 'result.zip'
  });
  a.click();
  URL.revokeObjectURL(url);
};

window.onload = () => {
  const entryTemplate = document.querySelector('template');
  const entryContainer = document.querySelector('.entries');
  const zipButton = document.querySelector('button');
  const addEntryButton = document.querySelector('.more');

  const newEntry = () => entryContainer.appendChild(entryTemplate.content.cloneNode(true));
  
  zipButton.onclick = () => {
    const entries = Array.from(document.querySelectorAll('.entry')).map(({children}) => ({name: children[0].value, data: children[1].value}));
    
    if (entries.some(({name, data}) => (!name || !data))) return alert('Empty name or value in one of the files');
    
    const archive = zipFiles(entries);
    
    downloadBlob(archive);
  };
  
  addEntryButton.onclick = newEntry;
  newEntry();
};
