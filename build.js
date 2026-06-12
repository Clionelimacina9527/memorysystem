const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, 'src', 'frontend.html'), 'utf8');
const worker = fs.readFileSync(path.join(__dirname, 'src', 'worker.js'), 'utf8');

// Prepend the HTML as a const so worker.js can reference HTML_CONTENT
const output = 'const HTML_CONTENT = ' + JSON.stringify(html) + ';\n' + worker;

fs.writeFileSync(path.join(__dirname, 'index.js'), output, 'utf8');
console.log('Build complete → index.js (' + Math.round(output.length / 1024) + ' KB)');
