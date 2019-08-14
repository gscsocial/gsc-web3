const fs = require('fs');
const path = require('path');
const target = path.resolve(__dirname, '..', 'test', 'setup', 'GSCWeb3.js');

try {
    fs.unlinkSync(target);
} catch(ex) {}

fs.copyFileSync(
    path.resolve(__dirname, '..', 'test', 'setup', 'browser.js'),
    target
);