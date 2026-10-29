const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const tscBin = path.resolve(__dirname, '../../micro saas network/fasttools/node_modules/.bin/tsc.cmd');
console.log('📦 Compiling n8n-webhook-guard...');
execSync(`"${tscBin}"`, { cwd: __dirname, stdio: 'inherit' });

const distDir = path.join(__dirname, 'dist');
const jsFile = path.join(distDir, 'index.js');
const mjsFile = path.join(distDir, 'index.mjs');

if (fs.existsSync(jsFile)) {
  fs.copyFileSync(jsFile, mjsFile);
  console.log('✅ Generated dist/index.mjs');
}

console.log('🚀 Build completed successfully!');
