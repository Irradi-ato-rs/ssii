// scripts/generate-build-id.js
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, '../public');

// Ensure public directory exists
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

// Write a unique timestamp to force asset hash change
const buildId = Date.now().toString();
fs.writeFileSync(path.join(publicDir, '.build-id'), buildId);
console.log(`Generated build ID: ${buildId}`);   