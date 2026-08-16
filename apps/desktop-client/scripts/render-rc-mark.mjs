/**
 * Rasterize the canonical RC mark into Tauri icon sizes.
 * Geometry must stay identical to src/brand/rc-mark.ts.
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Resvg } from '@resvg/resvg-js';

const SCREENS =
  'M1.7 1.4h10.6v8.1H1.7zm1.9 2.55h6.8v4.15H3.6zM8.7 11.1h10.6v8.1H8.7zm1.9 2.55h6.8v4.15h-6.8z';
const LINK = 'M7.15 8.85h2.7l1.95 1.7-1.95 1.7H7.15l1.75-1.7z';
const COLOR = '#FF413D';
const PAGE = '#141618';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const icons = join(root, 'src-tauri', 'icons');

function markSvg(canvas, pad) {
  const inner = canvas - pad * 2;
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${canvas}" height="${canvas}" viewBox="0 0 ${canvas} ${canvas}">
  <rect width="${canvas}" height="${canvas}" fill="${PAGE}"/>
  <g transform="translate(${pad} ${pad}) scale(${inner / 21})">
    <path fill="${COLOR}" fill-rule="evenodd" d="${SCREENS}"/>
    <path fill="${COLOR}" d="${LINK}"/>
  </g>
</svg>`;
}

function writePng(name, canvas, pad) {
  const png = new Resvg(markSvg(canvas, pad), {
    fitTo: { mode: 'width', value: canvas },
  }).render().asPng();
  writeFileSync(join(icons, name), png);
}

writePng('32x32.png', 32, 5);
writePng('128x128.png', 128, 20);
writePng('128x128@2x.png', 256, 40);
writePng('icon.png', 512, 80);

console.log('wrote RC mark rasters to src-tauri/icons');
