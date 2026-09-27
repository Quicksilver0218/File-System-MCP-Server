import { build } from 'esbuild';

await build({
  entryPoints: ['./src/index.ts'],
  bundle: true,
  outfile: './dist/index.js',
  platform: 'node',
  format: 'esm',
  minify: true,
  packages: 'external',
  banner: {
    js: '#!/usr/bin/env node',
  },
});
