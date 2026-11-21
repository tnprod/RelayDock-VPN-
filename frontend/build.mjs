import {build} from 'esbuild';
import {copyFile,mkdir} from 'node:fs/promises';
await mkdir('../relaydock/static',{recursive:true});
await build({entryPoints:['src/app.tsx'],bundle:true,minify:true,format:'esm',outfile:'../relaydock/static/app.js',legalComments:'linked'});
await copyFile('src/index.html','../relaydock/static/index.html');
