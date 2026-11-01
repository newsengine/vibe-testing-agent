import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';

const srcRoot = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

function resolveAlias(specifier) {
  const base = join(srcRoot, specifier.slice(2));
  for (const candidate of [`${base}.ts`, `${base}.tsx`, `${base}.js`, join(base, 'index.ts')]) {
    if (existsSync(candidate)) return pathToFileURL(candidate).href;
  }
  return pathToFileURL(`${base}.ts`).href;
}

export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith('@/')) {
    return nextResolve(resolveAlias(specifier), context);
  }
  return nextResolve(specifier, context);
}
