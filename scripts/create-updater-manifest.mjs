import { readFileSync, writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';

const [version, platform, artifact, output = 'latest.json'] = process.argv.slice(2);

if (!version || !platform || !artifact) {
  console.error('Usage: npm run make-updater-manifest -- <version> <platform> <artifact> [output]');
  console.error('Example: npm run make-updater-manifest -- 1.4.3 darwin-aarch64 "…/BurnISO to USB.app.tar.gz"');
  process.exit(1);
}

if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error(`Invalid semantic version: ${version}`);
  process.exit(1);
}

const artifactPath = resolve(artifact);
const signaturePath = `${artifactPath}.sig`;
const signature = readFileSync(signaturePath, 'utf8').trim();

if (!signature) {
  console.error(`Empty updater signature: ${signaturePath}`);
  process.exit(1);
}

const assetName = basename(artifactPath);
const manifest = {
  version,
  notes: `BurnISO to USB ${version}`,
  pub_date: new Date().toISOString(),
  platforms: {
    [platform]: {
      signature,
      url: `https://github.com/nojan01/burniso-tauri/releases/download/v${version}/${encodeURIComponent(assetName)}`
    }
  }
};

const outputPath = resolve(output);
writeFileSync(outputPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Updater manifest created: ${outputPath}`);
