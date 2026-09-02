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

// GitHub benennt hochgeladene Release-Dateien um: Alles ausserhalb von
// [A-Za-z0-9._-] wird zu einem Punkt. Aus "BurnISO to USB.app.tar.gz" wird
// also "BurnISO.to.USB.app.tar.gz". Wer hier stattdessen den Originalnamen
// prozentkodiert, erzeugt eine Adresse mit %20, die es auf GitHub nie gibt -
// der Updater bekommt dann stillschweigend 404 und bietet nie ein Update an.
const assetName = basename(artifactPath).replace(/[^A-Za-z0-9._-]/g, '.');
const manifest = {
  version,
  notes: `BurnISO to USB ${version}`,
  pub_date: new Date().toISOString(),
  platforms: {
    [platform]: {
      signature,
      url: `https://github.com/nojan01/burnISOtoUSB-tauri/releases/download/v${version}/${encodeURIComponent(assetName)}`
    }
  }
};

const outputPath = resolve(output);
writeFileSync(outputPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Updater manifest created: ${outputPath}`);
