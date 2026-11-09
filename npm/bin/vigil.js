#!/usr/bin/env node
'use strict';

// npm launcher for the Vigil CLI. The binary ships in a platform package
// (@lv24/vigil-<os>-<cpu>) pulled in through optionalDependencies, so nothing
// is downloaded or run at install time. Importing this file has no side
// effects; the CLI runs only when it is executed directly.

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const PLATFORM_PACKAGES = new Map([
  ['win32-x64', '@lv24/vigil-win32-x64'],
  ['win32-arm64', '@lv24/vigil-win32-arm64'],
  ['darwin-x64', '@lv24/vigil-darwin-x64'],
  ['darwin-arm64', '@lv24/vigil-darwin-arm64'],
  ['linux-x64', '@lv24/vigil-linux-x64'],
  ['linux-arm64', '@lv24/vigil-linux-arm64'],
]);

class LauncherError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LauncherError';
  }
}

function platformPackageName(platform, arch) {
  return PLATFORM_PACKAGES.get(`${platform}-${arch}`) ?? null;
}

function resolveBinary(platform, arch, resolve = (id) => require.resolve(id)) {
  const pkg = platformPackageName(platform, arch);
  if (pkg === null) {
    const supported = [...PLATFORM_PACKAGES.keys()].join(', ');
    throw new LauncherError(
      `vigil: unsupported platform ${platform}/${arch}. Supported: ${supported}.`,
    );
  }
  let manifestPath;
  try {
    manifestPath = resolve(`${pkg}/package.json`);
  } catch {
    throw new LauncherError(
      `vigil: platform package ${pkg} is not installed. ` +
        'Reinstall with optional dependencies enabled (do not use --no-optional or --omit=optional).',
    );
  }
  const exe = platform === 'win32' ? 'vigil.exe' : 'vigil';
  return path.join(path.dirname(manifestPath), 'bin', exe);
}

function runVigil(argv, options = {}) {
  const {
    platform = process.platform,
    arch = process.arch,
    resolve,
    spawn = spawnSync,
    env = process.env,
    stderr = process.stderr,
  } = options;

  let binary;
  try {
    binary = resolveBinary(platform, arch, resolve);
  } catch (err) {
    if (err instanceof LauncherError) {
      stderr.write(`${err.message}\n`);
      return 1;
    }
    throw err;
  }

  const result = spawn(binary, argv, {
    stdio: 'inherit',
    windowsHide: false,
    env: { ...env, VIGIL_INSTALL_SOURCE: 'npm' },
  });
  if (result.error) {
    stderr.write(`vigil: cannot run ${binary}: ${result.error.message}\n`);
    return 1;
  }
  return typeof result.status === 'number' ? result.status : 1;
}

if (require.main === module) {
  process.exitCode = runVigil(process.argv.slice(2));
}

module.exports = {
  PLATFORM_PACKAGES,
  LauncherError,
  platformPackageName,
  resolveBinary,
  runVigil,
};
