function version(value) {
  if (typeof value !== 'string' || !/^\d+\.\d+\.\d+\.\d+(?:-\d+(?:\.\d+)*)?$/.test(value)) return null;
  const parts = value.split('-')[0].split('.').map(Number);
  return parts.every(Number.isSafeInteger) ? {label: value, parts} : null;
}

// Compare the packaged engine to the source target recorded at packaging time.
// This does not check a release service or establish current security support.
export function engineSecurityStatus(buildInfo = {}) {
  const installed = version(buildInfo?.engineVersion);
  const target = version(buildInfo?.sourceTargetVersion);
  let comparison = null;
  if (installed && target) {
    comparison = 0;
    for (let index = 0; index < 4; index++) {
      if (installed.parts[index] === target.parts[index]) continue;
      comparison = installed.parts[index] < target.parts[index] ? -1 : 1;
      break;
    }
  }
  const kind = comparison === null ? 'unknown' : comparison < 0 ? 'older' : comparison > 0 ? 'newer' : 'matches';
  const titles = {
    unknown: 'Engine comparison is unavailable.',
    older: 'This engine is older than Kumo’s source target.',
    matches: 'Engine matches this build’s source target.',
    newer: 'Engine is newer than this build’s source target.',
  };
  return {
    kind, title: titles[kind],
    versions: `Installed Chromium: ${installed?.label || 'unavailable'}. Source target: ${target?.label || 'unavailable'}.`,
  };
}
