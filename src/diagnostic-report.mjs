const escape = value => String(value ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const mib = bytes => (Number(bytes || 0) / 1048576).toFixed(1);
const speed = value => Number.isFinite(value) ? value.toFixed(1) + ' MiB/s' : '—';

export function diagnosticSummary(result, t) {
  const d = result.details;
  if (!d) return result.message;
  if (d.kind === 'f3') return t(result.success ? 'diagnose.f3Complete' : 'diagnose.f3Failed');
  if (!result.success) return t('diagnose.scanFailed');
  if (d.kind === 'speed') return t('diagnose.measurementComplete');
  if (d.sampled) return t('diagnose.sampleComplete');
  return t(d.retry_count ? 'diagnose.scanRetried' : 'diagnose.scanComplete');
}

export function renderDiagnosticDetails(result, t) {
  const d = result.details;
  if (!d) return '';
  if (d.kind === 'f3') {
    return '<p>' + escape(t('diagnose.f3Scope')) + '</p><p>' + escape(d.volume) + ' · ' + escape(d.mount_point) + '</p>' +
      '<p>' + escape(t('diagnose.f3Checked')) + ': ' + mib(d.bytes_checked) + ' MiB · ' +
      escape(t('diagnose.f3Good')) + ': ' + mib(d.good_bytes) + ' MiB</p>' +
      '<p>' + ['corrupted', 'changed', 'overwritten'].map(k => escape(t('diagnose.f3' + k[0].toUpperCase() + k.slice(1))) +
        ': ' + Number(d[k + '_sectors'] || 0)).join(' · ') + '</p><p>' + escape(t('diagnose.f3Cleaned')) + '</p>';
  }
  if (d.kind === 'speed') {
    return '<p>' + escape(t(d.profile === 'quick' ? 'diagnose.quickCaveat' : 'diagnose.detailedCaveat')) + '</p>' +
      '<p>' + escape(t('diagnose.weightedAverage')) + '</p>' +
      '<div class="diagnostic-table-scroll"><table class="diagnostic-table"><thead><tr>' +
      ['blockSize', 'writtenRead', 'writeSpeed', 'readSpeed'].map(k => '<th>' + escape(t('diagnose.' + k)) + '</th>').join('') +
      '</tr></thead><tbody>' + (d.speed_results || []).map(row => '<tr><td>' +
        mib(row.block_bytes) + ' MiB</td><td>' + mib(row.write_bytes) + ' / ' + mib(row.read_bytes) + ' MiB</td><td>' +
        speed(row.write_mib_s) + '</td><td>' + speed(row.read_mib_s) + '</td></tr>').join('') + '</tbody></table></div>';
  }
  return '<p class="' + (d.sampled ? 'warning' : '') + '">' + escape(t(d.sampled ? 'diagnose.sampleCaveat' : 'diagnose.fullCoverage')) + '</p>' +
    '<p>' + escape(t('diagnose.coverage')) + ': ' + Number(d.coverage_percent || 0).toFixed(2) + '% (' +
    mib(d.bytes_checked) + ' / ' + mib(d.device_bytes) + ' MiB)</p>' +
    '<p>' + escape(t('diagnose.unreadable')) + ': ' + mib(d.unreadable_bytes) + ' MiB · ' +
    escape(t('diagnose.retryCount')) + ': ' + Number(d.retry_count || 0) + '</p>' +
    ((d.bad_ranges || []).length ? '<p>' + escape(t('diagnose.regionCaveat')) + '</p><ul>' +
      d.bad_ranges.map(r => '<li>' + escape(t('diagnose.byteRange')) + ': ' + escape(r.offset) + '–' +
        escape(Number(r.offset) + Number(r.length) - 1) + ' (' + escape(r.length) + ' Bytes)</li>').join('') + '</ul>' : '') +
    (d.bad_ranges_truncated ? '<p>' + escape(t('diagnose.truncatedRanges')) + '</p>' : '');
}

export function diagnosticProgress(payload, t) {
  const d = payload.details;
  if (!d) return {status:payload.phase + ': ' + payload.status, eta:null};
  const phases = {reading:'readingPhase', read:'readingPhase', write:'writingPhase', retrying:'retryingPhase', synchronizing:'syncPhase', cleanup:'f3Cleanup'};
  let status = t('diagnose.' + (phases[payload.phase] || 'readingPhase'));
  if (d.block_bytes) status += ' · ' + mib(d.block_bytes) + ' MiB';
  if (d.target_bytes) status += ' · ' + mib(d.bytes_checked) + ' / ' + mib(d.target_bytes) + ' MiB';
  if (d.sampled) status = t('diagnose.sampleLabel') + ' · ' + status;
  if (d.kind === 'f3') status = 'F3 · ' + status;
  const seconds = d.eta_seconds;
  const rounded = Math.ceil(seconds);
  const eta = Number.isFinite(seconds) && seconds >= 0
    ? t('diagnose.remaining') + ': ~' + Math.floor(rounded / 60) + ' min ' + rounded % 60 + ' s' : '';
  return {status, eta};
}
