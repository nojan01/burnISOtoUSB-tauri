// Pure presentation of backend evidence; never infer verification from a checkbox.
export function burnCompletion(result, t) {
  if (result?.written !== true || typeof result.verified !== 'boolean') {
    throw new Error(t('burn.incompleteResult'));
  }
  const message = t(result.verified ? 'burn.writtenVerified' : 'burn.written');
  let warning = '';
  if (result.warning) {
    const key = result.warning.action === 'eject' ? 'burn.ejectWarning' : 'burn.mountWarning';
    warning = t(key);
    if (result.warning.detail) warning += '\n' + String(result.warning.detail);
  }
  return {message, warning, notification: message + (warning ? '\n' + warning : '')};
}
