import { diagnosticSummary, renderDiagnosticDetails, diagnosticProgress } from './diagnostic-report.mjs';
import { burnCompletion } from './burn-result.mjs';
import { createForensicRenderer, standaloneReport, buildForensicJsonExport } from './forensic-report.mjs';

// Wait for Tauri to be ready
document.addEventListener('DOMContentLoaded', async () => {
  // Initialize i18n first
  await window.i18n.init();
  window.i18n.applyTranslations();
  
  // Wait a bit for Tauri to initialize
  await new Promise(resolve => setTimeout(resolve, 100));
  
  const { invoke, Channel } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;
  const { open, save } = window.__TAURI__.dialog;
  const { getCurrentWindow, ProgressBarStatus } = window.__TAURI__.window;

  // Sicheres HTML-Escaping für alle Backend-/User-Daten, die in innerHTML
  // landen (siehe Code-Review K2 – verhindert XSS über Fehlertexte und
  // Gerätenamen).
  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  
  // Bekannte GPT-Partitionstyp-GUIDs. Wichtig: Die EFI System Partition (ESP)
  // steht ausschliesslich in der GPT-Tabelle. Im MBR einer GPT-Platte findet
  // sich nur der Schutzeintrag 0xEE - der ist KEINE EFI-Partition.
  const GPT_TYPE_NAMES = {
    'C12A7328-F81F-11D2-BA4B-00A0C93EC93B': 'EFI System Partition',
    '7C3457EF-0000-11AA-AA11-00306543ECAC': 'Apple APFS Container',
    '48465300-0000-11AA-AA11-00306543ECAC': 'Apple HFS+',
    '426F6F74-0000-11AA-AA11-00306543ECAC': 'Apple Boot (Recovery)',
    '53746F72-6167-11AA-AA11-00306543ECAC': 'Apple Core Storage',
    'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7': 'Microsoft Basic Data',
    'E3C9E316-0B5C-4DB8-817D-F92DF00215AE': 'Microsoft Reserved',
    'DE94BBA4-06D1-4D40-A16A-BFD50179D6AC': 'Windows Recovery',
    '0FC63DAF-8483-4772-8E79-3D69D8477DE4': 'Linux Filesystem',
    '0657FD6D-A4AB-43C4-84E5-0933C84B4F4F': 'Linux Swap',
    'E6D6D379-F507-44C2-A23C-238F2A3DF928': 'Linux LVM',
    '21686148-6449-6E6F-744E-656564454649': 'BIOS Boot',
    '024DEE41-33E7-11D3-9D69-0008C781F39F': 'MBR Partition Scheme'
  };

  // Wandelt "1:EFI:C12A...;2:Container:7C34..." in lesbare Zeilen um.
  function formatGptPartitions(raw) {
    if (!raw || raw === 'none') return [];
    return String(raw).split(';').filter(Boolean).map((entry) => {
      const parts = entry.split(':');
      const num = parts[0] || '?';
      const name = parts[1] || '';
      const guid = (parts[2] || '').toUpperCase();
      const typeName = GPT_TYPE_NAMES[guid] || guid;
      const hasName = name && name !== '-';
      const label = hasName ? name : typeName;
      const suffix = (hasName && typeName && typeName !== name) ? ' — ' + typeName : '';
      return num + ': ' + label + suffix;
    });
  }

  // Einschraenkungs-Hinweise kommen als Code aus dem Backend, damit sie uebersetzbar sind.
const LIMITATION_KEYS = {
  smart_unavailable: 'tools.limitSmartUnavailable',
  filesystem_metadata_unavailable: 'tools.limitFilesystemMetadata',
  filesystem_scan_incomplete: 'tools.scanIncomplete'
};

function translateLimitation(code) {
  const key = LIMITATION_KEYS[String(code)];
  return key ? t(key) : String(code);
}

// Zeigt "110 (14 Nutzdaten, 96 System/Index)". Systemordner werden von macOS
// laufend neu geschrieben, daher waere die reine Gesamtzahl nicht reproduzierbar.
function formatCountBreakdown(total, userCount) {
  const totalNum = Number(total);
  const userNum = Number(userCount);
  if (!Number.isFinite(totalNum) || !Number.isFinite(userNum) || userNum > totalNum) {
    return String(total);
  }
  const systemNum = totalNum - userNum;
  if (systemNum <= 0) return String(total);
  return totalNum + ' (' + userNum + ' ' + t('tools.forensicUserData') + ', '
    + systemNum + ' ' + t('tools.forensicSystemData') + ')';
}

// Rohe Backend-Schluessel wurden bisher nur per _ -> Leerzeichen angezeigt, also
// "is whole disk" oder "free space in bytes" -- unabhaengig von der Sprache und
// teils irrefuehrend, weil die Werte gar nicht in Bytes dargestellt werden.
const FORENSIC_FIELD_KEYS = {
  exact_size_bytes: 'tools.fieldExactSize',
  preferred_block_size: 'tools.fieldPreferredBlockSize',
  physical_block_size: 'tools.fieldPhysicalBlockSize',
  hardware_removable: 'tools.fieldRemovable',
  ejectable: 'tools.fieldEjectable',
  is_whole_disk: 'tools.fieldWholeDisk',
  storage_name: 'tools.fieldStorageName',
  size_in_bytes: 'tools.fieldVolumeSize',
  free_space_in_bytes: 'tools.fieldFreeSpace',
  writable: 'tools.fieldWritable',
  ignore_ownership: 'tools.fieldIgnoreOwnership',
  host_controller: 'tools.fieldHostController',
  pci_vendor_id: 'tools.fieldPciVendorId',
  pci_device_id: 'tools.fieldPciDeviceId',
  pci_revision_id: 'tools.fieldPciRevisionId',
  usb_bus: 'tools.fieldUsbBus',
  special_partitions: 'tools.fieldSpecialPartitions',
  has_windows_recovery: 'tools.fieldWindowsRecovery'
};

function fieldLabel(key) {
  const mapped = FORENSIC_FIELD_KEYS[key];
  if (mapped) {
    const translated = t(mapped);
    // t() gibt bei fehlendem Schlüssel den Schlüssel selbst zurueck.
    if (translated && translated !== mapped) return translated;
  }
  return String(key).replace(/_/g, ' ');
}

// Eigene Helferfunktion, weil yesNo() erst weiter unten als const im SMART-Block
// definiert wird und hier noch in der temporalen Todzone laege.
function formatBool(value) {
  return value ? '✓ ' + t('forensic.yes') : '✗ ' + t('forensic.no');
}

// Geraetename fuer Dateinamen und Berichtstitel.
// Das Backend liefert disk_info durchgehend in snake_case: diskutils
// "Device Identifier" wird in lib.rs zu device_id umbenannt. Die frueher hier
// gelesenen Schluessel Device und "Device Identifier" existierten deshalb nie,
// sodass jeder Bericht auf den Platzhalter "usb" zurueckfiel -- mehrere
// gepruefte Datentraeger ueberschrieben einander stillschweigend, und kein
// Bericht nannte den Traeger, zu dem er gehoerte.
function forensicDeviceName(result, fallback) {
  const info = result?.disk_info || {};
  const raw = info.device_id || info.device_node || result?.disk_id || '';
  const name = String(raw).replace('/dev/', '').trim();
  return name || fallback;
}

// Clipboard helper - use native API as fallback
  async function copyToClipboard(text) {
    try {
      if (window.__TAURI__?.clipboard?.writeText) {
        await window.__TAURI__.clipboard.writeText(text);
      } else {
        await navigator.clipboard.writeText(text);
      }
      return true;
    } catch (e) {
      console.log('Clipboard error:', e);
      return false;
    }
  }

  async function showUpdateMessage(message, title) {
    try {
      if (window.__TAURI__?.dialog?.message) {
        await window.__TAURI__.dialog.message(message, { title, kind: 'info' });
        return;
      }
    } catch (error) {
      console.warn('Native update dialog unavailable:', error);
    }
    window.alert(message);
  }

  async function askToInstallUpdate(message, title) {
    try {
      if (window.__TAURI__?.dialog?.ask) {
        return await window.__TAURI__.dialog.ask(message, {
          title,
          kind: 'info',
          okLabel: window.i18n.currentLang === 'de' ? 'Installieren' : 'Install',
          cancelLabel: window.i18n.currentLang === 'de' ? 'Später' : 'Later'
        });
      }
    } catch (error) {
      console.warn('Native update confirmation unavailable:', error);
    }
    return window.confirm(message);
  }

  let updateCheckInProgress = false;

  async function checkForUpdates({ interactive = false } = {}) {
    if (updateCheckInProgress) return;
    updateCheckInProgress = true;
    let updateReserved = false;
    let installationRequested = false;

    const isGerman = window.i18n.currentLang === 'de';
    const title = isGerman ? 'BurnISO to USB – Updates' : 'BurnISO to USB – Updates';

    try {
      const update = await invoke('plugin:updater|check');
      if (!update) {
        if (interactive) {
          await showUpdateMessage(
            isGerman ? 'Diese Version ist aktuell.' : 'This version is up to date.',
            title
          );
        }
        return;
      }

      const notes = update.body ? `\n\n${update.body}` : '';
      const installNow = await askToInstallUpdate(
        isGerman
          ? `Version ${update.version} ist verfügbar (installiert: ${update.currentVersion}).${notes}\n\nJetzt herunterladen und installieren?`
          : `Version ${update.version} is available (installed: ${update.currentVersion}).${notes}\n\nDownload and install now?`,
        title
      );
      if (!installNow) return;
      installationRequested = true;
      await invoke('reserve_update');
      updateReserved = true;

      let downloaded = 0;
      let contentLength = 0;
      const progressChannel = new Channel((event) => {
        if (event.event === 'Started') {
          contentLength = event.data.contentLength || 0;
        } else if (event.event === 'Progress') {
          downloaded += event.data.chunkLength;
          if (contentLength > 0) {
            document.title = `BurnISO to USB – ${Math.round((downloaded / contentLength) * 100)}%`;
          }
        }
      });

      await invoke('plugin:updater|download_and_install', {
        rid: update.rid,
        onEvent: progressChannel
      });
      document.title = 'BurnISO to USB';

      await showUpdateMessage(
        isGerman
          ? 'Das Update wurde installiert. Die App wird jetzt neu gestartet.'
          : 'The update was installed. The app will now restart.',
        title
      );
      await invoke('restart_application');
    } catch (error) {
      document.title = 'BurnISO to USB';
      console.error('Update check failed:', error);
      if (interactive || installationRequested) {
        await showUpdateMessage(
          isGerman
            ? `Die Update-Prüfung ist fehlgeschlagen: ${String(error)}`
            : `The update check failed: ${String(error)}`,
          title
        );
      }
    } finally {
      if (updateReserved) await invoke('release_update').catch(console.error);
      updateCheckInProgress = false;
    }
  }

  // Check dependencies and show banner if needed
  async function checkAndShowDependencies() {
    try {
      // Check if user dismissed the banner before
      const dismissed = localStorage.getItem('dependenciesBannerDismissed');
      if (dismissed) return;
      
      const deps = await invoke('check_dependencies');
      console.log('Dependencies check:', deps);
      
      if (deps.install_command) {
        const banner = document.getElementById('dependencies-banner');
        const command = document.getElementById('dependencies-command');
        const copyBtn = document.getElementById('dependencies-copy-btn');
        const dismissBtn = document.getElementById('dependencies-dismiss-btn');
        const message = document.getElementById('dependencies-message');
        
        command.textContent = deps.install_command;
        
        // Update message with missing packages
        const missing = deps.missing_brew_packages || [];
        if (missing.length > 0) {
          const packageNames = missing.join(', ');
          const lang = window.i18n.currentLang;
          message.textContent = lang === 'de' 
            ? `Fehlende Pakete: ${packageNames}` 
            : `Missing packages: ${packageNames}`;
        }
        
        banner.classList.remove('hidden');
        
        copyBtn.addEventListener('click', async () => {
          const success = await copyToClipboard(deps.install_command);
          if (success) {
            copyBtn.textContent = '✓';
            setTimeout(() => { copyBtn.textContent = '📋'; }, 2000);
          }
        });
        
        dismissBtn.addEventListener('click', () => {
          banner.classList.add('hidden');
          localStorage.setItem('dependenciesBannerDismissed', 'true');
        });
      }
    } catch (e) {
      console.log('Dependencies check error:', e);
    }
  }
  
  // Check dependencies on startup
  checkAndShowDependencies();

  // Prüft im Hintergrund. Bei einer verfügbaren Version wird ausdrücklich
  // nachgefragt; bei Netzwerkfehlern bleibt der Start der App unbeeinträchtigt.
  setTimeout(() => checkForUpdates(), 1500);

  // Dock progress helper (macOS dock icon progress bar)
  const appWindow = getCurrentWindow();
  async function setDockProgress(percent, status = 'normal') {
    try {
      if (status === 'none') {
        await appWindow.setProgressBar({ status: ProgressBarStatus.None });
      } else if (status === 'error') {
        await appWindow.setProgressBar({ status: ProgressBarStatus.Error, progress: percent });
      } else if (status === 'paused') {
        await appWindow.setProgressBar({ status: ProgressBarStatus.Paused, progress: percent });
      } else {
        await appWindow.setProgressBar({ status: ProgressBarStatus.Normal, progress: percent });
      }
    } catch (err) {
      console.log('Dock progress error:', err);
    }
  }
  
  // Notification helper
  async function sendNotification(title, body) {
    try {
      const { isPermissionGranted, requestPermission, sendNotification: notify } = window.__TAURI__.notification;
      let permissionGranted = await isPermissionGranted();
      if (!permissionGranted) {
        const permission = await requestPermission();
        permissionGranted = permission === 'granted';
      }
      if (permissionGranted) {
        notify({ title, body });
      }
    } catch (err) {
      console.log('Notification error:', err);
    }
  }

  // State
  let selectedIsoPath = '';
  let selectedBurnDisk = null;
  let selectedBackupDisk = null;
  let selectedBackupDestination = '';
  let volumeInfo = null;
  let isBurning = false;
  let isBackingUp = false;
  let burnCancelled = false;
  let backupCancelled = false;
  let selectedDiagnoseDisk = null;
  let isDiagnosing = false;
  let diagnoseCancelled = false;
  
  // ETA tracking
  let burnStartTime = null;
  let backupStartTime = null;
  let diagnoseStartTime = null;

  // Recent Files Management
  const MAX_RECENT_FILES = 10;
  
  function getRecentIsoFiles() {
    try {
      const stored = localStorage.getItem('recentIsoFiles');
      return stored ? JSON.parse(stored) : [];
    } catch (e) {
      return [];
    }
  }
  
  function addRecentIsoFile(path) {
    if (!path) return;
    let recent = getRecentIsoFiles();
    // Remove if already exists
    recent = recent.filter(f => f !== path);
    // Add to front
    recent.unshift(path);
    // Limit to MAX_RECENT_FILES
    recent = recent.slice(0, MAX_RECENT_FILES);
    localStorage.setItem('recentIsoFiles', JSON.stringify(recent));
    updateRecentFilesDropdown();
  }
  
  function getRecentBackupDestinations() {
    try {
      const stored = localStorage.getItem('recentBackupDestinations');
      return stored ? JSON.parse(stored) : [];
    } catch (e) {
      return [];
    }
  }
  
  function addRecentBackupDestination(path) {
    if (!path) return;
    // Store only directory, not full file path
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (!dir) return;
    let recent = getRecentBackupDestinations();
    recent = recent.filter(d => d !== dir);
    recent.unshift(dir);
    recent = recent.slice(0, MAX_RECENT_FILES);
    localStorage.setItem('recentBackupDestinations', JSON.stringify(recent));
  }

  // Confirm modal elements
  const confirmModal = document.getElementById('confirm-modal');
  const confirmTitle = document.getElementById('confirm-title');
  const confirmMessage = document.getElementById('confirm-message');
  const confirmOkBtn = document.getElementById('confirm-ok-btn');
  const confirmCancelBtn = document.getElementById('confirm-cancel-btn');
  let confirmResolve = null;

  // Confirm dialog function - returns a Promise
  function requestConfirm(title, message, okLabel, cancelLabel) {
    return new Promise((resolve) => {
      confirmResolve = resolve;
      confirmTitle.textContent = title;
      confirmMessage.textContent = message;
      confirmOkBtn.textContent = okLabel || 'Ja, löschen';
      confirmCancelBtn.textContent = cancelLabel || 'Abbrechen';
      confirmModal.classList.remove('hidden');
      setTimeout(() => confirmOkBtn.focus(), 100);
    });
  }

  // Confirm modal event handlers
  confirmOkBtn.addEventListener('click', function() {
    confirmModal.classList.add('hidden');
    if (confirmResolve) {
      confirmResolve(true);
    }
    confirmResolve = null;
  });

  confirmCancelBtn.addEventListener('click', function() {
    confirmModal.classList.add('hidden');
    if (confirmResolve) {
      confirmResolve(false);
    }
    confirmResolve = null;
  });

  // Handle Escape key in confirm modal
  confirmModal.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      confirmCancelBtn.click();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      confirmOkBtn.click();
    }
  });

  // Password modal elements
  const passwordModal = document.getElementById('password-modal');
  const passwordInput = document.getElementById('password-input');
  const passwordPrompt = document.getElementById('password-prompt');
  const passwordOkBtn = document.getElementById('password-ok-btn');
  const passwordCancelBtn = document.getElementById('password-cancel-btn');
  let passwordResolve = null;
  let passwordReject = null;
  // W1: Singleton-Lock — verhindert mehrere parallele Passwort-Modale.
  let passwordPromptActive = false;

  // Password dialog function - returns a Promise
  function requestPassword(promptText) {
    if (passwordPromptActive) {
      return Promise.reject('Passwortabfrage läuft bereits');
    }
    passwordPromptActive = true;
    return new Promise((resolve, reject) => {
      passwordResolve = resolve;
      passwordReject = reject;
      passwordPrompt.textContent = promptText;
      passwordInput.value = '';
      passwordModal.classList.remove('hidden');
      setTimeout(() => passwordInput.focus(), 100);
    });
  }

  // Password modal event handlers
  passwordOkBtn.addEventListener('click', function() {
    const password = passwordInput.value;
    passwordModal.classList.add('hidden');
    if (password && passwordResolve) {
      passwordResolve(password);
    } else if (passwordReject) {
      passwordReject('No password entered');
    }
    passwordResolve = null;
    passwordReject = null;
    passwordPromptActive = false;
  });

  passwordCancelBtn.addEventListener('click', function() {
    passwordModal.classList.add('hidden');
    passwordInput.value = '';
    if (passwordReject) {
      passwordReject('Passwortabfrage abgebrochen');
    }
    passwordResolve = null;
    passwordReject = null;
    passwordPromptActive = false;
  });

  // Handle Enter key in password input
  passwordInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      passwordOkBtn.click();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      passwordCancelBtn.click();
    }
  });

  // DOM Elements
  const tabs = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  // Burn tab elements
  const isoPathInput = document.getElementById('iso-path');
  const selectIsoBtn = document.getElementById('select-iso-btn');
  const recentIsoSelect = document.getElementById('recent-iso-select');
  const burnDiskSelect = document.getElementById('burn-disk-select');
  const refreshBurnDisks = document.getElementById('refresh-burn-disks');
  const burnDiskInfo = document.getElementById('burn-disk-info');
  const verifyAfterBurn = document.getElementById('verify-after-burn');
  const ejectAfterBurn = document.getElementById('eject-after-burn');
  const burnBtn = document.getElementById('burn-btn');
  const cancelBurnBtn = document.getElementById('cancel-burn-btn');
  const burnProgressFill = document.getElementById('burn-progress-fill');
  const burnProgressText = document.getElementById('burn-progress-text');
  const burnEta = document.getElementById('burn-eta');
  const burnPhase = document.getElementById('burn-phase');
  const burnWarning = document.getElementById('burn-warning');
  const burnLog = document.getElementById('burn-log');
  
  // ETA calculation helper
  function formatEta(seconds) {
    if (seconds <= 0 || !isFinite(seconds)) return '';
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    const remaining = window.i18n.t('common.remaining') || 'verbleibend';
    if (mins >= 60) {
      const hours = Math.floor(mins / 60);
      const remainingMins = mins % 60;
      return `~${hours}:${remainingMins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')} ${remaining}`;
    }
    return `~${mins}:${secs.toString().padStart(2, '0')} ${remaining}`;
  }
  
  function calculateEta(startTime, percent) {
    if (!startTime || percent <= 0) return '';
    const elapsed = (Date.now() - startTime) / 1000; // seconds
    const remaining = (elapsed / percent) * (100 - percent);
    return formatEta(remaining);
  }

  // Translation helper shortcut
  function t(key) {
    return window.i18n.t(key) || key;
  }

  // Backup tab elements
  const backupDiskSelect = document.getElementById('backup-disk-select');
  const refreshBackupDisks = document.getElementById('refresh-backup-disks');
  const backupDiskInfo = document.getElementById('backup-disk-info');
  const backupDestinationInput = document.getElementById('backup-destination');
  const selectDestinationBtn = document.getElementById('select-destination-btn');
  const backupModeIso = document.querySelector('input[name="backup-mode"][value="iso"]');
  const backupModeRaw = document.querySelector('input[name="backup-mode"][value="raw"]');
  const backupModeFilesystem = document.querySelector('input[name="backup-mode"][value="filesystem"]');
  const backupBtn = document.getElementById('backup-btn');
  const cancelBackupBtn = document.getElementById('cancel-backup-btn');
  const backupProgressFill = document.getElementById('backup-progress-fill');
  const backupProgressText = document.getElementById('backup-progress-text');
  const backupEta = document.getElementById('backup-eta');
  const backupLog = document.getElementById('backup-log');

  // Diagnose tab elements
  const diagnoseDiskSelect = document.getElementById('diagnose-disk-select');
  const refreshDiagnoseDisks = document.getElementById('refresh-diagnose-disks');
  const diagnoseDiskInfo = document.getElementById('diagnose-disk-info');
  const diagnoseModeInputs = document.querySelectorAll('input[name="diagnose-mode"]');
  const diagnoseWarning = document.getElementById('diagnose-warning');
  const diagnoseBtn = document.getElementById('diagnose-btn');
  const cancelDiagnoseBtn = document.getElementById('cancel-diagnose-btn');
  const diagnoseProgressFill = document.getElementById('diagnose-progress-fill');
  const diagnoseProgressText = document.getElementById('diagnose-progress-text');
  const diagnoseEta = document.getElementById('diagnose-eta');
  const diagnoseDetails = document.getElementById('diagnose-details');
  const speedProfile = document.getElementById('speed-profile');
  const diagnosePhase = document.getElementById('diagnose-phase');
  const statSectorsChecked = document.getElementById('stat-sectors-checked');
  const statErrorsFound = document.getElementById('stat-errors-found');
  const statReadSpeed = document.getElementById('stat-read-speed');
  const statWriteSpeed = document.getElementById('stat-write-speed');
  const diagnoseLog = document.getElementById('diagnose-log');
  
  // SMART elements
  const smartLoading = document.getElementById('smart-loading');
  const smartUnavailable = document.getElementById('smart-unavailable');
  const smartUnavailableMsg = document.getElementById('smart-unavailable-msg');
  const smartData = document.getElementById('smart-data');
  const smartHealthValue = document.getElementById('smart-health-value');
  const smartTempValue = document.getElementById('smart-temp-value');
  const smartHoursValue = document.getElementById('smart-hours-value');
  const smartCyclesValue = document.getElementById('smart-cycles-value');
  const smartReallocatedValue = document.getElementById('smart-reallocated-value');
  const smartPendingValue = document.getElementById('smart-pending-value');
  const smartUncorrectableValue = document.getElementById('smart-uncorrectable-value');
  const smartSource = document.getElementById('smart-source');
  const smartWarning = document.getElementById('smart-warning');
  const smartStatusBadge = document.getElementById('smart-status-badge');
  const smartSection = document.getElementById('smart-section');
  const smartHeader = document.getElementById('smart-header');
  const smartContent = document.getElementById('smart-content');
  const statsSection = document.getElementById('diagnose-stats-section');
  const statsHeader = document.getElementById('stats-header');
  const statsContent = document.getElementById('stats-content');
  const statsSummaryBadge = document.getElementById('stats-summary-badge');

  // Tools tab elements
  const toolsDiskSelect = document.getElementById('tools-disk-select');
  const refreshToolsDisks = document.getElementById('refresh-tools-disks');
  const toolsDiskInfo = document.getElementById('tools-disk-info');
  const formatFilesystem = document.getElementById('format-filesystem');
  const formatName = document.getElementById('format-name');
  const formatScheme = document.getElementById('format-scheme');
  const formatEncrypted = document.getElementById('format-encrypted');
  const formatEncryptionPassword = document.getElementById('format-encryption-password');
  const encryptionRow = document.getElementById('encryption-row');
  const encryptionPasswordRow = document.getElementById('encryption-password-row');
  const formatBtn = document.getElementById('format-btn');
  const repairBtn = document.getElementById('repair-btn');
  const eraseLevelInputs = document.querySelectorAll('input[name="erase-level"]');
  const secureEraseBtn = document.getElementById('secure-erase-btn');
  const cancelEraseBtn = document.getElementById('cancel-erase-btn');

  // Update the small "~xx min" labels under each erase option based on the
  // currently selected disk size. Estimates use a typical USB write speed
  // range of 10–30 MB/s — slow USB-2 sticks at the low end, decent USB-3
  // sticks at the high end.
  function updateEraseTimeEstimates(sizeStr) {
    // Parse "63 GB" / "32 GB" / "1.5 TB" → bytes
    let gb = NaN;
    if (sizeStr) {
      const m = String(sizeStr).match(/([\d.,]+)\s*(KB|MB|GB|TB)/i);
      if (m) {
        const v = parseFloat(m[1].replace(',', '.'));
        const unit = m[2].toUpperCase();
        const factor = unit === 'TB' ? 1024 : unit === 'GB' ? 1 : unit === 'MB' ? 1/1024 : 1/(1024*1024);
        gb = v * factor;
      }
    }

    function fmt(min) {
      if (!isFinite(min) || min <= 0) return '';
      const number = new Intl.NumberFormat(window.i18n.currentLang === 'de' ? 'de-DE' : 'en-US', {
        maximumFractionDigits: 0
      });
      if (min < 60) return number.format(Math.round(min)) + ' ' + t('tools.eraseEstimateMinutes');
      const h = Math.floor(min / 60);
      const r = Math.round(min - h * 60);
      const hours = number.format(h) + ' ' + t('tools.eraseEstimateHours');
      return r === 0 ? hours : hours + ' ' + number.format(r) + ' ' + t('tools.eraseEstimateMinutes');
    }

    function rangeFor(passes) {
      if (!isFinite(gb) || gb <= 0) return null;
      // 30 MB/s fast end, 10 MB/s slow end
      const fastMin = (gb * 1024) / 30 / 60 * passes;
      const slowMin = (gb * 1024) / 10 / 60 * passes;
      return t('tools.eraseEstimatePrefix') + ' ' + fmt(fastMin) + ' – ' + fmt(slowMin);
    }

    const map = { '0': 1, '1': 1, '4': 3, '3': 35 };
    eraseLevelInputs.forEach(input => {
      const small = input.parentElement.querySelector('small');
      if (!small) return;
      // Don't overwrite the Gutmann warning text
      if (input.value === '3') return;
      const range = rangeFor(map[input.value]);
      if (range) {
        small.textContent = range;
      } else {
        // Restore default i18n label
        const key = small.getAttribute('data-i18n');
        if (key && window.i18n) small.textContent = window.i18n.t(key);
      }
    });
  }

  const bootcheckBtn = document.getElementById('bootcheck-btn');
  const bootcheckResult = document.getElementById('bootcheck-result');
  const toolsProgressFill = document.getElementById('tools-progress-fill');
  const toolsProgressText = document.getElementById('tools-progress-text');
  const toolsEta = document.getElementById('tools-eta');
  const toolsPhase = document.getElementById('tools-phase');
  const toolsLog = document.getElementById('tools-log');
  
  // Forensic tab elements
  const forensicDiskSelect = document.getElementById('forensic-disk-select');
  const refreshForensicDisks = document.getElementById('refresh-forensic-disks');
  const forensicBtn = document.getElementById('forensic-btn');
  const forensicResult = document.getElementById('forensic-result');
  const forensicExportSection = document.getElementById('forensic-export-section');
  const copyForensicBtn = document.getElementById('copy-forensic-btn');
  const exportHtmlBtn = document.getElementById('export-html-btn');
  const forensicLog = document.getElementById('forensic-log');
  
  // Debug check for Tools elements
  console.log('Tools Tab Elements loaded:', {
    toolsDiskSelect: !!toolsDiskSelect,
    refreshToolsDisks: !!refreshToolsDisks,
    formatBtn: !!formatBtn,
    secureEraseBtn: !!secureEraseBtn,
    bootcheckBtn: !!bootcheckBtn,
    bootcheckResult: !!bootcheckResult,
    toolsLog: !!toolsLog
  });
  
  // Forensic tab state
  let selectedForensicDisk = null;
  let lastForensicResult = null;
  let forensicTabLoaded = false;
  
  // Tools tab state
  let selectedToolsDisk = null;
  let isToolsRunning = false;
  let toolsStartTime = null;

  // Collapsible section toggle
  function setupCollapsible(header, content, section) {
    header.addEventListener('click', () => {
      const isExpanded = section.classList.contains('expanded');
      if (isExpanded) {
        section.classList.remove('expanded');
        content.classList.add('hidden');
      } else {
        section.classList.add('expanded');
        content.classList.remove('hidden');
      }
    });
  }
  
  setupCollapsible(smartHeader, smartContent, smartSection);
  setupCollapsible(statsHeader, statsContent, statsSection);

  // Track if smartctl check was already done
  let smartctlCheckDone = false;
  let toolsTabLoaded = false;

  // Tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', async () => {
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(tab.dataset.tab + '-tab').classList.add('active');
      
      // Check smartctl when switching to diagnose tab
      if (tab.dataset.tab === 'diagnose' && !smartctlCheckDone) {
        smartctlCheckDone = true;
        try {
          const installed = await invoke('check_smartctl_installed');
          if (!installed) {
            logDiagnose(t('diagnose.smartTip'), 'info');
            logDiagnose(t('diagnose.smartInstall'), 'warning');
            logDiagnose(t('diagnose.smartNote'), 'info');
          } else {
            logDiagnose(t('diagnose.smartDetected'), 'success');
          }
        } catch (err) {
          // Ignore errors
        }
      }
      
      // Load disks when switching to tools tab (only first time with logging)
      if (tab.dataset.tab === 'tools') {
        if (!toolsTabLoaded) {
          toolsTabLoaded = true;
          loadDisks(toolsDiskSelect, toolsDiskInfo, logTools);
          // Check for Paragon drivers and enable/disable filesystem options
          await checkParagonDrivers();
        } else {
          loadDisksSilent(toolsDiskSelect, toolsDiskInfo);
        }
      }
      
      // Load disks when switching to forensic tab
      if (tab.dataset.tab === 'forensic') {
        if (!forensicTabLoaded) {
          forensicTabLoaded = true;
          loadDisks(forensicDiskSelect, null, logForensic);
        } else {
          loadDisksSilent(forensicDiskSelect, null);
        }
      }
    });
  });

  // ===== DRAG & DROP FOR ISO FILES (Tauri 2) =====
  const dropOverlay = document.getElementById('drop-overlay');
  const container = document.querySelector('.container');

  // Helper to set ISO file from path
  function setIsoFile(path) {
    if (path && (path.toLowerCase().endsWith('.iso') || path.toLowerCase().endsWith('.img') || path.toLowerCase().endsWith('.xz'))) {
      selectedIsoPath = path;
      isoPathInput.value = path;
      logBurn(t('logs.isoSelected') + path.split('/').pop(), 'info');
      updateBurnButton();
      // Reset progress when selecting new file
      setDockProgress(0, 'none');
      burnProgressFill.style.width = '0%';
      burnProgressText.textContent = '0%';
      burnEta.textContent = '';
      burnPhase.textContent = '';
      burnPhase.className = 'phase-text';
      
      // Switch to burn tab if not already there
      const burnTab = document.querySelector('[data-tab="burn"]');
      if (!burnTab.classList.contains('active')) {
        burnTab.click();
      }
      return true;
    }
    return false;
  }

  // Listen for Tauri's drag-drop events
  listen('tauri://drag-enter', (event) => {
    dropOverlay.classList.remove('hidden');
    container.classList.add('drag-over');
  });

  listen('tauri://drag-leave', (event) => {
    dropOverlay.classList.add('hidden');
    container.classList.remove('drag-over');
  });

  listen('tauri://drag-drop', (event) => {
    dropOverlay.classList.add('hidden');
    container.classList.remove('drag-over');
    
    // event.payload contains the paths array
    const paths = event.payload.paths || event.payload;
    if (paths && paths.length > 0) {
      const filePath = paths[0];
      if (setIsoFile(filePath)) {
        logBurn(t('logs.isoDropped') + filePath.split('/').pop(), 'success');
      } else {
        logBurn(t('logs.isoDropInvalid'), 'warning');
      }
    }
  });

  // Logging functions
  // Generischer Log-Helper. Escaped die Nachricht, damit Backend-Texte mit
  // HTML-Sonderzeichen (z. B. Datei-/Gerätenamen) keinen XSS auslösen.
  function appendLog(target, message, type) {
    type = type || 'info';
    const timestamp = new Date().toLocaleTimeString();
    const span = document.createElement('span');
    span.className = type;
    span.textContent = '[' + timestamp + '] ' + message;
    target.appendChild(span);
    target.appendChild(document.createTextNode('\n'));
    target.scrollTop = target.scrollHeight;
  }

  function logBurn(message, type) { appendLog(burnLog, message, type); }
  function logBackup(message, type) { appendLog(backupLog, message, type); }
  function logDiagnose(message, type) { appendLog(diagnoseLog, message, type); }
  function logTools(message, type) { appendLog(toolsLog, message, type); }
  function logForensic(message, type) { appendLog(forensicLog, message, type); }

  function forensicValue(value, fallback = '—') {
    if (value === null || value === undefined || value === '' || value === 'Not applicable') return fallback;
    if (typeof value === 'boolean') return value ? t('forensic.yes') : t('forensic.no');
    return String(value);
  }

  function forensicItem(label, value, options = {}) {
    const className = options.className ? ' ' + options.className : '';
    const fullWidth = options.fullWidth ? ' full-width' : '';
    return '<div class="forensic-item' + fullWidth + '">' +
      '<span class="forensic-label">' + escapeHtml(label) + ':</span>' +
      '<span class="forensic-value' + className + '">' + escapeHtml(forensicValue(value)) + '</span>' +
      '</div>';
  }

  // Reset burn state to initial (silent = no disk reload log)
  function resetBurnState(silent) {
    clearBurnWarning();
    isBurning = false;
    selectedBurnDisk = null;
    burnStartTime = null;
    burnProgressFill.style.width = '0%';
    burnProgressText.textContent = '0%';
    burnEta.textContent = '';
    burnPhase.textContent = '';
    burnPhase.className = 'phase-text';
    cancelBurnBtn.disabled = true;
    // Clear dock progress bar
    setDockProgress(0, 'none');
    updateBurnButton();
    if (!silent) {
      loadDisks(burnDiskSelect, burnDiskInfo, logBurn);
    } else {
      loadDisksSilent(burnDiskSelect, burnDiskInfo);
    }
  }

  // Reset backup state to initial
  function resetBackupState(silent) {
    isBackingUp = false;
    backupStartTime = null;
    backupProgressFill.style.width = '0%';
    backupProgressText.textContent = '0%';
    backupEta.textContent = '';
    cancelBackupBtn.disabled = true;
    // Clear dock progress bar
    setDockProgress(0, 'none');
    updateBackupButton();
    if (!silent) {
      loadDisks(backupDiskSelect, backupDiskInfo, logBackup);
    } else {
      loadDisksSilent(backupDiskSelect, backupDiskInfo);
    }
  }

  // Reset diagnose state to initial
  function resetDiagnoseState(silent) {
    isDiagnosing = false;
    diagnoseStartTime = null;
    diagnoseProgressFill.style.width = '0%';
    diagnoseProgressText.textContent = '0%';
    diagnoseEta.textContent = '';
    diagnosePhase.textContent = '';
    diagnosePhase.className = 'phase-text';
    statSectorsChecked.textContent = '0';
    statErrorsFound.textContent = '0';
    statReadSpeed.textContent = '-';
    statWriteSpeed.textContent = '-';
    cancelDiagnoseBtn.disabled = true;
    // Clear dock progress bar
    setDockProgress(0, 'none');
    updateDiagnoseButton();
    if (!silent) {
      loadDisks(diagnoseDiskSelect, diagnoseDiskInfo, logDiagnose);
    } else {
      loadDisksSilent(diagnoseDiskSelect, diagnoseDiskInfo);
    }
  }

  // Format bytes to human readable string
  // macOS rechnet Speichergroessen durchgehend dezimal: diskutil meldet fuer diesen
  // Stick "62.3 GB (62264442880 Bytes)". Zuvor wurde hier binaer durch 1024 geteilt,
  // das Ergebnis aber als "GB" beschriftet -- dadurch stand in der App 57.8 GB, wo
  // macOS 62.0 GB anzeigt. Das war keine andere Einheit, sondern eine falsche.
  function formatBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n <= 0) return '0 B';
    // macOS rechnet Speichergroessen seit 10.6 dezimal. Mit k=1024 stuende hier
    // "57.8 GB", waehrend diskutil und der Finder "62.0 GB" zeigen.
    const k = 1000;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), sizes.length - 1);
    // Dezimaltrennzeichen an die App-Sprache koppeln, sonst steht im Deutschen der
    // Punkt gleichzeitig fuer Nachkomma- und Tausenderstelle.
    const locale = window.i18n?.currentLang === 'de' ? 'de-DE' : 'en-US';
    const value = (n / Math.pow(k, i)).toLocaleString(locale, {
      minimumFractionDigits: i >= 2 ? 1 : 0,
      maximumFractionDigits: 1
    });
    return value + ' ' + sizes[i];
  }

  // Forensische Darstellung nach Vorbild von diskutil: gerundeter Wert plus exakte
  // Byte-Zahl. Noetig, weil Felder wie size_in_bytes eine Byte-Angabe versprechen.
  function formatBytesExact(bytes) {
    const n = Number(bytes);
    // Nicht-numerische ioreg-Werte lieber roh zeigen als eine Groesse erfinden.
    if (!Number.isFinite(n) || n < 0) return String(bytes);
    // Trennzeichen an die App-Sprache koppeln, nicht an die System-Locale.
    const locale = window.i18n?.currentLang === 'de' ? 'de-DE' : 'en-US';
    return formatBytes(n) + ' (' + n.toLocaleString(locale) + ' Bytes)';
  }

  // Load disks (with logging)
  async function loadDisks(selectElement, infoElement, logFn) {
    selectElement.innerHTML = '<option value="">' + window.i18n.t('burn.selectUsbPlaceholder') + '</option>';
    
    try {
      const disks = await invoke('list_disks');
      selectElement.innerHTML = '<option value="">' + window.i18n.t('burn.selectUsbPlaceholder') + '</option>';
      
      if (disks.length === 0) {
        logFn(t('messages.noUsbFound'), 'warning');
      } else {
        disks.forEach(function(disk) {
          const option = document.createElement('option');
          option.value = JSON.stringify(disk);
          option.textContent = disk.id + ' - ' + disk.name + ' (' + disk.size + ')';
          selectElement.appendChild(option);
        });
        logFn(disks.length + ' ' + t('messages.usbFound'), 'info');
      }
    } catch (err) {
      selectElement.innerHTML = '<option value="">' + window.i18n.t('burn.selectUsbPlaceholder') + '</option>';
      logFn(t('logs.errorPrefix') + err, 'error');
    }
    
    if (infoElement) infoElement.classList.remove('visible');
  }

  // Load disks silently (no logging)
  async function loadDisksSilent(selectElement, infoElement) {
    selectElement.innerHTML = '<option value="">' + window.i18n.t('burn.selectUsbPlaceholder') + '</option>';
    
    try {
      const disks = await invoke('list_disks');
      selectElement.innerHTML = '<option value="">' + window.i18n.t('burn.selectUsbPlaceholder') + '</option>';
      
      disks.forEach(function(disk) {
        const option = document.createElement('option');
        option.value = JSON.stringify(disk);
        option.textContent = disk.id + ' - ' + disk.name + ' (' + disk.size + ')';
        selectElement.appendChild(option);
      });
    } catch (err) {
      selectElement.innerHTML = '<option value="">' + window.i18n.t('burn.selectUsbPlaceholder') + '</option>';
    }
    
    if (infoElement) infoElement.classList.remove('visible');
  }

  // Update recent files dropdown
  function updateRecentFilesDropdown() {
    if (!recentIsoSelect) return;
    const recent = getRecentIsoFiles();
    const placeholderText = window.i18n?.t('burn.recentFiles') || 'Zuletzt verwendet...';
    
    if (recent.length === 0) {
      recentIsoSelect.innerHTML = '<option value="">' + placeholderText + '</option>';
      recentIsoSelect.disabled = true;
      return;
    }
    
    recentIsoSelect.disabled = false;
    recentIsoSelect.innerHTML = '<option value="">' + placeholderText + '</option>';
    recent.forEach(function(path) {
      const option = document.createElement('option');
      option.value = path;
      // Show only filename for display
      const filename = path.split('/').pop();
      option.textContent = filename;
      option.title = path; // Full path as tooltip
      recentIsoSelect.appendChild(option);
    });
  }
  
  // Initialize recent files dropdown on load
  updateRecentFilesDropdown();

  // Show disk info
  async function showDiskInfo(diskId, infoElement, logFn) {
    try {
      const info = await invoke('get_disk_info', { diskId: diskId });
      infoElement.textContent = info;
      infoElement.classList.add('visible');
    } catch (err) {
      logFn(t('logs.errorPrefix') + err, 'error');
    }
  }

  // Check volume info for filesystem backup support
  async function checkVolumeInfo(diskId) {
    try {
      volumeInfo = await invoke('get_volume_info', { diskId: diskId });
      
      if (volumeInfo) {
        // Bei ISO-Dateisystemen: "Dateibasiert" deaktiviert lassen
        if (volumeInfo.filesystem && volumeInfo.filesystem.startsWith('ISO:')) {
          backupModeFilesystem.disabled = true;
          backupModeRaw.checked = true;
        } else {
          backupModeFilesystem.disabled = false;
        }
      } else {
        // Kein Dateisystem erkannt - Raw-Modus erzwingen
        backupModeFilesystem.disabled = true;
        backupModeRaw.checked = true;
      }
    } catch (err) {
      console.error('Volume info error:', err);
      backupModeFilesystem.disabled = true;
      backupModeRaw.checked = true;
      volumeInfo = null;
    }
  }

  // Update button states
  function updateBurnButton() {
    burnBtn.disabled = !selectedIsoPath || !selectedBurnDisk || isBurning;
  }

  function updateBackupButton() {
    backupBtn.disabled = !selectedBackupDisk || !selectedBackupDestination || isBackingUp;
  }

  function updateDiagnoseButton() {
    diagnoseBtn.disabled = !selectedDiagnoseDisk || isDiagnosing;
  }

  // Event listeners - Burn tab
  function clearBurnWarning() {
    burnWarning.textContent = '';
    burnWarning.classList.add('hidden');
  }
  selectIsoBtn.addEventListener('click', async function() {
    try {
      const selected = await open({
        filters: [{ name: 'ISO/IMG/XZ Files', extensions: ['iso', 'img', 'dmg', 'xz'] }],
        multiple: false
      });
      
      if (selected) {
        clearBurnWarning();
        selectedIsoPath = selected;
        isoPathInput.value = selected;
        logBurn(t('logs.isoSelected') + selected, 'success');
        updateBurnButton();
        // Reset progress when selecting new file
        setDockProgress(0, 'none');
        burnProgressFill.style.width = '0%';
        burnProgressText.textContent = '0%';
        burnEta.textContent = '';
        burnPhase.textContent = '';
        burnPhase.className = 'phase-text';
        // Reset recent dropdown selection
        if (recentIsoSelect) recentIsoSelect.value = '';
      }
    } catch (err) {
      logBurn(t('logs.selectionError') + err, 'error');
    }
  });

  // Recent files dropdown change
  if (recentIsoSelect) {
    recentIsoSelect.addEventListener('change', function() {
      if (recentIsoSelect.value) {
        clearBurnWarning();
        selectedIsoPath = recentIsoSelect.value;
        isoPathInput.value = recentIsoSelect.value;
        logBurn(t('logs.isoSelected') + recentIsoSelect.value, 'success');
        updateBurnButton();
        // Reset progress
        setDockProgress(0, 'none');
        burnProgressFill.style.width = '0%';
        burnProgressText.textContent = '0%';
        burnEta.textContent = '';
        burnPhase.textContent = '';
        burnPhase.className = 'phase-text';
      }
    });
  }

  refreshBurnDisks.addEventListener('click', function() {
    loadDisks(burnDiskSelect, burnDiskInfo, logBurn);
  });

  burnDiskSelect.addEventListener('change', async function() {
    clearBurnWarning();
    if (burnDiskSelect.value) {
      selectedBurnDisk = JSON.parse(burnDiskSelect.value);
      // Reset progress when selecting new disk
      setDockProgress(0, 'none');
      burnProgressFill.style.width = '0%';
      burnProgressText.textContent = '0%';
      burnEta.textContent = '';
      burnPhase.textContent = '';
      burnPhase.className = 'phase-text';
      await showDiskInfo(selectedBurnDisk.id, burnDiskInfo, logBurn);
      logBurn(t('logs.usbSelected') + selectedBurnDisk.name + ' (' + selectedBurnDisk.size + ')', 'info');
    } else {
      selectedBurnDisk = null;
      burnDiskInfo.classList.remove('visible');
    }
    updateBurnButton();
  });

  burnBtn.addEventListener('click', async function() {
    if (!selectedIsoPath || !selectedBurnDisk) return;
    
    // W3: Frontend-Validierung des ISO-Pfads
    const isoLower = String(selectedIsoPath).toLowerCase();
    if (!isoLower.endsWith('.iso') && !isoLower.endsWith('.img') && !isoLower.endsWith('.xz')) {
      logBurn(t('errors.invalidIsoExtension') || 'Invalid file: only .iso/.img/.xz are supported', 'error');
      return;
    }
    if (selectedIsoPath.length < 5) {
      logBurn(t('errors.invalidIsoPath') || 'Invalid ISO path', 'error');
      return;
    }
    
    // Confirmation dialog
    const confirmed = await requestConfirm(
      '⚠️ WARNING!',
      'All data on "' + selectedBurnDisk.name + '" (' + selectedBurnDisk.id + ') will be PERMANENTLY deleted!\n\nContinue?',
      'Yes, delete',
      'Cancel'
    );
    
    if (!confirmed) {
      logBurn(t('logs.burnCancelled'), 'warning');
      return;
    }

    // Passwort im App-Fenster abfragen
    let password;
    try {
      password = await requestPassword('Zum Schreiben auf den USB-Stick werden Administrator-Rechte benötigt.\n\nBitte geben Sie Ihr macOS-Passwort ein:');
    } catch (err) {
      logBurn(t('logs.passwordCancelled'), 'warning');
      return;
    }
    
    // Optionen lesen
    const doVerify = verifyAfterBurn.checked;
    const doEject = ejectAfterBurn.checked;
    
    // Start burn
    clearBurnWarning();
    isBurning = true;
    burnCancelled = false;
    burnStartTime = Date.now();
    burnBtn.disabled = true;
    cancelBurnBtn.disabled = false;
    burnProgressFill.style.width = '0%';
    burnProgressText.textContent = '0%';
    burnEta.textContent = '';
    burnPhase.textContent = 'Phase 1: Writing...';
    burnPhase.className = 'phase-text writing';
    
    logBurn(t('logs.burnStarting'), 'info');
    if (doVerify) {
      logBurn(t('logs.verifyEnabled'), 'info');
    }
    
    try {
      const result = await invoke('burn_iso', {
        isoPath: selectedIsoPath,
        diskId: selectedBurnDisk.id,
        password: password,
        verify: doVerify,
        eject: doEject
      });
      const completed = burnCompletion(result, t);
      logBurn(completed.message, 'success');
      if (completed.warning) logBurn(completed.warning, 'warning');
      burnWarning.textContent = completed.warning;
      burnWarning.classList.toggle('hidden', !completed.warning);
      burnProgressFill.style.width = '100%';
      burnProgressText.textContent = '100%';
      burnEta.textContent = '';
      burnPhase.textContent = '✓ ' + completed.message;
      burnPhase.className = 'phase-text success';
      
      // Add to recent files on success
      addRecentIsoFile(selectedIsoPath);
      
      // Send notification
      sendNotification(
        window.i18n.t('notifications.burnComplete') || 'Brennvorgang abgeschlossen',
        completed.notification
      );
      
      isBurning = false;
      selectedBurnDisk = null;
      updateBurnButton();
      cancelBurnBtn.disabled = true;
      loadDisks(burnDiskSelect, burnDiskInfo, logBurn);
    } catch (err) {
      resetBurnState(true); // Reset controls first, retain the actual error below.
      // On cancel: Short message only
      if (burnCancelled) {
        logBurn(t('logs.burnCancelledMark'), 'warning');
        burnPhase.textContent = 'Cancelled';
        burnPhase.className = 'phase-text error';
      } else {
        logBurn(t('logs.errorPrefix') + err, 'error');
        burnPhase.textContent = t('burn.failed');
        burnPhase.className = 'phase-text error';
      }
    }
  });

  cancelBurnBtn.addEventListener('click', async function() {
    burnCancelled = true;
    cancelBurnBtn.disabled = true;
    try {
      await invoke('cancel_burn');
      logBurn(t('logs.cancelling'), 'warning');
    } catch (err) {
      logBurn(t('logs.cancelError') + err, 'error');
    }
  });

  // Event listeners - Backup tab
  refreshBackupDisks.addEventListener('click', function() {
    loadDisks(backupDiskSelect, backupDiskInfo, logBackup);
  });

  backupDiskSelect.addEventListener('change', async function() {
    if (backupDiskSelect.value) {
      selectedBackupDisk = JSON.parse(backupDiskSelect.value);
      // Reset progress when selecting new disk
      setDockProgress(0, 'none');
      backupProgressFill.style.width = '0%';
      backupProgressText.textContent = '0%';
      backupEta.textContent = '';
      await showDiskInfo(selectedBackupDisk.id, backupDiskInfo, logBackup);
      await checkVolumeInfo(selectedBackupDisk.id);
      logBackup(t('logs.usbSelected') + selectedBackupDisk.name + ' (' + selectedBackupDisk.size + ')', 'info');
    } else {
      selectedBackupDisk = null;
      backupDiskInfo.classList.remove('visible');
      backupModeFilesystem.disabled = true;
      volumeInfo = null;
    }
    updateBackupButton();
  });

  selectDestinationBtn.addEventListener('click', async function() {
    const isFilesystemMode = backupModeFilesystem.checked;
    const extension = isFilesystemMode ? 'dmg' : (backupModeIso.checked ? 'iso' : 'img');
    const defaultName = 'USB_Backup_' + new Date().toISOString().slice(0, 10) + '.' + extension;
    
    try {
      const selected = await save({
        defaultPath: defaultName,
        filters: [{ 
          name: isFilesystemMode ? 'DMG Image' : 'ISO/IMG Image', 
          extensions: isFilesystemMode ? ['dmg'] : ['iso', 'img'] 
        }]
      });
      
      if (selected) {
        selectedBackupDestination = selected;
        backupDestinationInput.value = selected;
        logBackup(t('logs.destinationSelected') + selected, 'success');
        updateBackupButton();
      }
    } catch (err) {
      logBackup(t('logs.selectionError') + err, 'error');
    }
  });

  backupBtn.addEventListener('click', async function() {
    if (!selectedBackupDisk || !selectedBackupDestination) return;
    
    const isFilesystemMode = backupModeFilesystem.checked;

    // W3: Backup-Ziel-Validierung
    if (typeof selectedBackupDestination !== 'string' || selectedBackupDestination.length < 2) {
      logBackup(t('errors.invalidBackupPath') || 'Invalid backup destination', 'error');
      return;
    }
    if (!isFilesystemMode) {
      const dstLower = selectedBackupDestination.toLowerCase();
      if (!dstLower.endsWith('.img') && !dstLower.endsWith('.iso') && !dstLower.endsWith('.dmg')) {
        logBackup(t('errors.invalidBackupExtension') || 'Backup destination must end in .img/.iso/.dmg', 'error');
        return;
      }
    }

    // Passwort nur bei Raw-Modus abfragen (Filesystem braucht kein sudo)
    let password = null;
    if (!isFilesystemMode) {
      try {
        password = await requestPassword('Zum Lesen des USB-Sticks werden Administrator-Rechte benötigt.\n\nBitte geben Sie Ihr macOS-Passwort ein:');
      } catch (err) {
        logBackup(t('logs.passwordCancelled'), 'warning');
        return;
      }
    }

    isBackingUp = true;
    backupCancelled = false;
    backupStartTime = Date.now();
    backupBtn.disabled = true;
    cancelBackupBtn.disabled = false;
    backupProgressFill.style.width = '0%';
    backupProgressText.textContent = '0%';
    backupEta.textContent = '';
    
    logBackup(t('logs.backupStarting') + (isFilesystemMode ? t('logs.backupModeFs') : t('logs.backupModeRaw')) + ')...', 'info');
    
    try {
      let result;
      
      if (isFilesystemMode && volumeInfo) {
        result = await invoke('backup_usb_filesystem', {
          mountPoint: volumeInfo.mount_point,
          destination: selectedBackupDestination,
          volumeName: volumeInfo.name
        });
      } else {
        result = await invoke('backup_usb_raw', {
          diskId: selectedBackupDisk.id,
          destination: selectedBackupDestination,
          diskSize: selectedBackupDisk.bytes || 0,
          extractIso: backupModeIso.checked,
          password: password
        });
      }
      
      logBackup(result, 'success');
      backupProgressFill.style.width = '100%';
      backupProgressText.textContent = '100%';
      backupEta.textContent = '';
      
      // Clear dock progress bar on success
      setDockProgress(100, 'none');
      
      // Add to recent backup destinations on success
      addRecentBackupDestination(selectedBackupDestination);
      
      // Send notification
      sendNotification(
        window.i18n.t('notifications.backupComplete') || 'Backup abgeschlossen',
        window.i18n.t('notifications.backupSuccess') || 'USB wurde erfolgreich gesichert!'
      );
      
      isBackingUp = false;
      backupBtn.disabled = false;
      cancelBackupBtn.disabled = true;
      loadDisks(backupDiskSelect, backupDiskInfo, logBackup);
    } catch (err) {
      // On cancel: Short message only
      if (backupCancelled) {
        logBackup(t('logs.backupCancelled'), 'warning');
      } else {
        logBackup(t('logs.errorPrefix') + err, 'error');
      }
      resetBackupState(true); // silent reset
    }
  });

  cancelBackupBtn.addEventListener('click', async function() {
    backupCancelled = true;
    cancelBackupBtn.disabled = true;
    try {
      await invoke('cancel_backup');
      logBackup(t('logs.cancelling'), 'warning');
    } catch (err) {
      logBackup(t('logs.cancelError') + err, 'error');
    }
  });

  // Event listeners - Diagnose tab
  refreshDiagnoseDisks.addEventListener('click', function() {
    loadDisks(diagnoseDiskSelect, diagnoseDiskInfo, logDiagnose);
  });

  diagnoseDiskSelect.addEventListener('change', async function() {
    diagnoseDetails.innerHTML = '';
    diagnoseDetails.classList.add('hidden');
    if (diagnoseDiskSelect.value) {
      selectedDiagnoseDisk = JSON.parse(diagnoseDiskSelect.value);
      // Reset progress when selecting new disk
      setDockProgress(0, 'none');
      diagnoseProgressFill.style.width = '0%';
      diagnoseProgressText.textContent = '0%';
      diagnoseEta.textContent = '';
      diagnosePhase.textContent = '';
      diagnosePhase.className = 'phase-text';
      statSectorsChecked.textContent = '0';
      statErrorsFound.textContent = '0';
      statReadSpeed.textContent = '-';
      statWriteSpeed.textContent = '-';
      statsSummaryBadge.classList.add('hidden');
      await showDiskInfo(selectedDiagnoseDisk.id, diagnoseDiskInfo, logDiagnose);
      logDiagnose(t('diagnose.usbSelected').replace('{name}', selectedDiagnoseDisk.name).replace('{size}', selectedDiagnoseDisk.size), 'info');
      
      // Load SMART data
      await loadSmartData(selectedDiagnoseDisk.id);
    } else {
      selectedDiagnoseDisk = null;
      diagnoseDiskInfo.classList.remove('visible');
      resetSmartDisplay();
    }
    updateDiagnoseButton();
  });
  
  // SMART data functions
  function resetSmartDisplay() {
    smartLoading.classList.add('hidden');
    smartUnavailable.classList.add('hidden');
    smartData.classList.add('hidden');
    smartWarning.classList.add('hidden');
    smartStatusBadge.classList.add('hidden');
  }
  
  async function loadSmartData(diskId) {
    resetSmartDisplay();
    smartLoading.classList.remove('hidden');
    
    try {
      const data = await invoke('get_smart_data', { diskId: diskId });
      
      // DEBUG: Log all SMART data to console
      console.log('[SMART Debug] Full data received:', JSON.stringify(data, null, 2));
      console.log('[SMART Debug] Extended fields:', {
        model_family: data.model_family,
        device_model: data.device_model,
        serial_number: data.serial_number,
        firmware_version: data.firmware_version,
        user_capacity_bytes: data.user_capacity_bytes,
        form_factor: data.form_factor,
        rotation_rate: data.rotation_rate,
        protocol: data.protocol,
        sata_version: data.sata_version,
        smart_enabled: data.smart_enabled,
        trim_supported: data.trim_supported,
        attributes_count: data.attributes ? data.attributes.length : 0
      });
      
      smartLoading.classList.add('hidden');
      
      if (!data.available) {
        smartUnavailable.classList.remove('hidden');
        if (data.error_message) {
          smartUnavailableMsg.textContent = data.error_message;
        }
        // Update badge
        smartStatusBadge.textContent = 'N/A';
        smartStatusBadge.className = 'status-badge unavailable';
        smartStatusBadge.classList.remove('hidden');
        logDiagnose(t('diagnose.smartNotAvailable').replace('{msg}', data.error_message || t('diagnose.smartUnavailable')), 'info');
        return;
      }
      
      // Show SMART data
      smartData.classList.remove('hidden');
      
      // Health status
      smartHealthValue.textContent = data.health_status;
      if (data.health_status.includes('PASSED') || data.health_status.includes('✅')) {
        smartHealthValue.className = 'smart-health-value passed';
        smartStatusBadge.textContent = 'OK ✅';
        smartStatusBadge.className = 'status-badge passed';
      } else if (data.health_status.includes('FAILED') || data.health_status.includes('❌')) {
        smartHealthValue.className = 'smart-health-value failed';
        smartStatusBadge.textContent = 'FAIL ❌';
        smartStatusBadge.className = 'status-badge failed';
      } else {
        smartHealthValue.className = 'smart-health-value';
        smartStatusBadge.textContent = data.health_status;
        smartStatusBadge.className = 'status-badge info';
      }
      smartStatusBadge.classList.remove('hidden');
      
      // Helper to format bytes
      const formatBytes = (bytes) => {
        if (bytes === null || bytes === undefined) return '-';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = bytes;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
          size /= 1024;
          unitIndex++;
        }
        return size.toFixed(unitIndex === 0 ? 0 : 1) + ' ' + units[unitIndex];
      };
      
      // Helper to format LBAs to human readable size (assuming 512 byte sectors)
      const formatLBAs = (lbas) => {
        if (lbas === null || lbas === undefined) return '-';
        const bytes = lbas * 512;
        return formatBytes(bytes) + ' (' + lbas.toLocaleString() + ' LBAs)';
      };
      
      // Helper to set value and hide item if null
      const setSmartValue = (elementId, value, hideParentIfNull = true) => {
        const el = document.getElementById(elementId);
        const parentItem = document.getElementById(elementId.replace('-value', '-item'));
        if (el) {
          el.textContent = value !== null && value !== undefined ? value : '-';
        }
        if (hideParentIfNull && parentItem) {
          if (value === null || value === undefined) {
            parentItem.style.display = 'none';
          } else {
            parentItem.style.display = '';
          }
        }
      };
      
      // Helper for capability badges
      const setCapabilityBadge = (elementId, enabled) => {
        const el = document.getElementById(elementId);
        if (el) {
          if (enabled === true) {
            el.textContent = '✓';
            el.className = 'smart-capability-badge enabled';
          } else if (enabled === false) {
            el.textContent = '✗';
            el.className = 'smart-capability-badge disabled';
          } else {
            el.textContent = '-';
            el.className = 'smart-capability-badge';
          }
        }
      };
      
      // === Device Info Section ===
      const deviceInfoSection = document.getElementById('smart-device-info');
      const hasDeviceInfo = data.model_family || data.device_model || data.serial_number || data.firmware_version;
      if (deviceInfoSection) deviceInfoSection.style.display = hasDeviceInfo ? '' : 'none';
      
      setSmartValue('smart-model-family-value', data.model_family);
      setSmartValue('smart-device-model-value', data.device_model);
      setSmartValue('smart-serial-value', data.serial_number);
      setSmartValue('smart-firmware-value', data.firmware_version);
      setSmartValue('smart-capacity-value', data.user_capacity_bytes ? formatBytes(data.user_capacity_bytes) : null);
      setSmartValue('smart-form-factor-value', data.form_factor);
      
      // Rotation rate: 0 = SSD, >0 = HDD RPM
      let rotationType = null;
      if (data.rotation_rate !== null && data.rotation_rate !== undefined) {
        rotationType = data.rotation_rate === 0 ? 'SSD (Solid State)' : 'HDD (' + data.rotation_rate + ' RPM)';
      }
      setSmartValue('smart-rotation-value', rotationType);
      
      // Block size
      let blockSize = null;
      if (data.logical_block_size || data.physical_block_size) {
        const logical = data.logical_block_size || '-';
        const physical = data.physical_block_size || '-';
        blockSize = logical + ' / ' + physical + ' Bytes (log/phys)';
      }
      setSmartValue('smart-block-size-value', blockSize);
      
      // === Interface Section ===
      const interfaceSection = document.getElementById('smart-interface-info');
      const hasInterfaceInfo = data.protocol || data.ata_version || data.sata_version || data.interface_speed_max;
      if (interfaceSection) interfaceSection.style.display = hasInterfaceInfo ? '' : 'none';
      
      setSmartValue('smart-protocol-value', data.protocol);
      setSmartValue('smart-ata-version-value', data.ata_version);
      setSmartValue('smart-sata-version-value', data.sata_version);
      setSmartValue('smart-speed-max-value', data.interface_speed_max);
      setSmartValue('smart-speed-current-value', data.interface_speed_current);
      
      // === Capabilities Section ===
      const capabilitiesSection = document.getElementById('smart-capabilities-info');
      const hasCapabilities = data.smart_enabled !== null || data.trim_supported !== null || 
                              data.write_cache_enabled !== null || data.read_lookahead_enabled !== null;
      if (capabilitiesSection) capabilitiesSection.style.display = hasCapabilities ? '' : 'none';
      
      setCapabilityBadge('smart-enabled-value', data.smart_enabled);
      setCapabilityBadge('smart-trim-value', data.trim_supported);
      setCapabilityBadge('smart-write-cache-value', data.write_cache_enabled);
      setCapabilityBadge('smart-read-lookahead-value', data.read_lookahead_enabled);
      
      // ATA Security: show if enabled or frozen
      let securityStatus = null;
      if (data.ata_security_enabled !== null) {
        if (data.ata_security_enabled) {
          securityStatus = true;
        } else if (data.ata_security_frozen) {
          // Show as partial if frozen but not enabled
          securityStatus = false;
        } else {
          securityStatus = false;
        }
      }
      setCapabilityBadge('smart-security-value', securityStatus);
      
      // === Usage Stats Section ===
      const usageSection = document.getElementById('smart-usage-info');
      const hasUsageInfo = data.power_on_hours !== null || data.power_cycle_count !== null || 
                           data.total_lbas_written !== null || data.endurance_used_percent !== null;
      if (usageSection) usageSection.style.display = hasUsageInfo ? '' : 'none';
      
      smartHoursValue.textContent = data.power_on_hours !== null ? data.power_on_hours.toLocaleString() + ' h' : '-';
      smartCyclesValue.textContent = data.power_cycle_count !== null ? data.power_cycle_count.toLocaleString() : '-';
      setSmartValue('smart-lbas-written-value', data.total_lbas_written ? formatLBAs(data.total_lbas_written) : null);
      setSmartValue('smart-lbas-read-value', data.total_lbas_read ? formatLBAs(data.total_lbas_read) : null);
      setSmartValue('smart-endurance-value', data.endurance_used_percent !== null ? data.endurance_used_percent + '%' : null);
      setSmartValue('smart-spare-value', data.spare_available_percent !== null ? data.spare_available_percent + '%' : null);
      
      // === Temperature Section ===
      const tempSection = document.getElementById('smart-temperature-info');
      const hasTemp = data.temperature !== null || data.sct_temperature_current !== null;
      if (tempSection) tempSection.style.display = hasTemp ? '' : 'none';
      
      // Use SCT temperature if available, otherwise basic temperature
      const currentTemp = data.sct_temperature_current || data.temperature;
      smartTempValue.textContent = currentTemp !== null ? currentTemp + '°C' : '-';
      setSmartValue('smart-temp-min-value', data.sct_temperature_lifetime_min !== null ? data.sct_temperature_lifetime_min + '°C' : null);
      setSmartValue('smart-temp-max-value', data.sct_temperature_lifetime_max !== null ? data.sct_temperature_lifetime_max + '°C' : null);
      setSmartValue('smart-temp-limit-value', data.sct_temperature_op_limit !== null ? data.sct_temperature_op_limit + '°C' : null);
      
      // === Health Details Section ===
      const healthSection = document.getElementById('smart-health-info');
      const hasHealthDetails = data.reallocated_sectors !== null || data.pending_sectors !== null || 
                               data.uncorrectable_sectors !== null || data.error_log_count !== null;
      if (healthSection) healthSection.style.display = hasHealthDetails ? '' : 'none';
      
      const reallocated = data.reallocated_sectors;
      const pending = data.pending_sectors;
      const uncorrectable = data.uncorrectable_sectors;
      
      smartReallocatedValue.textContent = reallocated !== null ? reallocated : '-';
      smartPendingValue.textContent = pending !== null ? pending : '-';
      smartUncorrectableValue.textContent = uncorrectable !== null ? uncorrectable : '-';
      
      // Error log
      setSmartValue('smart-error-log-value', data.error_log_count !== null ? data.error_log_count : null);
      
      // Highlight warnings
      if (reallocated !== null && reallocated > 0) {
        smartReallocatedValue.className = 'smart-detail-value warning';
      } else {
        smartReallocatedValue.className = 'smart-detail-value';
      }
      
      if (pending !== null && pending > 0) {
        smartPendingValue.className = 'smart-detail-value warning';
      } else {
        smartPendingValue.className = 'smart-detail-value';
      }
      
      if (uncorrectable !== null && uncorrectable > 0) {
        smartUncorrectableValue.className = 'smart-detail-value critical';
      } else {
        smartUncorrectableValue.className = 'smart-detail-value';
      }
      
      // === Self-Test Section ===
      const selfTestSection = document.getElementById('smart-selftest-info');
      const hasSelfTest = data.self_test_status !== null || data.self_test_short_minutes !== null;
      if (selfTestSection) selfTestSection.style.display = hasSelfTest ? '' : 'none';
      
      setSmartValue('smart-selftest-status-value', data.self_test_status);
      setSmartValue('smart-selftest-short-value', data.self_test_short_minutes !== null ? data.self_test_short_minutes + ' min' : null);
      setSmartValue('smart-selftest-extended-value', data.self_test_extended_minutes !== null ? data.self_test_extended_minutes + ' min' : null);
      setSmartValue('smart-selftest-log-value', data.self_test_log_count !== null ? data.self_test_log_count : null);
      
      // === SMART Attributes Table ===
      const attributesSection = document.getElementById('smart-attributes-section');
      const attributesTbody = document.getElementById('smart-attributes-tbody');
      
      if (data.attributes && data.attributes.length > 0) {
        attributesSection.classList.remove('hidden');
        attributesTbody.innerHTML = '';
        
        for (const attr of data.attributes) {
          const row = document.createElement('tr');
          
          // ID
          const tdId = document.createElement('td');
          tdId.className = 'attr-id';
          tdId.textContent = attr.id;
          row.appendChild(tdId);
          
          // Name with prefailure indicator
          const tdName = document.createElement('td');
          tdName.className = 'attr-name';
          let nameText = attr.name.replace(/_/g, ' ');
          if (attr.prefailure) {
            nameText += ' ⚠️';
          }
          tdName.textContent = nameText;
          tdName.title = attr.name;
          row.appendChild(tdName);
          
          // Value
          const tdValue = document.createElement('td');
          tdValue.textContent = attr.value || '-';
          row.appendChild(tdValue);
          
          // Worst
          const tdWorst = document.createElement('td');
          tdWorst.textContent = attr.worst || '-';
          row.appendChild(tdWorst);
          
          // Threshold
          const tdThresh = document.createElement('td');
          tdThresh.textContent = attr.threshold || '-';
          row.appendChild(tdThresh);
          
          // Raw Value
          const tdRaw = document.createElement('td');
          tdRaw.textContent = attr.raw_value || '-';
          row.appendChild(tdRaw);
          
          // Flags
          const tdFlags = document.createElement('td');
          tdFlags.className = 'attr-flags';
          tdFlags.textContent = attr.flags || '-';
          row.appendChild(tdFlags);
          
          // Status
          const tdStatus = document.createElement('td');
          tdStatus.className = 'attr-status ' + (attr.status || 'ok');
          tdStatus.textContent = attr.status === 'ok' ? '✓' : (attr.status === 'warning' ? '⚠' : '✗');
          row.appendChild(tdStatus);
          
          attributesTbody.appendChild(row);
        }
      } else {
        attributesSection.classList.add('hidden');
      }
      
      // Source info
      if (data.source === 'smartctl') {
        smartSource.textContent = t('tools.smartSourceSmartctl');
      } else if (data.source === 'diskutil') {
        smartSource.textContent = t('tools.smartSourceDiskutil');
      }
      
      // Show warning if there's additional info
      if (data.error_message) {
        smartWarning.textContent = 'ℹ️ ' + data.error_message;
        smartWarning.classList.remove('hidden');
      }
      
      logDiagnose(t('diagnose.smartStatusLog').replace('{status}', data.health_status).replace('{source}', data.source), 'success');
      
    } catch (err) {
      smartLoading.classList.add('hidden');
      smartUnavailable.classList.remove('hidden');
      smartUnavailableMsg.textContent = t('diagnose.smartError').replace('{error}', err);
      logDiagnose(t('diagnose.smartError').replace('{error}', err), 'error');
    }
  }

  // Show/hide warning based on test mode
  speedProfile.addEventListener('change', function() {
    const note = document.getElementById('speed-profile-note');
    const key = speedProfile.value === 'detailed' ? 'diagnose.detailedCaveat' : 'diagnose.quickCaveat';
    note.dataset.i18n = key;
    note.textContent = t(key);
  });
  diagnoseModeInputs.forEach(function(input) {
    input.addEventListener('change', function() {
      const mode = document.querySelector('input[name="diagnose-mode"]:checked').value;
      document.getElementById('speed-profile-options').classList.toggle('hidden', mode !== 'speed');
      if (mode === 'surface' || mode === 'sample') {
        diagnoseWarning.classList.add('hidden');
      } else {
        diagnoseWarning.classList.remove('hidden');
      }
    });
  });

  diagnoseBtn.addEventListener('click', async function() {
    if (!selectedDiagnoseDisk) return;
    
    const mode = document.querySelector('input[name="diagnose-mode"]:checked').value;
    const isDestructive = (mode === 'full' || mode === 'speed');
    
    // Confirmation for destructive tests
    if (isDestructive) {
      const confirmed = await requestConfirm(
        t('diagnose.warningTitle'),
        t('diagnose.confirmDeleteMsg').replace('{name}', selectedDiagnoseDisk.name).replace('{id}', selectedDiagnoseDisk.id),
        t('diagnose.confirmDeleteYes'),
        t('dialogs.cancel')
      );
      
      if (!confirmed) {
        logDiagnose(t('diagnose.testCancelled'), 'warning');
        return;
      }
    }

    // Request password for raw device access
    let password;
    try {
      password = await requestPassword(t('dialogs.adminPasswordPrompt') + '\n\n' + t('dialogs.enterPassword') + ':');
    } catch (err) {
      logDiagnose(t('diagnose.passwordCancelled'), 'warning');
      return;
    }
    
    // Start diagnose
    isDiagnosing = true;
    diagnoseCancelled = false;
    diagnoseStartTime = Date.now();
    diagnoseBtn.disabled = true;
    cancelDiagnoseBtn.disabled = false;
    diagnoseProgressFill.style.width = '0%';
    diagnoseProgressText.textContent = '0%';
    diagnoseEta.textContent = '';
    statSectorsChecked.textContent = '0';
    statErrorsFound.textContent = '0';
    statReadSpeed.textContent = '-';
    statWriteSpeed.textContent = '-';
    statsSummaryBadge.classList.add('hidden');
    diagnoseDetails.innerHTML = '';
    diagnoseDetails.classList.add('hidden');
    
    const modeNames = { surface: 'Surface Scan', sample: t('diagnose.sampleLabel'), full: t('diagnose.fullTest'), speed: t('diagnose.speedTest') };
    logDiagnose(t('diagnose.startingTest').replace('{mode}', modeNames[mode]), 'info');
    diagnosePhase.textContent = t('messages.loading');
    diagnosePhase.className = 'phase-text';
    
    try {
      let result;
      logDiagnose(t('diagnose.callingTest').replace('{mode}', mode), 'info');
      
      if (mode === 'surface' || mode === 'sample') {
        result = await invoke('diagnose_surface_scan', {
          diskId: selectedDiagnoseDisk.id,
          sampled: mode === 'sample',
          password: password
        });
      } else if (mode === 'full') {
        logDiagnose(t('diagnose.invokingFullTest'), 'info');
        result = await invoke('diagnose_full_test', {
          diskId: selectedDiagnoseDisk.id,
          password: password
        });
        logDiagnose(t('diagnose.fullTestReturned'), 'info');
      } else if (mode === 'speed') {
        result = await invoke('diagnose_speed_test', {
          diskId: selectedDiagnoseDisk.id,
          profile: speedProfile.value,
          password: password
        });
      }
      
      const summary = diagnosticSummary(result, t);
      diagnoseDetails.innerHTML = renderDiagnosticDetails(result, t);
      diagnoseDetails.classList.toggle('hidden', !result.details);
      // Display results
      // Check if test was cancelled (message contains "abgebrochen" or "cancelled")
      const wasCancelled = result.message && 
        (result.message.toLowerCase().includes('abgebrochen') || 
         result.message.toLowerCase().includes('cancelled'));
      
      if (wasCancelled) {
        // Test was cancelled by user - not an error
        logDiagnose('⚠ ' + result.message, 'warning');
        diagnosePhase.textContent = t('diagnose.testCancelled') || 'Test abgebrochen';
        diagnosePhase.className = 'phase-text warning';
        diagnoseEta.textContent = '';
        statsSummaryBadge.textContent = t('messages.cancelled') || 'Abgebrochen';
        statsSummaryBadge.className = 'status-badge warning';
        statsSummaryBadge.classList.remove('hidden');
      } else if (result.success) {
        logDiagnose('✓ ' + summary, 'success');
        diagnosePhase.textContent = '✓ ' + t('diagnose.testComplete');
        diagnosePhase.className = 'phase-text success';
        diagnoseEta.textContent = '';
        const scoped = result.details?.sampled || result.details?.kind === 'speed' || result.details?.retry_count > 0;
        statsSummaryBadge.textContent = scoped ? summary : '✓ OK';
        statsSummaryBadge.className = scoped ? 'status-badge warning' : 'status-badge passed';
        diagnosePhase.textContent = summary;
        statsSummaryBadge.classList.remove('hidden');
        
        // Send notification
        sendNotification(
          window.i18n.t('notifications.diagnoseComplete') || 'Test abgeschlossen',
          summary
        );
      } else {
        logDiagnose('✗ ' + summary, 'error');
        diagnosePhase.textContent = '✗ ' + t('diagnose.errorsDetected');
        diagnosePhase.className = 'phase-text error';
        diagnoseEta.textContent = '';
        
        // Send notification for errors too
        sendNotification(
          window.i18n.t('notifications.diagnoseComplete') || 'Test abgeschlossen',
          window.i18n.t('notifications.diagnoseFailed') || 'USB-Test: Fehler gefunden!'
        );
        statsSummaryBadge.textContent = '✗ ' + t('diagnose.errorsDetected');
        statsSummaryBadge.className = 'status-badge failed';
        statsSummaryBadge.classList.remove('hidden');
      }
      
      // Update final stats
      statSectorsChecked.textContent = result.sectors_checked.toLocaleString();
      statErrorsFound.textContent = result.errors_found.toLocaleString();
      if (result.read_speed_mbps > 0) {
        statReadSpeed.textContent = result.read_speed_mbps.toFixed(1) + ' MiB/s';
      }
      if (result.write_speed_mbps > 0) {
        statWriteSpeed.textContent = result.write_speed_mbps.toFixed(1) + ' MiB/s';
      }
      
      // Log bad sectors if any
      if (result.bad_sectors && result.bad_sectors.length > 0) {
        logDiagnose(t('diagnose.badSectorsFound').replace('{sectors}', result.bad_sectors.slice(0, 20).join(', ')) + 
                    (result.bad_sectors.length > 20 ? t('diagnose.andMore').replace('{count}', result.bad_sectors.length - 20) : ''), 'warning');
      }
      
      diagnoseProgressFill.style.width = '100%';
      diagnoseProgressText.textContent = '100%';
      
      // Clear dock progress bar on success
      setDockProgress(100, 'none');
      
      isDiagnosing = false;
      diagnoseBtn.disabled = false;
      cancelDiagnoseBtn.disabled = true;
      loadDisks(diagnoseDiskSelect, diagnoseDiskInfo, logDiagnose);
    } catch (err) {
      if (diagnoseCancelled) {
        logDiagnose('✗ ' + t('diagnose.testCancelled'), 'warning');
        diagnosePhase.textContent = t('messages.cancelled');
        diagnosePhase.className = 'phase-text error';
      } else {
        logDiagnose(t('diagnose.error').replace('{error}', err), 'error');
        diagnosePhase.textContent = t('messages.error') + '!';
        diagnosePhase.className = 'phase-text error';
      }
      resetDiagnoseState(true);
    }
  });

  cancelDiagnoseBtn.addEventListener('click', async function() {
    diagnoseCancelled = true;
    cancelDiagnoseBtn.disabled = true;
    try {
      await invoke('cancel_diagnose');
      logDiagnose(t('diagnose.cancelling'), 'warning');
    } catch (err) {
      logDiagnose(t('diagnose.cancelError').replace('{error}', err), 'error');
    }
  });

  // ========== Paragon Driver Check ==========
  
  // Check for Paragon NTFS and extFS drivers and enable/disable filesystem options
  async function checkParagonDrivers() {
    try {
      const drivers = await invoke('check_paragon_drivers');
      console.log('Paragon drivers:', drivers);
      
      // Enable/disable NTFS option based on Paragon NTFS
      const ntfsOption = formatFilesystem.querySelector('option[value="NTFS"]');
      if (ntfsOption) {
        ntfsOption.disabled = !drivers.ntfs;
        ntfsOption.textContent = drivers.ntfs ? 'NTFS (Paragon)' : 'NTFS (Paragon nicht installiert)';
      }
      
      // Enable/disable ext2/3/4 options based on Paragon extFS
      const extOptions = formatFilesystem.querySelectorAll('.paragon-extfs-option');
      extOptions.forEach(opt => {
        opt.disabled = !drivers.extfs;
        if (!drivers.extfs) {
          opt.textContent = opt.value + ' (Paragon nicht installiert)';
        } else {
          opt.textContent = opt.value + ' (Paragon)';
        }
      });
      
      // Log driver status
      if (drivers.ntfs) {
        logTools('✓ ' + t('tools.paragonNtfsInstalled'), 'success');
      } else {
        logTools('ℹ️ ' + t('tools.ntfsNotAvailable'), 'info');
      }
      
      if (drivers.extfs) {
        logTools('✓ ' + t('tools.paragonExtfsInstalled'), 'success');
      } else {
        logTools('ℹ️ ' + t('tools.extfsNotAvailable'), 'info');
      }
      
    } catch (err) {
      console.error('Error checking Paragon drivers:', err);
    }
  }

  // ========== Tools Tab Event Handlers ==========
  
  refreshToolsDisks.addEventListener('click', function() {
    loadDisks(toolsDiskSelect, toolsDiskInfo, logTools);
  });

  // Toggle encryption options based on filesystem selection
  function updateEncryptionVisibility() {
    const fs = formatFilesystem.value;
    // Nur APFS: verschluesseltes HFS+ setzte CoreStorage voraus, das aktuelle
    // macOS-Versionen nicht mehr anbieten (`diskutil listFilesystems`).
    const supportsEncryption = fs === 'APFS';
    encryptionRow.style.display = supportsEncryption ? 'flex' : 'none';
    if (!supportsEncryption) {
      formatEncrypted.checked = false;
      encryptionPasswordRow.style.display = 'none';
      // Das Zuruecksetzen per Skript loest kein change-Ereignis aus, daher wird
      // das Passwort hier ausdruecklich verworfen statt nur ausgeblendet.
      formatEncryptionPassword.value = '';
    }
  }
  
  formatFilesystem.addEventListener('change', updateEncryptionVisibility);
  updateEncryptionVisibility(); // Initial state
  
  // Show/hide encryption password field
  formatEncrypted.addEventListener('change', function() {
    encryptionPasswordRow.style.display = formatEncrypted.checked ? 'flex' : 'none';
    if (!formatEncrypted.checked) {
      formatEncryptionPassword.value = '';
    }
  });

  toolsDiskSelect.addEventListener('change', async function() {
    if (toolsDiskSelect.value) {
      selectedToolsDisk = JSON.parse(toolsDiskSelect.value);
      await showDiskInfo(selectedToolsDisk.id, toolsDiskInfo, logTools);
      logTools(t('logs.usbSelected') + selectedToolsDisk.name + ' (' + selectedToolsDisk.size + ')', 'info');
      formatBtn.disabled = false;
      repairBtn.disabled = false;
      secureEraseBtn.disabled = false;
      bootcheckBtn.disabled = false;
      updateEraseTimeEstimates(selectedToolsDisk.size);
    } else {
      selectedToolsDisk = null;
      toolsDiskInfo.classList.remove('visible');
      formatBtn.disabled = true;
      repairBtn.disabled = true;
      secureEraseBtn.disabled = true;
      bootcheckBtn.disabled = true;
      updateEraseTimeEstimates(null);
    }
  });

  formatBtn.addEventListener('click', async function() {
    if (!selectedToolsDisk) return;
    
    const filesystem = formatFilesystem.value;
    const name = formatName.value || 'USB_STICK';
    const scheme = formatScheme.value;
    const encrypted = formatEncrypted.checked;
    const encryptionPassword = formatEncryptionPassword.value;
    
    // Validate encryption password if encrypted
    if (encrypted && encryptionPassword.length < 4) {
      logTools(t('tools.encryptionPasswordTooShort') || 'Verschlüsselungspasswort muss mindestens 4 Zeichen haben', 'error');
      return;
    }
    
    // Confirmation dialog
    const fsLabel = encrypted ? filesystem + ' (verschlüsselt)' : filesystem;
    const confirmed = await requestConfirm(
      '⚠️ ' + t('tools.formatWarning'),
      t('tools.formatConfirmMsg').replace('{name}', selectedToolsDisk.name).replace('{fs}', fsLabel),
      t('tools.formatConfirmYes'),
      t('dialogs.cancel')
    );
    
    if (!confirmed) {
      logTools(t('tools.formatCancelled'), 'warning');
      return;
    }
    
    let password;
    try {
      password = await requestPassword(t('tools.formatAdminPrompt'));
    } catch (e) {
      logTools(t('tools.formatCancelled'), 'warning');
      return;
    }
    
    isToolsRunning = true;
    toolsStartTime = Date.now();
    formatBtn.disabled = true;
    repairBtn.disabled = true;
    secureEraseBtn.disabled = true;
    bootcheckBtn.disabled = true;
    
    // Reset progress display
    toolsProgressFill.style.width = '0%';
    toolsProgressText.textContent = '0%';
    toolsEta.textContent = '';
    toolsPhase.textContent = t('tools.formatFormatting');
    toolsPhase.className = 'phase-text';
    
    logTools(t('tools.formatStarting').replace('{fs}', fsLabel), 'info');
    
    try {
      const result = await invoke('format_disk', {
        diskId: selectedToolsDisk.id,
        filesystem: filesystem,
        name: name,
        scheme: scheme,
        password: password,
        encrypted: encrypted,
        encryptionPassword: encrypted ? encryptionPassword : null
      });
      logTools(result, 'success');
      toolsProgressFill.style.width = '100%';
      toolsProgressText.textContent = '100%';
      toolsPhase.textContent = t('tools.formatComplete');
      toolsPhase.className = 'phase-text success';
      
      // Clear encryption password from memory
      formatEncryptionPassword.value = '';
      
      sendNotification(t('notifications.formatComplete'), t('notifications.formatSuccess'));
      loadDisks(toolsDiskSelect, toolsDiskInfo, logTools);
    } catch (err) {
      logTools(t('messages.error') + ': ' + err, 'error');
      toolsPhase.textContent = t('tools.formatError');
      toolsPhase.className = 'phase-text error';
    }
    
    isToolsRunning = false;
    formatBtn.disabled = !selectedToolsDisk;
    repairBtn.disabled = !selectedToolsDisk;
    secureEraseBtn.disabled = !selectedToolsDisk;
    bootcheckBtn.disabled = !selectedToolsDisk;
  });

  // Repair disk button
  repairBtn.addEventListener('click', async function() {
    if (!selectedToolsDisk) return;
    
    let password;
    try {
      password = await requestPassword(t('tools.repairAdminPrompt'));
    } catch (e) {
      logTools(t('tools.repairCancelled'), 'warning');
      return;
    }
    
    if (!password) {
      logTools(t('tools.repairCancelled'), 'warning');
      return;
    }
    
    isToolsRunning = true;
    formatBtn.disabled = true;
    repairBtn.disabled = true;
    secureEraseBtn.disabled = true;
    bootcheckBtn.disabled = true;
    
    logTools(t('tools.repairStarting'), 'info');
    toolsPhase.textContent = t('tools.repairRepairing');
    toolsPhase.className = 'phase-text';
    
    try {
      const result = await invoke('repair_disk', { 
        diskId: selectedToolsDisk.id,
        password: password
      });
      logTools(result, 'success');
      toolsProgressFill.style.width = '100%';
      toolsProgressText.textContent = '100%';
      
      // Check if result indicates success
      if (result.includes('OK') || result.includes('successfully') || result.includes('erfolgreich')) {
        toolsPhase.textContent = t('tools.repairNoErrors');
      } else {
        toolsPhase.textContent = t('tools.repairComplete');
      }
      toolsPhase.className = 'phase-text success';
      
      loadDisks(toolsDiskSelect, toolsDiskInfo, logTools);
    } catch (err) {
      logTools(t('tools.repairError') + ': ' + err, 'error');
      toolsPhase.textContent = t('tools.repairError');
      toolsPhase.className = 'phase-text error';
    }
    
    isToolsRunning = false;
    formatBtn.disabled = !selectedToolsDisk;
    repairBtn.disabled = !selectedToolsDisk;
    secureEraseBtn.disabled = !selectedToolsDisk;
    bootcheckBtn.disabled = !selectedToolsDisk;
  });

  secureEraseBtn.addEventListener('click', async function() {
    if (!selectedToolsDisk) return;
    
    const eraseLevel = document.querySelector('input[name="erase-level"]:checked').value;
    const levelNames = {
      '0': t('tools.eraseQuick'),
      '1': t('tools.eraseRandom'),
      '3': t('tools.eraseGutmann'),
      '4': t('tools.eraseDoe')
    };
    
    // Confirmation dialog
    const confirmed = await requestConfirm(
      '⚠️ ' + t('tools.eraseWarning'),
      t('tools.eraseConfirmMsg').replace('{name}', selectedToolsDisk.name).replace('{method}', levelNames[eraseLevel]),
      t('tools.eraseConfirmYes'),
      t('dialogs.cancel')
    );
    
    if (!confirmed) {
      logTools(t('tools.eraseCancelled'), 'warning');
      return;
    }
    
    let password;
    try {
      password = await requestPassword(t('tools.eraseAdminPrompt'));
    } catch (e) {
      logTools(t('tools.eraseCancelled'), 'warning');
      return;
    }
    
    isToolsRunning = true;
    toolsStartTime = Date.now();
    formatBtn.disabled = true;
    repairBtn.disabled = true;
    secureEraseBtn.disabled = true;
    bootcheckBtn.disabled = true;
    cancelEraseBtn.classList.remove('hidden');
    cancelEraseBtn.disabled = false;
    
    // Reset progress display
    toolsProgressFill.style.width = '0%';
    toolsProgressText.textContent = '0%';
    toolsEta.textContent = '';
    toolsPhase.textContent = t('tools.eraseErasing');
    toolsPhase.className = 'phase-text';
    
    logTools(t('tools.eraseStarting').replace('{method}', levelNames[eraseLevel]), 'info');
    logTools(t('tools.eraseTimeWarning'), 'warning');
    
    try {
      const result = await invoke('secure_erase', {
        diskId: selectedToolsDisk.id,
        level: parseInt(eraseLevel),
        password: password
      });
      logTools(result, 'success');
      toolsProgressFill.style.width = '100%';
      toolsProgressText.textContent = '100%';
      toolsPhase.textContent = t('tools.eraseComplete');
      toolsPhase.className = 'phase-text success';
      
      sendNotification(t('notifications.eraseComplete'), t('notifications.eraseSuccess'));
      loadDisks(toolsDiskSelect, toolsDiskInfo, logTools);
    } catch (err) {
      const errMsg = String(err);
      if (errMsg.includes('abgebrochen') || errMsg.includes('cancelled')) {
        logTools(t('tools.eraseCancelled'), 'warning');
        toolsPhase.textContent = t('tools.eraseAborted');
        toolsPhase.className = 'phase-text warning';
        toolsProgressFill.style.width = '0%';
        toolsProgressText.textContent = '0%';
      } else {
        logTools(t('messages.error') + ': ' + err, 'error');
        toolsPhase.textContent = t('tools.formatError');
        toolsPhase.className = 'phase-text error';
      }
    }
    
    isToolsRunning = false;
    formatBtn.disabled = !selectedToolsDisk;
    repairBtn.disabled = !selectedToolsDisk;
    secureEraseBtn.disabled = !selectedToolsDisk;
    bootcheckBtn.disabled = !selectedToolsDisk;
    cancelEraseBtn.classList.add('hidden');
    cancelEraseBtn.disabled = true;
  });

  cancelEraseBtn.addEventListener('click', async function() {
    logTools(t('messages.cancelled') + '...', 'warning');
    cancelEraseBtn.disabled = true;
    try {
      await invoke('cancel_tools');
    } catch (err) {
      logTools(t('messages.error') + ': ' + err, 'error');
    }
  });

  bootcheckBtn.addEventListener('click', async function() {
    console.log('Bootcheck clicked, selectedToolsDisk:', selectedToolsDisk);
    if (!selectedToolsDisk) {
      console.log('No disk selected, returning');
      return;
    }
    
    // Request password (needs raw disk access)
    let password;
    try {
      password = await requestPassword(t('tools.bootAdminPrompt'));
    } catch (e) {
      logTools(t('tools.bootCancelled'), 'warning');
      return;
    }
    
    console.log('Password received, starting bootcheck');
    logTools(t('tools.bootStarting') + ' ' + selectedToolsDisk.name + '...', 'info');
    bootcheckResult.classList.add('hidden');
    
    try {
      const result = await invoke('check_bootable', { diskId: selectedToolsDisk.id, password: password });
      console.log('Bootcheck result:', result);
      
      let html = '<div class="bootcheck-details">';
      html += '<div class="bootcheck-status ' + (result.bootable ? 'bootable' : 'not-bootable') + '">';
      html += result.bootable ? '✓ ' + t('tools.bootBootable') : '✗ ' + t('tools.bootNotBootable');
      html += '</div>';
      html += '<div class="bootcheck-type">' + result.boot_type + '</div>';
      html += '<ul class="bootcheck-info">';
      html += '<li>' + t('tools.bootMbrSig') + ': ' + (result.has_mbr ? '✓' : '✗') + '</li>';
      html += '<li>' + t('tools.bootGpt') + ': ' + (result.has_gpt ? '✓' : '✗') + '</li>';
      html += '<li>' + t('tools.bootEfiPart') + ': ' + (result.has_efi ? '✓' : '✗') + '</li>';
      html += '<li>' + t('tools.bootFlag') + ': ' + (result.has_bootable_flag ? '✓' : '✗') + '</li>';
      if (result.is_iso) {
        html += '<li>' + t('tools.bootIso9660') + ': ✓</li>';
        html += '<li>' + t('tools.bootElTorito') + ': ' + (result.has_el_torito ? '✓' : '✗') + '</li>';
      }
      html += '</ul></div>';
      
      bootcheckResult.innerHTML = html;
      bootcheckResult.classList.remove('hidden');
      
      logTools(t('tools.bootAnalysis') + ': ' + result.boot_type, result.bootable ? 'success' : 'warning');
    } catch (err) {
      logTools(t('tools.bootError') + ': ' + err, 'error');
      bootcheckResult.innerHTML = '<div class="bootcheck-error">' + escapeHtml(t('messages.error') + ': ' + err) + '</div>';
      bootcheckResult.classList.remove('hidden');
    }
  });

  const renderForensicReport = createForensicRenderer({
    t, escapeHtml, forensicValue, forensicItem, formatBytes, formatBytesExact,
    formatCountBreakdown, formatGptPartitions, fieldLabel, formatBool, translateLimitation
  });

  // ===== FORENSIC TAB HANDLERS =====
  
  // Forensic disk select change handler
  forensicDiskSelect.addEventListener('change', async function() {
    if (forensicDiskSelect.value) {
      selectedForensicDisk = JSON.parse(forensicDiskSelect.value);
      logForensic(t('logs.usbSelected') + selectedForensicDisk.name + ' (' + selectedForensicDisk.size + ')', 'info');
      forensicBtn.disabled = false;
    } else {
      selectedForensicDisk = null;
      forensicBtn.disabled = true;
    }
  });
  
  // Refresh forensic disks button
  refreshForensicDisks.addEventListener('click', function() {
    loadDisks(forensicDiskSelect, null, logForensic);
  });

  // Forensic Analysis button handler
  forensicBtn.addEventListener('click', async function() {
    if (!selectedForensicDisk) return;
    
    // Request password (needs raw disk access)
    let password;
    try {
      password = await requestPassword(t('tools.forensicAdminPrompt') || 'Administrator-Rechte für forensische Analyse erforderlich');
    } catch (e) {
      logForensic(t('tools.forensicCancelled') || 'Forensik-Analyse abgebrochen', 'warning');
      return;
    }
    
    logForensic(t('tools.forensicStarting') || 'Starte Forensik-Analyse...', 'info');
    forensicResult.classList.add('hidden');
    forensicExportSection.classList.add('hidden');
    forensicBtn.disabled = true;
    
    try {
      const result = await invoke('forensic_analysis', { 
        diskId: selectedForensicDisk.id, 
        password: password 
      });
      
      // Store for export
      lastForensicResult = result;
      
      // Build the forensic report HTML
      // K2: kurzer Alias für escapeHtml — alle Backend-Strings müssen damit
      // umhüllt werden, bevor sie in innerHTML eingebaut werden.
      const eh = (v) => escapeHtml(v == null ? '' : String(v));
      forensicResult.innerHTML = renderForensicReport(result);
      forensicResult.classList.remove('hidden');
      forensicExportSection.classList.remove('hidden');
      
      logForensic((t('tools.forensicComplete') || '✓ Forensik-Analyse abgeschlossen!'), 'success');
    } catch (err) {
      const errorMsg = String(err);
      const isPasswordError = errorMsg.includes('Falsches Passwort') || 
                              errorMsg.includes('incorrect password') ||
                              errorMsg.includes('Authentication');
      
      if (isPasswordError) {
        logForensic('🔐 ' + (t('tools.forensicWrongPassword') || 'Falsches Passwort') + ' - ' + errorMsg, 'error');
        forensicResult.innerHTML = `
          <div class="forensic-error" style="background: #ffebee; border: 2px solid #f44336; padding: 20px; border-radius: 8px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 10px;">🔐</div>
            <div style="color: #c62828; font-weight: bold; font-size: 18px; margin-bottom: 10px;">
              ${escapeHtml(t('tools.forensicWrongPassword') || 'Falsches Passwort')}
            </div>
            <div style="color: #333;">
              ${escapeHtml(t('tools.forensicPasswordHint') || 'Bitte geben Sie Ihr Administrator-Passwort korrekt ein und versuchen Sie es erneut.')}
            </div>
          </div>`;
      } else {
        logForensic((t('tools.forensicError') || 'Forensik-Analyse Fehler') + ': ' + err, 'error');
        forensicResult.innerHTML = '<div class="forensic-error">' + escapeHtml(t('messages.error') + ': ' + err) + '</div>';
      }
      forensicResult.classList.remove('hidden');
      // Nach einem Fehlschlag darf der Export nicht mehr angeboten werden.
      // Sonst exportiert ein Klick stillschweigend das Ergebnis des ZUVOR
      // geprueften Datentraegers, waehrend der Bildschirm einen Fehler zeigt --
      // in einem Forensik-Werkzeug ein Bericht ueber den falschen Stick.
      lastForensicResult = null;
      forensicExportSection.classList.add('hidden');
    } finally {
      forensicBtn.disabled = !selectedForensicDisk;
    }
  });
  
  // Save forensic JSON button
  copyForensicBtn.addEventListener('click', async function() {
    if (!lastForensicResult) return;
    
    try {
      const deviceName = forensicDeviceName(lastForensicResult, 'usb');
      const filePath = await save({
        defaultPath: 'forensic-report-' + deviceName + '.json',
        filters: [{ name: 'JSON', extensions: ['json'] }]
      });
      
      if (filePath) {
        const jsonContent = JSON.stringify(buildForensicJsonExport(lastForensicResult, window.i18n.currentLang), null, 2);
        await invoke('write_text_file', { path: filePath, content: jsonContent });
        copyForensicBtn.textContent = '✓ ' + t('messages.success');
        logForensic(t('forensic.reportSaved').replace('{path}', filePath), 'success');
        setTimeout(() => {
          copyForensicBtn.textContent = '💾 ' + t('forensic.saveJson');
        }, 2000);
      }
    } catch (err) {
      logForensic(t('forensic.exportError').replace('{error}', err), 'error');
    }
  });
  
  // Export as HTML button
  exportHtmlBtn.addEventListener('click', async function() {
    if (!lastForensicResult) return;
    
    try {
      const deviceName = forensicDeviceName(lastForensicResult, 'usb');
      const filePath = await save({
        defaultPath: 'forensic-report-' + deviceName + '.html',
        filters: [{ name: 'HTML', extensions: ['html'] }]
      });
      
      if (filePath) {
        const htmlContent = await generateForensicHtmlReport(lastForensicResult);
        await invoke('write_text_file', { path: filePath, content: htmlContent });
        logForensic(t('forensic.reportSaved').replace('{path}', filePath), 'success');
      }
    } catch (err) {
      logForensic(t('forensic.exportError').replace('{error}', err), 'error');
    }
  });
  
  // Load the exact same stylesheet as the in-app tab; never export stale DOM.
  async function generateForensicHtmlReport(result) {
    const response = await fetch(new URL('./forensic.css', import.meta.url));
    if (!response.ok) throw new Error('Forensic stylesheet unavailable');
    return standaloneReport({ result, render: renderForensicReport, styles: await response.text(),
      title: t('forensic.reportTitle') + ' - ' + forensicDeviceName(result, 'USB'),
      language: window.i18n.currentLang });
  }

  // Listen for log events from backend
  listen('log', function(event) {
    const message = event.payload;
    // Route to appropriate log based on current operation
    if (isBurning) {
      logBurn(message, 'info');
    } else if (isBackingUp) {
      logBackup(message, 'info');
    } else if (isDiagnosing) {
      logDiagnose(message, 'info');
    } else if (isToolsRunning) {
      logTools(message, 'info');
    }
  });

  // W5: aktuelle Operation-ID für Filterung verspaeteter Events einer abgebrochenen/vorherigen Operation
  let currentOperationId = 0;
  listen('operation_start', function(event) {
    const id = typeof event.payload === 'number' ? event.payload : Number(event.payload);
    if (!Number.isNaN(id)) currentOperationId = id;
  });

  // Listen for progress events
  listen('progress', function(event) {
    // W5: verspaetete Events einer alten Operation verwerfen
    if (typeof event.payload.operation_id === 'number' && event.payload.operation_id < currentOperationId) {
      return;
    }
    const percent = event.payload.percent;
    const status = event.payload.status;
    const operation = event.payload.operation;
    if (operation === 'burn' && !isBurning) return;
    
    // Update dock progress bar
    setDockProgress(percent);
    
    if (operation === 'burn') {
      burnProgressFill.style.width = percent + '%';
      burnProgressText.textContent = percent + '%';
      burnEta.textContent = calculateEta(burnStartTime, percent);
      // Don't log every progress update, only significant ones
      if (status.indexOf('✓') >= 0 || status.indexOf('FEHLER') >= 0) {
        logBurn(status, status.indexOf('FEHLER') >= 0 ? 'error' : 'success');
      }
    } else if (operation === 'backup') {
      backupProgressFill.style.width = percent + '%';
      backupProgressText.textContent = percent + '%';
      backupEta.textContent = calculateEta(backupStartTime, percent);
      if (status.indexOf('✓') >= 0) {
        logBackup(status, 'success');
      }
    } else if (operation === 'tools') {
      toolsProgressFill.style.width = percent + '%';
      toolsProgressText.textContent = percent + '%';
      // ETA is included in the status message from backend
      toolsEta.textContent = '';
      toolsPhase.textContent = status;
    }
  });

  // Listen for burn phase events
  listen('burn_phase', function(event) {
    if (!isBurning) return;
    const phase = event.payload;
    if (phase === 'writing') {
      burnPhase.textContent = 'Phase 1: Writing...';
      burnPhase.className = 'phase-text writing';
    } else if (phase === 'verifying') {
      burnPhase.textContent = 'Phase 2: Verifying...';
      burnPhase.className = 'phase-text verifying';
      // Reset start time for accurate ETA in verify phase
      burnStartTime = Date.now();
      burnEta.textContent = '';
      logBurn(t('logs.verifyStarting'), 'info');
    } else if (phase === 'finalizing') {
      burnPhase.textContent = t('burn.finalizing');
      burnPhase.className = 'phase-text';
      burnEta.textContent = '';
    } else if (phase === 'success') {
      burnPhase.textContent = '✓ Successfully completed!';
      burnPhase.className = 'phase-text success';
      burnEta.textContent = '';
      // Clear dock progress bar on success
      setDockProgress(100, 'none');
    } else if (phase === 'error') {
      burnPhase.textContent = '✗ Verification failed!';
      burnPhase.className = 'phase-text error';
      burnEta.textContent = '';
      // Show error state in dock, then clear
      setDockProgress(100, 'error');
      setTimeout(() => setDockProgress(0, 'none'), 2000);
    }
  });

  // Listen for diagnose progress events
  listen('diagnose_progress', function(event) {
    const payload = event.payload;
    // W5: verspaetete Events einer alten Operation verwerfen
    if (typeof payload.operation_id === 'number' && payload.operation_id < currentOperationId) {
      return;
    }
    diagnoseProgressFill.style.width = payload.percent + '%';
    diagnoseProgressText.textContent = payload.percent + '%';
    const display = diagnosticProgress(payload, t);
    diagnoseEta.textContent = display.eta ?? calculateEta(diagnoseStartTime, payload.percent);
    diagnosePhase.textContent = display.status;
    
    // Update dock progress bar for diagnose
    setDockProgress(payload.percent);
    
    // Update stats in real-time
    statSectorsChecked.textContent = payload.sectors_checked.toLocaleString();
    statErrorsFound.textContent = payload.errors_found.toLocaleString();
    if (payload.read_speed_mbps > 0) {
      statReadSpeed.textContent = payload.read_speed_mbps.toFixed(1) + ' MiB/s';
    }
    if (payload.write_speed_mbps > 0) {
      statWriteSpeed.textContent = payload.write_speed_mbps.toFixed(1) + ' MiB/s';
    }
  });

  // Listen for menu events
  listen('menu-action', function(event) {
    const action = event.payload;
    switch (action) {
      case 'refresh':
        loadDisks(burnDiskSelect, burnDiskInfo, logBurn);
        loadDisks(backupDiskSelect, backupDiskInfo, logBackup);
        loadDisks(diagnoseDiskSelect, diagnoseDiskInfo, logDiagnose);
        break;
      case 'select_iso':
        selectIsoBtn.click();
        break;
      case 'select_destination':
        selectDestinationBtn.click();
        break;
      case 'tab_burn':
        document.querySelector('[data-tab="burn"]').click();
        break;
      case 'tab_backup':
        document.querySelector('[data-tab="backup"]').click();
        break;
      case 'tab_diagnose':
        document.querySelector('[data-tab="diagnose"]').click();
        break;
      case 'tab_tools':
        document.querySelector('[data-tab="tools"]').click();
        break;
      case 'tab_forensic':
        document.querySelector('[data-tab="forensic"]').click();
        break;
      case 'start_burn':
        if (!burnBtn.disabled) burnBtn.click();
        break;
      case 'start_backup':
        if (!backupBtn.disabled) backupBtn.click();
        break;
      case 'start_diagnose':
        if (!diagnoseBtn.disabled) diagnoseBtn.click();
        break;
      case 'cancel_action':
        if (!cancelBurnBtn.disabled) cancelBurnBtn.click();
        if (!cancelBackupBtn.disabled) cancelBackupBtn.click();
        if (!cancelDiagnoseBtn.disabled) cancelDiagnoseBtn.click();
        break;
      case 'lang_de':
        window.i18n.setLanguage('de').then(() => updateEraseTimeEstimates(selectedToolsDisk?.size));
        break;
      case 'lang_en':
        window.i18n.setLanguage('en').then(() => updateEraseTimeEstimates(selectedToolsDisk?.size));
        break;
      case 'theme_dark':
        window.i18n.setTheme('dark');
        break;
      case 'theme_light':
        window.i18n.setTheme('light');
        break;
      case 'help':
        // Open help in new Tauri window
        (async () => {
          try {
            const { WebviewWindow } = window.__TAURI__.webviewWindow;
            const helpWindow = new WebviewWindow('help', {
              url: 'help.html',
              title: window.i18n.currentLang === 'de' ? 'Hilfe - BurnISO to USB' : 'Help - BurnISO to USB',
              width: 700,
              height: 800,
              center: true,
              resizable: true
            });
            helpWindow.once('tauri://created', () => {
              console.log('Help window created');
            });
            helpWindow.once('tauri://error', (e) => {
              console.error('Error creating help window:', e);
            });
          } catch (err) {
            console.error('Failed to open help:', err);
          }
        })();
        break;
      case 'check_updates':
        checkForUpdates({ interactive: true });
        break;
    }
  });

  // Window state persistence - save position and size
  async function saveWindowState() {
    try {
      const { getCurrentWindow } = window.__TAURI__.window;
      const appWindow = getCurrentWindow();
      const size = await appWindow.innerSize();
      const position = await appWindow.outerPosition();
      const scaleFactor = await appWindow.scaleFactor();
      
      // Convert physical pixels to logical pixels
      const width = Math.round(size.width / scaleFactor);
      const height = Math.round(size.height / scaleFactor);
      
      await invoke('save_window_state', { 
        width: width, 
        height: height, 
        x: position.x, 
        y: position.y 
      });
    } catch (err) {
      console.error('Failed to save window state:', err);
    }
  }

  // Initialize window state tracking
  function initWindowStateTracking() {
    if (!window.__TAURI__ || !window.__TAURI__.window) {
      console.warn('Tauri window API not available');
      return;
    }
    
    const { getCurrentWindow } = window.__TAURI__.window;
    const appWindow = getCurrentWindow();
    
    // Debounced save on resize
    let resizeTimeout = null;
    appWindow.onResized(() => {
      if (resizeTimeout) clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(saveWindowState, 500);
    });
    
    // Debounced save on move
    let moveTimeout = null;
    appWindow.onMoved(() => {
      if (moveTimeout) clearTimeout(moveTimeout);
      moveTimeout = setTimeout(saveWindowState, 500);
    });
  }

  // Initialize
  logBurn(t('logs.appReady'), 'info');
  logBackup(t('logs.backupReady'), 'info');
  logDiagnose(t('diagnose.ready'), 'info');
  loadDisks(burnDiskSelect, burnDiskInfo, logBurn);
  loadDisks(backupDiskSelect, backupDiskInfo, logBackup);
  loadDisks(diagnoseDiskSelect, diagnoseDiskInfo, logDiagnose);
  
  // Start window state tracking
  initWindowStateTracking();
});
