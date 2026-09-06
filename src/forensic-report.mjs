// One renderer for the application tab and standalone HTML exports.
  export function buildForensicJsonExport(result, language = 'de') {
    const disk = result.disk_info || {};
    const boot = result.boot_info || {};
    const smart = result.smart_info || {};
    const partitions = Array.isArray(result.partitions) ? result.partitions : [];
    const detectedFilesystems = result.filesystem_signatures?.detected_filesystems || [];

    return {
      schema_version: '1.1',
      report: {
        type: 'forensic-usb-analysis',
        created_at: result.timestamp,
        language,
        read_only: result.analysis_quality?.mode === 'read_only'
      },
      summary: {
        device: disk.media_name || disk.device_id || result.disk_id || null,
        disk_identifier: result.disk_id || disk.device_id || null,
        capacity: disk.disk_size || null,
        filesystem: disk.filesystem || disk.content_type || null,
        partition_count: partitions.length,
        bootable: Boolean(disk.bootable || boot.is_iso9660 || (boot.has_gpt && (boot.has_efi || result.mbr_analysis?.partition_entries?.some(p => p.type_hex === 'EF')))),
        smart_health: smart.health_status || disk.smart_status || null,
        detected_filesystems: detectedFilesystems
      },
      acquisition: result.analysis_quality || {
        mode: 'read_only',
        sources: [],
        limitations: []
      },
      evidence: result
    };
  }


export function createForensicRenderer(context) {
  const { t, escapeHtml, forensicValue, forensicItem, formatBytes, formatBytesExact,
    formatCountBreakdown, formatGptPartitions, fieldLabel, formatBool, translateLimitation } = context;
  return function renderForensicReport(result) {
  const eh = (v) => escapeHtml(v == null ? '' : String(v));
  let html = '<div class="forensic-report">';
  
  // Header with timestamp
  html += '<div class="forensic-header">';
  html += '<h4>🔬 ' + (t('tools.forensicTitle') || 'Forensik-Analyse') + '</h4>';
  html += '<div class="forensic-timestamp">' + (t('tools.forensicTimestamp') || 'Zeitstempel') + ': ' + eh(result.timestamp) + '</div>';
  html += '</div>';

  // A compact overview makes the key evidence visible before the detailed
  // acquisition data. The remaining sections retain the complete result.
  const overviewDisk = result.disk_info || {};
  const overviewSmart = result.smart_info || {};
  const overviewPartitions = Array.isArray(result.partitions) ? result.partitions.length : 0;
  const overviewHealth = overviewSmart.health_status || overviewDisk.smart_status || t('tools.unknown');
  const overviewBootable = overviewDisk.bootable === true || result.boot_info?.is_iso9660 ||
    (result.boot_info?.has_gpt && (result.boot_info?.has_efi || result.mbr_analysis?.partition_entries?.some(p => p.type_hex === 'EF')));
  const overviewFilesystem = overviewDisk.filesystem || overviewDisk.content_type || t('tools.unknown');
  const overviewDevice = overviewDisk.media_name || overviewDisk.device_id || result.disk_id || t('tools.unknown');

  html += '<section class="forensic-overview" aria-label="Forensik-Überblick">';
  html += '<div class="forensic-overview-card"><span class="forensic-overview-label">' + eh(t('tools.device')) + '</span><strong>' + eh(forensicValue(overviewDevice)) + '</strong></div>';
  html += '<div class="forensic-overview-card"><span class="forensic-overview-label">' + eh(t('tools.size')) + '</span><strong>' + eh(forensicValue(overviewDisk.disk_size)) + '</strong></div>';
  html += '<div class="forensic-overview-card"><span class="forensic-overview-label">' + eh(t('tools.forensicFileSystem')) + '</span><strong>' + eh(forensicValue(overviewFilesystem)) + '</strong></div>';
  html += '<div class="forensic-overview-card"><span class="forensic-overview-label">' + eh(t('tools.forensicPartitions')) + '</span><strong>' + overviewPartitions + '</strong></div>';
  html += '<div class="forensic-overview-card ' + (String(overviewHealth).toLowerCase().includes('fail') ? 'critical' : '') + '"><span class="forensic-overview-label">SMART</span><strong>' + eh(forensicValue(overviewHealth)) + '</strong></div>';
  html += '<div class="forensic-overview-card"><span class="forensic-overview-label">' + eh(t('tools.forensicBootable')) + '</span><strong>' + (overviewBootable ? '✓ ' + eh(t('forensic.yes')) : '— ' + eh(t('forensic.no'))) + '</strong></div>';
  html += '</section>';

  if (result.analysis_quality) {
    const sources = Array.isArray(result.analysis_quality.sources) ? result.analysis_quality.sources : [];
    const limitations = Array.isArray(result.analysis_quality.limitations) ? result.analysis_quality.limitations : [];
    html += '<section class="forensic-acquisition">';
    html += '<div><strong>✓ ' + eh(t('forensic.readOnlyMode')) + '</strong>';
    if (result.analysis_quality.sections_collected) html += ' <span class="forensic-acquisition-count">' + eh(result.analysis_quality.sections_collected) + ' ' + eh(t('forensic.sectionsCollected')) + '</span>';
    html += '</div>';
    if (sources.length) html += '<div class="forensic-source-list">' + sources.map(source => '<span>' + eh(source) + '</span>').join('') + '</div>';
    if (limitations.length) html += '<ul class="forensic-limitations">' + limitations.map(note => '<li>' + eh(translateLimitation(note)) + '</li>').join('') + '</ul>';
    html += '</section>';
  }
  
  // Paragon Drivers Section (if available)
  if (result.paragon_drivers) {
    html += '<div class="forensic-section">';
    html += '<h5>🔧 ' + t('tools.forensicParagonDrivers') + '</h5>';
    html += '<div class="forensic-grid">';
    html += '<div class="forensic-item"><span class="forensic-label">NTFS:</span> <span class="forensic-value ' + (result.paragon_drivers.ntfs ? 'success' : 'warning') + '">' + (result.paragon_drivers.ntfs ? t('tools.installed') : t('tools.notInstalled')) + '</span></div>';
    html += '<div class="forensic-item"><span class="forensic-label">extFS (ext2/3/4):</span> <span class="forensic-value ' + (result.paragon_drivers.extfs ? 'success' : 'warning') + '">' + (result.paragon_drivers.extfs ? t('tools.installed') : t('tools.notInstalled')) + '</span></div>';
    html += '</div></div>';
  }
  
  // Device Info Section
  html += '<div class="forensic-section">';
  html += '<h5>📱 ' + t('tools.forensicDeviceInfo') + '</h5>';
  html += '<div class="forensic-grid">';
  
  // Check if this is an SD Card (has SD Card info from card reader)
  const isSDCard = result.usb_info && result.usb_info.hardware_type === 'SD Card';
  
  const diskLabels = {
    media_name: t('tools.forensicMediaName'), device_id: 'Identifier', device_node: t('tools.forensicDevicePath'),
    protocol: t('tools.forensicProtocol'), disk_size: t('tools.forensicTotalSize'),
    block_size: t('tools.forensicBlockSize'), filesystem: t('tools.forensicFileSystem'), content_type: t('tools.forensicContentType'),
    volume_name: 'Volume', mount_point: t('tools.mountPoint'), total_space: t('tools.forensicVolumeCapacity'),
    used_space: t('tools.forensicUsedSpace'), free_space: t('tools.forensicFreeSpace'),
    removable: t('tools.forensicRemovable'), read_only: t('tools.forensicReadOnly'), is_ssd: 'Solid State',
    uuid: 'UUID', volume_uuid: 'Volume-UUID', smart_status: 'SMART'
  };
  const primaryDiskFields = ['media_name', 'device_id', 'device_node', 'protocol', 'disk_size', 'block_size',
    'filesystem', 'content_type', 'volume_name', 'mount_point', 'total_space', 'used_space', 'free_space',
    'removable', 'read_only', 'is_ssd', 'uuid', 'volume_uuid', 'smart_status'];
  primaryDiskFields.forEach(key => {
    if (isSDCard && key === 'smart_status') return;
    const value = result.disk_info?.[key];
    if (value !== undefined && value !== null && value !== '' && !String(value).includes('Not applicable')) {
      html += forensicItem(diskLabels[key] || key, value, { className: key.includes('uuid') ? 'mono' : '' });
    }
  });
  html += '</div></div>';
  
  // Partitions Section - show all partitions with their filesystems
  if (result.partitions && Array.isArray(result.partitions) && result.partitions.length > 0) {
    html += '<div class="forensic-section">';
    html += '<h5>💾 ' + t('tools.forensicPartitions') + ' (' + result.partitions.length + ')</h5>';
    
    result.partitions.forEach((partition, idx) => {
      const partId = eh(partition.partition_id || `Partition ${idx + 1}`);
      const volName = eh(partition.volume_name || '-');
      const fs = eh(partition.filesystem || partition.partition_type || partition.content_type || '-');
      const size = eh(partition.size || '-');
      const mountPoint = eh(partition.mount_point || t('tools.notMounted'));
      const apfsContainer = partition.apfs_container ? eh(partition.apfs_container) : null;
      const apfsVolumes = partition.apfs_volumes || [];
      
      html += '<div class="forensic-partition" style="border: 1px solid #555; padding: 10px; margin: 5px 0; border-radius: 6px; background: rgba(0,0,0,0.15);">';
      html += '<strong style="color: #81c784;">📂 ' + partId + '</strong>';
      if (volName !== '-') html += ' - <span style="color: #4fc3f7;">' + volName + '</span>';
      html += '<div class="forensic-grid" style="margin-top: 8px;">';
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.filesystem') + '</span> <span class="forensic-value">' + fs + '</span></div>';
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.size') + ':</span> <span class="forensic-value">' + size + '</span></div>';
      
      // Show APFS container info if present
      if (apfsContainer) {
        html += '<div class="forensic-item"><span class="forensic-label">APFS Container:</span> <span class="forensic-value">' + apfsContainer + '</span></div>';
      }
      
      // Show mount point for non-APFS or show volumes for APFS
      if (!apfsContainer) {
        html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.mountPoint') + ':</span> <span class="forensic-value">' + mountPoint + '</span></div>';
      }
      
      if (partition.used_space) {
        html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.usedSpace') + ':</span> <span class="forensic-value">' + eh(partition.used_space) + '</span></div>';
      }
      if (partition.free_space) {
        html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.freeSpace') + ':</span> <span class="forensic-value">' + eh(partition.free_space) + '</span></div>';
      }
      html += '</div>';
      
      // Show APFS volumes if present
      if (apfsVolumes.length > 0) {
        html += '<div class="forensic-apfs-volumes">';
        html += '<strong>📦 APFS Volumes (' + apfsVolumes.length + '):</strong>';
        apfsVolumes.forEach((vol) => {
          const volId = eh(vol.volume_id || '-');
          const volNameApfs = eh(vol.name || '-');
          const volMount = eh(vol.mount_point || t('tools.notMounted'));
          const volUsed = eh(vol.used || '-');
          const volFileVault = eh(vol.filevault || '-');
          
          html += '<div class="forensic-apfs-volume">';
          html += '<span class="forensic-apfs-id">📁 ' + volId + '</span> - <span class="forensic-apfs-name">' + volNameApfs + '</span><br>';
          html += '<span class="forensic-label">Mount:</span> <span class="forensic-value">' + volMount + '</span>';
          if (volUsed !== '-') {
            html += ' | <span class="forensic-label">' + t('tools.usedSpace') + ':</span> <span class="forensic-value">' + volUsed + '</span>';
          }
          if (volFileVault !== '-' && volFileVault !== 'No') {
            html += ' | <span class="forensic-label">FileVault:</span> <span class="forensic-value forensic-apfs-alert">' + volFileVault + '</span>';
          }
          html += '</div>';
        });
        html += '</div>';
      }
      
      html += '</div>';
    });
    
    html += '</div>';
  }
  
  // USB Info Section - properly format USB device objects
  if (result.usb_info && Object.keys(result.usb_info).length > 0) {
    html += '<div class="forensic-section">';
    html += '<h5>🔌 ' + t('tools.forensicUsbInfo') + '</h5>';
    html += '<div class="forensic-grid">';
    
    // Check if usb_info contains a devices array
    if (result.usb_info.devices && Array.isArray(result.usb_info.devices)) {
      result.usb_info.devices.forEach((device, idx) => {
        html += '<div class="forensic-usb-device" style="border: 1px solid #444; padding: 10px; margin: 5px 0; border-radius: 6px; background: rgba(0,0,0,0.2);">';
        html += '<strong style="color: #4fc3f7;">📱 ' + t('tools.device') + ' ' + (idx + 1) + ': ' + eh(device.product_name || t('tools.unknown')) + '</strong><br>';
        if (device.manufacturer) html += '<span class="forensic-label">' + t('tools.manufacturer') + ':</span> <span class="forensic-value">' + eh(device.manufacturer) + '</span><br>';
        if (device.vendor_id) html += '<span class="forensic-label">Vendor ID:</span> <span class="forensic-value mono">' + eh(device.vendor_id) + '</span><br>';
        if (device.product_id) html += '<span class="forensic-label">Product ID:</span> <span class="forensic-value mono">' + eh(device.product_id) + '</span><br>';
        if (device.serial_number) html += '<span class="forensic-label">' + t('tools.serialNumber') + ':</span> <span class="forensic-value mono">' + eh(device.serial_number) + '</span><br>';
        if (device.usb_speed) html += '<span class="forensic-label">' + t('tools.usbSpeed') + ':</span> <span class="forensic-value" style="color: #4caf50;">' + eh(device.usb_speed) + '</span><br>';
        if (device.power_allocation) html += '<span class="forensic-label">' + t('tools.powerConsumption') + ':</span> <span class="forensic-value">' + eh(device.power_allocation) + '</span><br>';
        if (device.device_version) html += '<span class="forensic-label">' + t('tools.deviceVersion') + ':</span> <span class="forensic-value">' + eh(device.device_version) + '</span><br>';
        if (device.location_id) html += '<span class="forensic-label">Location ID:</span> <span class="forensic-value mono">' + eh(device.location_id) + '</span><br>';
        html += '</div>';
      });
    } else {
      // Single device or flat structure (USB or SD Card)
      const usbLabels = {
        product_name: t('tools.productName'),
        card_model: t('tools.cardModel'),
        manufacturer: t('tools.manufacturer'),
        manufacturer_id: t('tools.manufacturerId'),
        vendor_id: 'Vendor ID',
        product_id: 'Product ID',
        serial_number: t('tools.serialNumber'),
        usb_speed: t('tools.usbSpeed'),
        reader_link_speed: t('tools.readerSpeed'),
        power_allocation: t('tools.powerConsumption'),
        device_version: t('tools.deviceVersion'),
        location_id: 'Location ID',
        hardware_type: t('tools.deviceType'),
        manufacturing_date: t('tools.manufacturingDate'),
        sd_spec_version: t('tools.sdSpecVersion'),
        capacity: t('tools.capacity'),
        smart_status: 'SMART Status',
        reader_vendor_id: t('tools.readerVendor')
      };
      for (let key in result.usb_info) {
        if (result.usb_info[key] && typeof result.usb_info[key] !== 'object') {
          const label = usbLabels[key] || key;
          html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(result.usb_info[key]) + '</span></div>';
        }
      }
    }
    html += '</div></div>';
  }
  
  // Partition Layout Section
  if (result.partition_layout && !(result.partitions && Array.isArray(result.partitions) && result.partitions.length > 0)) {
    html += '<div class="forensic-section">';
    html += '<h5>💾 ' + t('tools.forensicPartitions') + '</h5>';
    html += '<div class="forensic-partitions">';
    if (Array.isArray(result.partition_layout)) {
      result.partition_layout.forEach((p, i) => {
        html += '<div class="forensic-partition">';
        html += '<strong>' + eh(p.identifier) + '</strong> (' + eh(p.size || 'N/A') + ')';
        if (p.name) html += ' - ' + eh(p.name);
        if (p.type) html += ' [' + eh(p.type) + ']';
        html += '</div>';
      });
    } else if (typeof result.partition_layout === 'string' && result.partition_layout.trim()) {
      // diskutil list output as string - display as preformatted text
      html += '<pre class="forensic-partition-raw">' + eh(result.partition_layout) + '</pre>';
    }
    html += '</div></div>';
  }
  
  // Boot Info Section
  if (result.boot_info) {
    html += '<div class="forensic-section">';
    html += '<h5>🚀 ' + (t('tools.forensicBootInfo') || 'Boot-Strukturen') + '</h5>';
    html += '<div class="forensic-grid">';
    // Use correct key names from Rust backend
    const hasMbr = result.boot_info.has_mbr_signature || result.boot_info.has_mbr;
    const hasGpt = result.boot_info.has_gpt;
    // Die EFI System Partition steht bei GPT ausschliesslich in der
    // GPT-Tabelle (Backend liefert has_efi). Nur bei reinem MBR ist sie
    // als Partitionstyp 0xEF eingetragen.
    const mbrHasEfType = result.mbr_analysis?.partition_entries?.some(
      (p) => String(p.type_hex || '').toUpperCase().replace(/^0X/, '') === 'EF'
    );
    const hasEfi = hasGpt ? !!result.boot_info.has_efi : (mbrHasEfType || !!result.boot_info.has_efi);
    
    // Schutz-MBR (Typ 0xEE) ist kein startfaehiger Legacy-BIOS-Eintrag
    const mbrPartitions = result.boot_info.mbr_partitions || '';
    const isGptProtectiveMbr = /type=0x?ee/i.test(mbrPartitions);
    
    // Real bootable MBR has actual bootable partitions, not just GPT protective
    const hasRealBootableMbr = hasMbr && !isGptProtectiveMbr && !hasGpt;
    const isBootable = hasRealBootableMbr || (hasGpt && hasEfi) || result.boot_info.is_iso9660;
    
    // Das Partitionsschema zuerst nennen - es ordnet alle weiteren Angaben ein.
    let scheme = '—';
    if (hasGpt) {
      scheme = isGptProtectiveMbr
        ? 'GPT (' + (t('tools.forensicProtectiveMbr') || 'mit Schutz-MBR') + ')'
        : 'GPT';
    } else if (hasMbr) {
      scheme = 'MBR';
    }
    html += '<div class="forensic-item"><span class="forensic-label">' + (t('tools.forensicPartScheme') || 'Partitionsschema') + ':</span> <span class="forensic-value">' + eh(scheme) + '</span></div>';
    html += '<div class="forensic-item"><span class="forensic-label">' + (t('tools.forensicMbrSignature') || 'MBR-Signatur') + ':</span> <span class="forensic-value">' + (hasMbr ? '✓ (55AA)' : '✗') + '</span></div>';
    html += '<div class="forensic-item"><span class="forensic-label">' + (t('tools.forensicEsp') || 'EFI-System-Partition') + ':</span> <span class="forensic-value">' + (hasEfi ? '✓' : '✗') + '</span></div>';
    
    // Determine boot type
    let bootType = '';
    if (result.boot_info.is_iso9660) {
      bootType = 'ISO 9660';
      if (result.boot_info.has_el_torito_boot) bootType += ' + El Torito';
    } else if (hasGpt && hasEfi) {
      bootType = 'UEFI (GPT)';
    } else if (hasRealBootableMbr && hasEfi) {
      bootType = 'UEFI (MBR)';
    } else if (hasRealBootableMbr) {
      bootType = 'Legacy BIOS (MBR)';
    } else if (hasGpt && !hasEfi) {
      bootType = 'GPT (' + t('tools.noEfiPartition') + ')';
    }
    
    html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.forensicBootable') + ':</span> <span class="forensic-value">' + (isBootable ? '✓ ' + bootType : '✗ ' + (bootType || t('tools.notBootable'))) + '</span></div>';
    
    if (result.boot_info.is_iso9660) {
      html += '<div class="forensic-item"><span class="forensic-label">ISO 9660:</span> <span class="forensic-value">✓</span></div>';
      if (result.boot_info.iso_volume_label) {
        html += '<div class="forensic-item"><span class="forensic-label">Volume Label:</span> <span class="forensic-value">' + eh(result.boot_info.iso_volume_label) + '</span></div>';
      }
      html += '<div class="forensic-item"><span class="forensic-label">El Torito:</span> <span class="forensic-value">' + (result.boot_info.has_el_torito_boot ? '✓' : '✗') + '</span></div>';
    }
    
    const gptPartitionLines = formatGptPartitions(result.boot_info.gpt_partitions);
    if (gptPartitionLines.length) {
      html += '<div class="forensic-item full-width"><span class="forensic-label">' + (t('tools.forensicGptParts') || 'GPT-Partitionen') + ':</span> <span class="forensic-value">' + eh(gptPartitionLines.join(' · ')) + '</span></div>';
    }
    
    if (result.boot_info.mbr_partitions && result.boot_info.mbr_partitions !== 'none') {
      html += '<div class="forensic-item full-width"><span class="forensic-label">' + t('tools.forensicMbrPartitions') + ':</span> <span class="forensic-value">' + eh(result.boot_info.mbr_partitions) + '</span></div>';
    }
    
    if (result.boot_info.gpt_disk_guid) {
      html += '<div class="forensic-item full-width"><span class="forensic-label">GPT Disk GUID:</span> <span class="forensic-value mono">' + eh(result.boot_info.gpt_disk_guid) + '</span></div>';
    }
    
    html += '</div></div>';
  }
  
  // Filesystem Signatures Section
  const fsSignatures = result.filesystem_signatures?.detected_filesystems || result.filesystem_signatures;
  if (fsSignatures && (Array.isArray(fsSignatures) ? fsSignatures.length > 0 : true)) {
    html += '<div class="forensic-section">';
    html += '<h5>📂 ' + t('tools.forensicFilesystems') + '</h5>';
    html += '<div class="forensic-filesystems">';
    
    if (Array.isArray(fsSignatures)) {
      // New format: array of strings like "ext4 (disk6s2)"
      fsSignatures.forEach(fs => {
        if (typeof fs === 'string') {
          html += '<div class="forensic-fs-item">';
          html += '<span class="fs-name">' + eh(fs) + '</span>';
          html += '</div>';
        } else if (typeof fs === 'object') {
          // Old format with filesystem, offset, label
          html += '<div class="forensic-fs-item">';
          html += '<span class="fs-name">' + eh(fs.filesystem) + '</span>';
          if (fs.offset) html += ' @ Offset ' + eh(fs.offset);
          if (fs.label) html += ' - Label: "' + eh(fs.label) + '"';
          html += '</div>';
        }
      });
    }
    html += '</div></div>';
  }

  // Linux filesystem metadata is read from the raw superblock. It remains
  // available even when macOS cannot mount the volume.
  const linuxFilesystems = result.linux_filesystem_details?.filesystems;
  if (Array.isArray(linuxFilesystems) && linuxFilesystems.length > 0) {
    html += '<div class="forensic-section">';
    html += '<h5>🐧 ' + t('tools.forensicLinuxFsDetails') + '</h5>';
    linuxFilesystems.forEach((filesystem) => {
      const filesystemName = eh(filesystem.filesystem || t('tools.forensicLinuxFs'));
      const partition = eh(filesystem.partition || '-');
      const bytes = (value) => Number.isFinite(Number(value)) ? formatBytes(Number(value)) : '-';
      const item = (label, value, fullWidth = false) => {
        if (value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0)) return '';
        const renderedValue = Array.isArray(value) ? value.join(', ') : String(value);
        return '<div class="forensic-item' + (fullWidth ? ' full-width' : '') + '"><span class="forensic-label">' + eh(label) + ':</span><span class="forensic-value">' + eh(renderedValue) + '</span></div>';
      };

      html += '<div class="forensic-partition">';
      html += '<strong>🐧 ' + filesystemName + ' (' + partition + ')</strong>';
      html += '<div class="forensic-grid" style="margin-top: 8px;">';
      html += item('UUID', filesystem.uuid);
      html += item('Label', filesystem.label);
      html += item(t('tools.size'), filesystem.total_bytes !== undefined ? bytes(filesystem.total_bytes) : undefined);
      html += item(t('tools.usedSpace'), filesystem.used_bytes !== undefined ? bytes(filesystem.used_bytes) + (filesystem.used_percent !== undefined ? ' (' + filesystem.used_percent + '%)' : '') : undefined);
      html += item(t('tools.freeSpace'), filesystem.free_bytes !== undefined ? bytes(filesystem.free_bytes) : undefined);
      html += item(t('tools.forensicBlockSize'), filesystem.block_size_bytes !== undefined ? bytes(filesystem.block_size_bytes) : undefined);
      html += item(t('tools.forensicInodeSize'), filesystem.inode_size_bytes !== undefined ? bytes(filesystem.inode_size_bytes) : undefined);
      html += item(t('tools.forensicInodes'), filesystem.inode_count !== undefined ? String(filesystem.inode_count) + (filesystem.free_inodes !== undefined ? ' (' + filesystem.free_inodes + ' ' + t('tools.forensicFreeSuffix') + ')' : '') : undefined);
      html += item(t('tools.forensicState'), filesystem.state);
      html += item(t('tools.forensicJournal'), filesystem.has_journal === undefined ? undefined : (filesystem.has_journal ? t('tools.forensicPresent') : t('tools.forensicNotPresent')));
      html += item(t('tools.forensicRecovery'), filesystem.needs_recovery === undefined ? undefined : (filesystem.needs_recovery ? t('tools.forensicRequired') : t('tools.forensicNotRequired')));
      html += item(t('tools.forensicLastMounted'), filesystem.last_mounted_at);
      html += item(t('tools.forensicLastWritten'), filesystem.last_written_at);
      html += item(t('tools.forensicLastChecked'), filesystem.last_checked_at);
      html += item(t('tools.forensicEncryption'), filesystem.cipher ? filesystem.cipher + (filesystem.cipher_mode ? ' · ' + filesystem.cipher_mode : '') : undefined);
      html += item(t('tools.forensicLuksVersion'), filesystem.luks_version);
      html += item(t('tools.forensicFeatures'), filesystem.features, true);
      html += '</div></div>';
    });
    html += '</div>';
  }
  
  // Content Analysis Section
  if (result.content_analysis) {
    html += '<div class="forensic-section">';
    html += '<h5>📁 ' + (t('tools.forensicContent') || 'Inhaltsanalyse') + '</h5>';
    html += '<div class="forensic-grid">';
    if (result.content_analysis.mount_point) {
      html += '<div class="forensic-item"><span class="forensic-label">Mount:</span> <span class="forensic-value">' + eh(result.content_analysis.mount_point) + '</span></div>';
    }
    if (result.content_analysis.total_items !== undefined) {
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.forensicTotalItems') + ':</span> <span class="forensic-value">' + eh(formatCountBreakdown(result.content_analysis.total_items, result.content_analysis.user_items)) + '</span></div>';
    }
    if (result.content_analysis.detected_os && result.content_analysis.detected_os.length > 0) {
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.forensicDetectedOS') + ':</span> <span class="forensic-value">' + eh(result.content_analysis.detected_os.join(', ')) + '</span></div>';
    }
    if (result.content_analysis.top_level && result.content_analysis.top_level.length > 0) {
      html += '<div class="forensic-item full-width"><span class="forensic-label">' + t('tools.forensicTopLevel') + ':</span></div>';
      html += '<div class="forensic-toplevel">' + result.content_analysis.top_level.map(f => '<span class="toplevel-item">' + eh(f) + '</span>').join('') + '</div>';
    }
    html += '</div></div>';
  }
  
  // Special Structures Section
  if (result.special_structures) {
    html += '<div class="forensic-section">';
    html += '<h5>🔎 ' + t('tools.forensicSpecial') + '</h5>';
    html += '<div class="forensic-grid">';
    for (let key in result.special_structures) {
      const value = result.special_structures[key];
      // special_partitions ist eine Liste von diskutil-Zeilen. Als blosses "✓"
      // ginge die eigentliche Information verloren.
      let shown;
      if (Array.isArray(value)) {
        shown = value.map(eh).join('<br>');
      } else if (typeof value === 'boolean') {
        shown = formatBool(value);
      } else {
        shown = eh(value);
      }
      html += '<div class="forensic-item"><span class="forensic-label">' + eh(fieldLabel(key)) + ':</span> <span class="forensic-value">' + shown + '</span></div>';
    }
    html += '</div></div>';
  }
  
  // Hardware Info Section
  if (result.hardware_info) {
    html += '<details class="forensic-section forensic-disclosure">';
    html += '<summary>🔧 ' + (t('tools.forensicHardwareInfo') || 'Hardware-Details') + '</summary>';
    html += '<div class="forensic-grid">';
    for (let key in result.hardware_info) {
      let value = result.hardware_info[key];
      if (typeof value === 'boolean') {
        value = formatBool(value);
      } else if (key.endsWith('_bytes')) {
        value = formatBytesExact(value);
      }
      html += '<div class="forensic-item"><span class="forensic-label">' + eh(fieldLabel(key)) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
    }
    html += '</div></details>';
  }
  
  // Controller Info Section
  if (result.controller_info) {
    html += '<details class="forensic-section forensic-disclosure">';
    html += '<summary>🎛️ ' + (t('tools.forensicController') || 'USB-Controller') + '</summary>';
    html += '<div class="forensic-grid">';
    for (let key in result.controller_info) {
      html += '<div class="forensic-item"><span class="forensic-label">' + eh(fieldLabel(key)) + ':</span> <span class="forensic-value">' + eh(result.controller_info[key]) + '</span></div>';
    }
    html += '</div></details>';
  }
  
  // Storage Info Section
  if (result.storage_info) {
    html += '<details class="forensic-section forensic-disclosure">';
    html += '<summary>💿 ' + (t('tools.forensicStorageInfo') || 'Speicher-Details') + '</summary>';
    html += '<div class="forensic-grid">';
    for (let key in result.storage_info) {
      let value = result.storage_info[key];
      // Byte-Felder mit exakter Zahl zeigen, sonst widerspricht der Wert dem Namen.
      if (key.includes('bytes')) {
        value = formatBytesExact(value);
      } else if (typeof value === 'boolean') {
        value = formatBool(value);
      }
      html += '<div class="forensic-item"><span class="forensic-label">' + eh(fieldLabel(key)) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
    }
    html += '</div></details>';
  }
  
  // MBR Analysis Section
  // Signatur und Gueltigkeit stehen bereits unter "Boot-Strukturen". Hier nur
  // noch die Partitionseintraege, sonst steht dieselbe Angabe zweimal auf der
  // Seite -- zuvor sogar in zwei verschiedenen Sprachen.
  const mbrEntries = result.mbr_analysis?.partition_entries;
  if (mbrEntries && mbrEntries.length > 0) {
    html += '<details class="forensic-section forensic-disclosure">';
    html += '<summary>📀 ' + (t('tools.forensicMbrAnalysis') || 'MBR-Analyse') + '</summary>';
    html += '<div class="forensic-partitions">';
    mbrEntries.forEach(p => {
      html += '<div class="forensic-partition">';
      html += '<strong>' + eh(t('tools.partition')) + ' ' + eh(p.number) + '</strong>';
      html += ' [' + eh(p.type_hex) + '] ' + eh(p.type_name);
      if (p.bootable) html += ' 🚀 Boot';
      html += '</div>';
    });
    html += '</div></details>';
  }
  
  // GPT Analysis Section
  if (result.gpt_analysis) {
    html += '<details class="forensic-section forensic-disclosure">';
    html += '<summary>📦 ' + (t('tools.forensicGptAnalysis') || 'GPT-Analyse') + '</summary>';
    html += '<div class="forensic-grid">';
    html += '<div class="forensic-item"><span class="forensic-label">' + eh(t('forensic.signature')) + ':</span> <span class="forensic-value">' + eh(result.gpt_analysis.gpt_signature) + '</span></div>';
    html += '<div class="forensic-item"><span class="forensic-label">' + eh(t('forensic.valid')) + ':</span> <span class="forensic-value">' + formatBool(result.gpt_analysis.valid_gpt) + '</span></div>';
    if (result.gpt_analysis.gpt_revision) {
      html += '<div class="forensic-item"><span class="forensic-label">Revision:</span> <span class="forensic-value">' + eh(result.gpt_analysis.gpt_revision) + '</span></div>';
    }
    html += '</div></details>';
  }
  
  // Filesystem Details Section
  if (result.filesystem_details) {
    html += '<div class="forensic-section">';
    html += '<h5>📁 ' + t('tools.forensicFsDetails') + '</h5>';
    html += '<div class="forensic-grid">';
    if (result.filesystem_details.total_file_count != null) {
      html += '<div class="forensic-item"><span class="forensic-label">' + t('forensic.files') + ':</span> <span class="forensic-value">' + eh(formatCountBreakdown(result.filesystem_details.total_file_count, result.filesystem_details.user_file_count)) + '</span></div>';
    }
    if (result.filesystem_details.directory_count != null) {
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.directories') + ':</span> <span class="forensic-value">' + eh(formatCountBreakdown(result.filesystem_details.directory_count, result.filesystem_details.user_directory_count)) + '</span></div>';
    }
    if (result.filesystem_details.hidden_files_count != null) {
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.hiddenFiles') + ':</span> <span class="forensic-value">' + eh(result.filesystem_details.hidden_files_count) + '</span></div>';
    }
    if (result.filesystem_details.symlink_count != null) {
      html += '<div class="forensic-item"><span class="forensic-label">Symlinks:</span> <span class="forensic-value">' + eh(result.filesystem_details.symlink_count) + '</span></div>';
    }
    if (result.filesystem_details.capacity_percent) {
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.capacity') + ':</span> <span class="forensic-value">' + eh(result.filesystem_details.capacity_percent) + '</span></div>';
    }
    if (result.filesystem_details.inode_usage_percent) {
      html += '<div class="forensic-item"><span class="forensic-label">' + t('tools.forensicInodeUsage') + ':</span> <span class="forensic-value">' + eh(result.filesystem_details.inode_usage_percent) + '</span></div>';
    }
    html += '</div>';
    
    // Largest files
    if (result.filesystem_details.largest_files && result.filesystem_details.largest_files.length > 0) {
      html += '<div class="forensic-subsection"><strong>' + (t('tools.forensicLargestFiles') || 'Größte Dateien') + ':</strong>';
      html += '<div class="forensic-filelist">';
      result.filesystem_details.largest_files.forEach(f => {
        const sizeFormatted = formatBytes(parseInt(f.size_bytes) || 0);
        html += '<div class="forensic-file-item"><span class="file-size">' + eh(sizeFormatted) + '</span> <span class="file-path">' + eh(f.path) + '</span></div>';
      });
      html += '</div></div>';
    }
    
    // File type distribution
    if (result.filesystem_details.file_type_distribution && result.filesystem_details.file_type_distribution.length > 0) {
      html += '<div class="forensic-subsection"><strong>' + (t('tools.forensicFileTypes') || 'Dateitypen') + ':</strong>';
      html += '<div class="forensic-types">';
      result.filesystem_details.file_type_distribution.forEach(ft => {
        html += '<span class="forensic-type-badge">' + eh(ft.extension) + ' (' + eh(ft.count) + ')</span>';
      });
      html += '</div></div>';
    }
    
    // Recently modified
    if (result.filesystem_details.recently_modified && result.filesystem_details.recently_modified.length > 0) {
      html += '<div class="forensic-subsection"><strong>' + (t('tools.forensicRecent') || 'Kürzlich geändert (7 Tage)') + ':</strong>';
      html += '<div class="forensic-filelist">';
      result.filesystem_details.recently_modified.forEach(f => {
        html += '<div class="forensic-file-item"><span class="file-path">' + eh(f) + '</span></div>';
      });
      html += '</div></div>';
    }
    html += '</div>';
  }
  
  // SMART Info Section - comprehensive display
  if (result.smart_info) {
    // SMART labels for translation
    const smartLabels = {
      // Device identification
      'model_family': t('tools.smartModelFamily'),
      'device_model': t('tools.smartDeviceModel'),
      'serial_number': t('tools.smartSerial'),
      'wwn_id': t('tools.smartWwnId'),
      'firmware_version': t('tools.smartFirmware'),
      'device_type': t('tools.smartDeviceType'),
      // Capacity and physical
      'capacity': t('tools.smartCapacity'),
      'logical_block_size': t('tools.smartLogicalBlockSize'),
      'physical_block_size': t('tools.smartPhysicalBlockSize'),
      'sector_size': t('tools.smartSectorSize'),
      'rotation_rate': t('tools.smartRotationRate'),
      'form_factor': t('tools.smartFormFactor'),
      // Interface
      'protocol': t('tools.smartProtocol'),
      'ata_version': t('tools.smartAtaVersion'),
      'sata_version': t('tools.smartSataVersion'),
      'interface_speed_max': t('tools.smartMaxSpeed'),
      'interface_speed_current': t('tools.smartCurrentSpeed'),
      // Status and capabilities
      'smart_supported': t('tools.smartSupported'),
      'smart_enabled': t('tools.smartEnabled'),
      'health_status': t('tools.smartHealthStatus'),
      'trim_supported': t('tools.smartTrimSupported'),
      'write_cache_enabled': t('tools.smartWriteCacheEnabled'),
      'read_lookahead_enabled': t('tools.smartReadLookaheadEnabled'),
      'ata_security_enabled': t('tools.smartSecurityEnabled'),
      'ata_security_frozen': t('tools.smartSecurityFrozen'),
      // Temperature (SCT)
      'temperature': t('tools.smartTemperature'),
      'sct_temperature_current': t('tools.smartTempCurrent'),
      'sct_temperature_lifetime_min': t('tools.smartTempLifetimeMin'),
      'sct_temperature_lifetime_max': t('tools.smartTempLifetimeMax'),
      'sct_temperature_op_limit': t('tools.smartTempOpLimit'),
      // Usage stats
      'power_on_hours': t('tools.smartPowerOnHours'),
      'power_cycle_count': t('tools.smartPowerCycleCount'),
      'total_data_written': t('tools.smartTotalWritten'),
      'total_data_read': t('tools.smartTotalRead'),
      // Self-test
      'self_test_status': t('tools.smartSelfTestStatus'),
      'self_test_short_minutes': t('tools.smartShortTestMinutes'),
      'self_test_extended_minutes': t('tools.smartExtendedTestMinutes'),
      // Error logs
      'error_log_count': t('tools.smartErrorLogCount'),
      'self_test_log_count': t('tools.smartSelfTestLogCount'),
      // SSD-specific
      'endurance_used_percent': t('tools.smartEnduranceUsed'),
      'spare_available_percent': t('tools.smartSpareAvailable'),
      'ssd_wear_level': t('tools.smartWearLevel'),
      'lifetime_remaining': t('tools.smartLifetime'),
      // Sector health
      'reallocated_sectors': t('tools.smartReallocatedSectors'),
      'pending_sectors': t('tools.smartPendingSectors'),
      'uncorrectable_sectors': t('tools.smartUncorrectableSectors'),
      'offline_uncorrectable': t('tools.smartOfflineUncorr'),
      // Other attributes
      'used_reserved_blocks': t('tools.smartReservedBlocks'),
      'program_fail_count': t('tools.smartProgramFail'),
      'erase_fail_count': t('tools.smartEraseFail'),
      'runtime_bad_blocks': t('tools.smartBadBlocks'),
      'uncorrectable_errors': t('tools.smartUncorrectable'),
      'ecc_error_rate': t('tools.smartEcc'),
      'crc_error_count': t('tools.smartCrc'),
      'unexpected_power_loss': t('tools.smartPowerLoss'),
      'bad_flash_blocks': t('tools.smartBadFlash'),
      'spin_up_time': t('tools.smartSpinUp'),
      'start_stop_count': t('tools.smartStartStop'),
      'seek_error_rate': t('tools.smartSeekError'),
      'head_flying_hours': t('tools.smartHeadHours'),
      'load_cycle_count': t('tools.smartLoadCycles'),
      // SD Card specific
      'manufacturer': t('tools.manufacturer'),
      'sd_spec_version': t('tools.sdSpecVersion'),
      'manufacturing_date': t('tools.manufacturingDate'),
      'source': t('tools.dataSource')
    };
    
    html += '<div class="forensic-section">';
    html += '<h5>🔬 ' + t('tools.forensicSmart') + '</h5>';
    
    // Device Info subsection
    html += '<div class="forensic-subsection"><strong>📱 ' + t('tools.forensicDeviceInfo') + ':</strong></div>';
    html += '<div class="forensic-grid">';
    const deviceFields = ['model_family', 'device_model', 'manufacturer', 'serial_number', 'firmware_version', 
                         'device_type', 'capacity', 'logical_block_size', 'physical_block_size',
                         'rotation_rate', 'form_factor'];
    
    const yesNo = (val) => val ? '✅ ' + t('common.yes') : '❌ ' + t('common.no');
    
    for (let key of deviceFields) {
      if (result.smart_info[key] !== undefined) {
        let value = result.smart_info[key];
        if (typeof value === 'boolean') {
          value = yesNo(value);
        }
        const label = smartLabels[key] || key.replace(/_/g, ' ');
        html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
      }
    }
    html += '</div>';
    
    // Interface Info subsection
    const interfaceFields = ['protocol', 'ata_version', 'sata_version', 'interface_speed_max', 'interface_speed_current'];
    const hasInterfaceData = interfaceFields.some(k => result.smart_info[k] !== undefined);
    if (hasInterfaceData) {
      html += '<div class="forensic-subsection"><strong>🔌 ' + t('tools.interface') + ':</strong></div>';
      html += '<div class="forensic-grid">';
      for (let key of interfaceFields) {
        if (result.smart_info[key] !== undefined) {
          let value = result.smart_info[key];
          const label = smartLabels[key] || key.replace(/_/g, ' ');
          html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
        }
      }
      html += '</div>';
    }
    
    // Capabilities subsection
    const capFields = ['smart_supported', 'smart_enabled', 'health_status', 'trim_supported', 
                      'write_cache_enabled', 'read_lookahead_enabled', 'ata_security_enabled', 'ata_security_frozen'];
    const hasCapData = capFields.some(k => result.smart_info[k] !== undefined);
    if (hasCapData) {
      html += '<div class="forensic-subsection"><strong>⚙️ ' + t('tools.capabilitiesStatus') + ':</strong></div>';
      html += '<div class="forensic-grid">';
      for (let key of capFields) {
        if (result.smart_info[key] !== undefined) {
          let value = result.smart_info[key];
          if (typeof value === 'boolean') {
            value = yesNo(value);
          }
          const label = smartLabels[key] || key.replace(/_/g, ' ');
          html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
        }
      }
      html += '</div>';
    }
    
    // Temperature subsection
    const tempFields = ['temperature', 'sct_temperature_current', 'sct_temperature_lifetime_min', 
                       'sct_temperature_lifetime_max', 'sct_temperature_op_limit'];
    const hasTempData = tempFields.some(k => result.smart_info[k] !== undefined);
    if (hasTempData) {
      html += '<div class="forensic-subsection"><strong>🌡️ Temperature:</strong></div>';
      html += '<div class="forensic-grid">';
      for (let key of tempFields) {
        if (result.smart_info[key] !== undefined) {
          let value = result.smart_info[key];
          const label = smartLabels[key] || key.replace(/_/g, ' ');
          html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
        }
      }
      html += '</div>';
    }
    
    // Usage Stats subsection
    const usageFields = ['power_on_hours', 'power_cycle_count', 'total_data_written', 'total_data_read',
                        'endurance_used_percent', 'spare_available_percent'];
    const hasUsageData = usageFields.some(k => result.smart_info[k] !== undefined);
    if (hasUsageData) {
      html += '<div class="forensic-subsection"><strong>📊 ' + t('tools.usageStatistics') + ':</strong></div>';
      html += '<div class="forensic-grid">';
      for (let key of usageFields) {
        if (result.smart_info[key] !== undefined) {
          let value = result.smart_info[key];
          const label = smartLabels[key] || key.replace(/_/g, ' ');
          html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
        }
      }
      html += '</div>';
    }
    
    // Self-test & Error Logs subsection
    const testFields = ['self_test_status', 'self_test_short_minutes', 'self_test_extended_minutes',
                       'error_log_count', 'self_test_log_count'];
    const hasTestData = testFields.some(k => result.smart_info[k] !== undefined);
    if (hasTestData) {
      html += '<div class="forensic-subsection"><strong>🧪 ' + t('tools.selfTestLogs') + ':</strong></div>';
      html += '<div class="forensic-grid">';
      for (let key of testFields) {
        if (result.smart_info[key] !== undefined) {
          let value = result.smart_info[key];
          const label = smartLabels[key] || key.replace(/_/g, ' ');
          html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
        }
      }
      html += '</div>';
    }
    
    // Sector Health subsection
    const sectorFields = ['reallocated_sectors', 'pending_sectors', 'uncorrectable_sectors', 'offline_uncorrectable'];
    const hasSectorData = sectorFields.some(k => result.smart_info[k] !== undefined);
    if (hasSectorData) {
      html += '<div class="forensic-subsection"><strong>💾 ' + t('tools.sectorHealth') + ':</strong></div>';
      html += '<div class="forensic-grid">';
      for (let key of sectorFields) {
        if (result.smart_info[key] !== undefined) {
          let value = result.smart_info[key];
          const label = smartLabels[key] || key.replace(/_/g, ' ');
          html += '<div class="forensic-item"><span class="forensic-label">' + eh(label) + ':</span> <span class="forensic-value">' + eh(value) + '</span></div>';
        }
      }
      html += '</div>';
    }
    
    // Full SMART Attributes Table (from attributes_table)
    if (result.smart_info.attributes_table && result.smart_info.attributes_table.length > 0) {
      html += '<div class="forensic-subsection"><strong>📋 ' + t('tools.fullSmartAttributes') + ':</strong></div>';
      html += '<div class="smart-attributes-table-container">';
      html += '<table class="smart-attributes-table">';
      html += '<thead><tr><th>ID</th><th>Attribute</th><th>Value</th><th>Worst</th><th>Thresh</th><th>Raw</th><th>Flags</th><th>Status</th></tr></thead>';
      html += '<tbody>';
      
      for (let attr of result.smart_info.attributes_table) {
        const isPrefailure = attr.prefailure === true;
        const rowClass = isPrefailure ? 'prefailure-warning' : '';
        const status = isPrefailure ? '⚠️ Pre-fail' : '✅ OK';
        
        html += '<tr class="' + rowClass + '">';
        html += '<td>' + eh(attr.id || '-') + '</td>';
        html += '<td>' + eh(attr.name || '-') + '</td>';
        html += '<td>' + eh(attr.value !== undefined ? attr.value : '-') + '</td>';
        html += '<td>' + eh(attr.worst !== undefined ? attr.worst : '-') + '</td>';
        html += '<td>' + eh(attr.threshold !== undefined ? attr.threshold : '-') + '</td>';
        html += '<td>' + eh(attr.raw_value !== undefined ? attr.raw_value : '-') + '</td>';
        html += '<td>' + eh(attr.flags || '-') + '</td>';
        html += '<td>' + status + '</td>';
        html += '</tr>';
      }
      
      html += '</tbody></table>';
      html += '</div>';
    }
    
    // Legacy attributes format (for backward compatibility)
    if (result.smart_info.attributes && Object.keys(result.smart_info.attributes).length > 0) {
      html += '<div class="forensic-subsection">';
      html += '<strong>📊 ' + (t('tools.smartAttributes') || 'SMART Attributes') + ':</strong>';
      html += '<div class="forensic-grid smart-attrs">';
      
      for (let attrKey in result.smart_info.attributes) {
        const attrLabel = smartLabels[attrKey] || attrKey.replace(/_/g, ' ');
        html += '<div class="forensic-item"><span class="forensic-label">' + eh(attrLabel) + ':</span> <span class="forensic-value">' + eh(result.smart_info.attributes[attrKey]) + '</span></div>';
      }
      
      html += '</div></div>';
    }
    
    // Data source
    if (result.smart_info.source) {
      html += '<div class="forensic-item forensic-source-note"><span class="forensic-label">' + t('tools.dataSource') + ':</span> <span class="forensic-value">' + eh(result.smart_info.source) + '</span></div>';
    }
    
    html += '</div>';
  }
  
  // Sector Checksums Section
  if (result.sector_checksums) {
    html += '<details class="forensic-section forensic-disclosure">';
    html += '<summary>🔐 ' + t('tools.forensicChecksums') + '</summary>';
    html += '<div class="forensic-grid">';
    if (result.sector_checksums.mbr_md5) {
      html += '<div class="forensic-item full-width"><span class="forensic-label">MD5:</span> <span class="forensic-value mono">' + eh(result.sector_checksums.mbr_md5) + '</span></div>';
    }
    if (result.sector_checksums.mbr_sha256) {
      html += '<div class="forensic-item full-width"><span class="forensic-label">SHA256:</span> <span class="forensic-value mono">' + eh(result.sector_checksums.mbr_sha256) + '</span></div>';
    }
    html += '</div></details>';
  }
  
  // Raw Header Hex Dump Section
  if (result.raw_header_hex) {
    html += '<details class="forensic-section forensic-disclosure">';
    html += '<summary>🔢 ' + (t('tools.forensicRawHeader') || 'Raw Header (Hex)') + '</summary>';
    html += '<pre class="forensic-hexdump">' + eh(result.raw_header_hex) + '</pre>';
    html += '</details>';
  }
  
  html += '</div>';
  

  const scan = result.filesystem_details?.scan_quality || result.filesystem_details?.quality;
  if (scan) {
    const warning = scan.complete ? t('tools.scanComplete') : t('tools.scanIncomplete');
    const details = '<aside class="forensic-acquisition">' + eh(warning) +
      ' · ' + eh(t('tools.scanErrors')) + ': ' + eh(scan.error_count ?? 0) +
      ' · ' + eh(t('tools.scanSkippedMounts')) + ': ' + eh(scan.skipped_mounts ?? 0) +
      '<p>' + eh(t('tools.scanListLimit')) + '</p>' +
      (scan.errors || []).map(e => '<p>' + eh(e) + '</p>').join('') +
      (scan.type_overflow ? '<p>' + eh(t('tools.scanTypeOverflow')) + '</p>' : '') + '</aside>';
    html = html.replace('<div class="forensic-report">', '<div class="forensic-report">' + details);
  }
  return html;
  };
}

export function standaloneReport({ result, render, styles, title, language }) {
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  return '<!DOCTYPE html><html lang="' + escape(language) + '"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + escape(title) + '</title><style>' + styles + '</style></head>' +
    '<body class="forensic-export">' + render(result) + '</body></html>';
}
