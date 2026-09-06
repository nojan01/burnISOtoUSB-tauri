import { createForensicRenderer } from '../src/forensic-report.mjs';
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const render = createForensicRenderer({
  t: key => key, escapeHtml, forensicValue: v => v ?? '—',
  forensicItem: (label, value) => `<div class="forensic-item">${escapeHtml(label)}: ${escapeHtml(value)}</div>`,
  formatBytes: v => `${v} B`, formatBytesExact: v => `${v} B`,
  formatCountBreakdown: v => String(v), formatGptPartitions: () => [],
  fieldLabel: v => v, formatBool: v => String(v), translateLimitation: v => v
});
export const fixture = {
  disk_id:'disk99', timestamp:'2026-01-01', disk_info:{media_name:'<script>bad()</script>',disk_size:'4 GB'},
  analysis_quality:{mode:'read_only',sources:['metadata'],limitations:[]},
  boot_info:{has_gpt:true,has_efi:true}, partitions:[],
  mbr_analysis:{mbr_signature:'55AA',valid_mbr:true,partition_entries:[]},
  gpt_analysis:{gpt_signature:'EFI PART',valid_gpt:true},
  filesystem_details:{total_file_count:0,user_file_count:0,directory_count:0,user_directory_count:0,symlink_count:0,
    hidden_files_count:0,largest_files:[{size_bytes:131,path:'/a\nb<img>.txt'}],
    file_type_distribution:[{extension:'txt',count:1}],recently_modified:['/a\nb<img>.txt'],
    scan_quality:{complete:false,error_count:1,errors:['<Permission denied>'],skipped_mounts:1}},
  smart_info:{health_status:'PASSED',smart_available:true}, sector_checksums:{mbr_sha256:'123'},raw_header_hex:'00 <bad>'
};


