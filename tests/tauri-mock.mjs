// Browser-only UI smoke harness. No native IPC, disks, secrets or networking.
import { fixture } from './forensic-fixture.mjs';
const listeners = new Map();
const emit = (name, payload) => listeners.get(name)?.({payload});
async function diagnose(command, args) {
  const speed = command === 'diagnose_speed_test';
  const sampled = !speed && args.sampled;
  const blocks = args.profile === 'detailed' ? [1, 4, 16] : [8];
  const details = speed ? {
    kind:'speed', profile:args.profile, complete:true, success:true,
    speed_results:blocks.map(b => ({block_bytes:b*1048576,write_bytes:104857600,read_bytes:104857600,
      write_seconds:10,read_seconds:5,write_mib_s:10,read_mib_s:20})),
    read_mib_s:20,write_mib_s:10
  } : {kind:sampled?'sample':'surface',sampled,complete:true,success:true,bytes_checked:134217728,
    device_bytes:4000000000,coverage_percent:3.3554432,unreadable_bytes:0,retry_count:0,bad_ranges:[]};
  emit('operation_start', 1);
  emit('diagnose_progress', {operation_id:1,percent:50,phase:speed?'write':'reading',
    sectors_checked:1024,errors_found:0,read_speed_mbps:20,write_speed_mbps:10,
    details:{...details,target_bytes:134217728,bytes_checked:67108864,eta_seconds:5}});
  await new Promise(resolve => setTimeout(resolve, 600));
  return {success:true,total_sectors:7812500,sectors_checked:262144,errors_found:0,
    bad_sectors:[],read_speed_mbps:20,write_speed_mbps:speed?10:0,message:'Mock',details};
}
const appWindow = {
  setProgressBar: async () => {}, onResized: async () => () => {}, onMoved: async () => () => {},
  outerSize: async () => ({width:900,height:900}), outerPosition: async () => ({x:0,y:0}), scaleFactor: async () => 1
};
window.__TAURI__ = {
  core: { Channel: class { constructor(callback) { this.callback = callback; } }, invoke: async (command, args = {}) => {
    if (command === 'burn_iso') {
      const scenario = new URL(window.parent.location.href).searchParams.get('burn') || 'mount';
      emit('operation_start', 1);
      emit('burn_phase', 'writing');
      if (args.verify) emit('burn_phase', 'verifying');
      await new Promise(resolve => setTimeout(resolve, 400));
      if (scenario === 'io-error') throw new Error('Verifizierung: 1 fehlerhafter Block (simuliert)');
      emit('burn_phase', 'finalizing');
      return {written:true,verified:args.verify,warning:scenario === 'success' ? null : {
        action:args.eject?'eject':'mount',detail:args.eject?'Resource busy (simuliert)':'Failed to find disk /dev/disk99 (simuliert)'
      }};
    }
    if (['diagnose_speed_test','diagnose_surface_scan'].includes(command)) return diagnose(command,args);
    if (command === 'list_disks') return [{id:'disk99',name:'Disposable Test Fixture',size:'4 GB',bytes:4000000000}];
    if (command === 'get_disk_info') return 'Test fixture (no device access)';
    if (command === 'forensic_analysis') return structuredClone(fixture);
    if (command === 'check_dependencies') return {python3:true,xz:true,smartctl:true,all_installed:true};
    if (command === 'check_paragon_drivers') return {ntfs:false,extfs:false};
    if (command === 'get_smart_data') return {available:false};
    return null;
  }},
  event: {listen: async (name, callback) => {listeners.set(name,callback); return () => listeners.delete(name);}},
  dialog: {open: async () => '/test-fixture/no-native-access.img', save: async () => null, message: async () => {}, ask: async () => false},
  window: {getCurrentWindow: () => appWindow, ProgressBarStatus: {None:'none',Normal:'normal'}},
  app: {getVersion: async () => '1.4.15'}, notification: {isPermissionGranted: async () => true,sendNotification: async () => {}}
};
