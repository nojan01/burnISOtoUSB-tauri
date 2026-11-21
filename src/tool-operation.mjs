// Reserve synchronously, including time spent in confirmation/password dialogs.
export function createToolOperation(onChange) {
  let busy = false;
  return {
    get busy() { return busy; },
    async run(action) {
      if (busy) return;
      busy = true;
      try {
        onChange();
        await action();
      } finally {
        busy = false;
        onChange();
      }
    }
  };
}
