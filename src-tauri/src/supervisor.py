# Kept outside worker.py so unit tests can import the I/O algorithms directly.
if __name__ == '__main__':
    import selectors
    import signal
    import json
    cfg = json.loads(sys.argv[1])
    child = os.fork()
    if child == 0:
        os.setpgid(0, 0)
        try:
            worker(cfg)
            print('DONE', flush=True)
        except BaseException as exc:
            print('ERROR: %s' % exc, file=sys.stderr, flush=True)
            os._exit(1)
        os._exit(0)
    try:
        os.setpgid(child, child)
    except ProcessLookupError:
        pass
    selector = selectors.DefaultSelector()
    selector.register(0, selectors.EVENT_READ)
    pending = b''
    cancelled = False
    while True:
        pid, status = os.waitpid(child, os.WNOHANG)
        if pid:
            # Also reap/stop any grandchildren left by a failed decoder/helper.
            try: os.killpg(child, signal.SIGKILL)
            except ProcessLookupError: pass
            sys.exit(130 if cancelled else (os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1))
        if selector.select(0.1):
            data = os.read(0, 4096)
            pending += data
            lines = pending.split(b'\n')
            pending = lines.pop()
            # A cached sudo ticket can leave the password line here. Ignore it.
            if not data or b'CANCEL' in lines:
                cancelled = True
                try: os.killpg(child, signal.SIGKILL)
                except ProcessLookupError: pass
                selector.unregister(0)
