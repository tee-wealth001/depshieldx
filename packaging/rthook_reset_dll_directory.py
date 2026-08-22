"""PyInstaller runtime hook -- runs after the frozen bootloader's own
startup (so depshieldx's own bundled DLLs, e.g. vcruntime140.dll, have
already loaded successfully) but before any of depshieldx's own code,
including every subprocess call to an external toolchain, runs.

Confirmed directly against a real Windows release binary and a series of
minimal, isolated repro builds: PyInstaller's onefile bootloader sets a
process-wide DLL search directory pointing at its own extraction
directory (sys._MEIPASS) -- confirmed NOT via the PATH environment
variable (a real, direct check of os.environ['PATH'] from inside a
frozen process shows no _MEIPASS entry at all, and passing subprocess.run()
an entirely empty PATH does not fix the bug either, ruling out every
environment-variable-based explanation). That process-wide DLL search
directory is what a real external toolchain launched via subprocess.run()
-- confirmed with composer -> php.exe -- picks up: PHP finds
depshieldx's own bundled vcruntime140.dll (an older version than PHP's
own build needs) from inside _MEIPASS instead of the real, compatible,
newer one already present in the target system's own System32, and
refuses to start at all ("VCRUNTIME140.dll' 14.34 is not compatible with
this PHP build linked with 14.44").

SetDllDirectoryW(None) resets that process-wide search directory to
empty, confirmed directly this fully resolves the real repro end to end
while leaving depshieldx's own already-completed startup untouched (its
own bundled DLLs are already loaded into memory by the time this hook
runs) -- every subsequent external toolchain subprocess call falls back
to Windows' own standard DLL search order instead, which correctly finds
a system-installed vcruntime140.dll when one is present.

A prior attempt at this fix (stripping sys._MEIPASS out of PATH before
handing subprocess.run() its own env=) did not work -- confirmed
directly, since the real mechanism was never PATH-based -- and is kept
only as harmless, no-op-in-practice defense in depth for any other,
genuinely PATH-based leak.
"""

import sys

if sys.platform == "win32":
    import ctypes

    ctypes.windll.kernel32.SetDllDirectoryW(None)
