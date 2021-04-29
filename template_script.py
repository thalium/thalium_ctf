from pwn import gdb, context, log, ELF, remote, process, p64, u64
from os import listdir, path
import sys

# Specify the default path of library (use ldd on a binary if needed)
PATH_LIBS = "/usr/lib64/" 


def set_context32():
    context.arch = "i386"  # amd64
    context.bits = 32
    context.endian = "little"
    context.os = "linux"
    context.log_level = "info"
    context.terminal = ["gnome-terminal", "-x", "bash", "-c"]


def set_context64():
    context.arch = "amd64"  # amd64
    context.bits = 64
    context.endian = "little"
    context.os = "linux"
    context.log_level = "info"
    context.terminal = ["gnome-terminal", "-x", "bash", "-c"]


class Mode:
    DEBUG = "-d"
    REMOTE = "-r"
    LIBC = "-libc"


def usage():
    print("Usage in default mode: ./path_to_bin/bin")
    print("Usage in debug mode: -d ./path_to_bin/bin")
    print(
        "Usage with custom libc: -libc VERSION\nLibc must be in %s\nYou can check https://github.com/niklasb/libc-database to find libc binaries.\nYou can check https://github.com/skysider/pwndocker to find how to run with other custom libraries"
        % PATH_LIBS
    )

    print(
        "Usage in remote mode: -r host port ./path_to_bin/bin (*./path_to_libc/libc <- optional)"
    )
    exit()


def get_PIE(proc):
    memory_map = open("/proc/{}/maps".format(proc.pid), "rb").readlines()
    for line in memory_map:
        if sys.argv[1][2:].encode() in line.split(b"-")[-1]:
            return int(line.split(b"-")[0], 16)
    else:
        return 0


def add_bps(r, bps, elf):
    script = "continue\n"
    script = ""

    if elf.pie:
        PIE = get_PIE(r)
    else:
        PIE = 0

    for x in bps:
            script += "b *0x%x\n" % (PIE + x)
    return script


def debug(r, bps, elf):
    script = (
        "set verbose on\n"  # set debug-file-directory /home/user/libs/glibc-2.27/debug
    )
    script += add_bps(r, bps, elf)
    print(script)
    gdb.attach(r, gdbscript=script)


def myExit(msg):
    log.warning(msg)
    exit()


def main():

    if len(sys.argv) < 2:
        usage()
    binary = sys.argv[1]
    try:
        elf = ELF(binary)
    except:
        myExit("Problem with binary path " + binary)

    ldPath = None
    libc = None
    libcPath = None
    DEBUG = False
    REMOTE = False

    env = {}
    i = 2
    while i < len(sys.argv):
        opt = sys.argv[i]
        if opt == Mode.DEBUG:
            log.debug("Enable gdb mode")
            DEBUG = True
            i += 1
        elif opt == Mode.REMOTE:
            try:
                host = sys.argv[i + 1]
                port = sys.argv[i + 2]
            except:
                myExit("Problem with -r HOST PORT")
            log.debug("Enable remote connection to ", host, port)
            REMOTE = True
            i += 3

        elif opt == Mode.LIBC:
            try:
                libcVersion = sys.argv[i + 1]
            except:
                myExit("Problem with -l PathToLibC")

            log.debug("Set Library version to", libcVersion)
            # PATH_CUSTOM_GLIBC = PATH_GLIBC % libcVersion

            for file in listdir(PATH_LIBS):

                if file.startswith("ld") and libcVersion in file:
                    ldPath = path.join(PATH_LIBS, file)
                if file.startswith("libc") and libcVersion in file:
                    libcPath = path.join(PATH_LIBS, file)

            # libcPath = "/lib/x86_64-linux-gnu/libc-2.27.so"

            env = {"LD_PRELOAD": libcPath}

            libc = ELF(libcPath)
            i += 2

        else:
            myExit("Unknown option only -d -l -ld -r")

    if not libc:
        libc = elf.libc
    if REMOTE:
        r = remote(host, int(port))

    else:
        if ldPath is None:
            r = process(binary, env=env)
        else:
            r = process([ldPath, binary], env=env)
        if DEBUG:
            # Example
            # bp = [elf.sym["malloc"]]
            # bp = ["malloc"]

            debug(r, bp, elf)
    exploit(r, elf, libc)


def exploit(p, elf, libc):

    # Filled this function
    p.interactive()


if __name__ == "__main__":
    # Select context 32 or 64 bits
    set_context64()
    main()
