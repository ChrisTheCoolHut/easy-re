import argparse

parser = argparse.ArgumentParser(description="Quick Concolic Analysis")
parser.add_argument("file", help="Binary File")
parser.add_argument("-s", "--start", help="Where to start analyzing from")
parser.add_argument("-e", "--end", help="Where to stop analyzing")
parser.add_argument(
    "-a",
    "--args",
    help="Solve for a symbolic arg (optional)",
    default=False,
    action="store_true",
)
parser.add_argument(
    "-x", "--avoid", help="Where to avoid analysis, eg 0x12345678,0x12345678"
)
parser.add_argument("-z", "--xref", help="String to xref and find")

avoidList = []

args = parser.parse_args()

if args.avoid:
    avoidList = [int(x, 16) for x in args.avoid.split(",")]

if args.file is None or args.file is "":
    print("[-] Missing file to analyze")
    exit(0)

if args.xref:
    import r2pipe
    import json
    from base64 import b64decode

    r2 = r2pipe.open(args.file)
    r2.cmd("aaa")
    base_addr = json.loads(r2.cmd("ij"))["bin"]["baddr"]
    res = json.loads(r2.cmd("izj"))

    string_res = [
        x for x in res if args.xref.encode().lower() in b64decode(x["string"]).lower()
    ]

    v_addr = string_res[0]["vaddr"]
    location = json.loads(r2.cmd("axtj @ {}".format(v_addr)))
    offset = int(location[0]["from"]) - int(base_addr)

    print("Found xref to strings at offset : {}".format(hex(offset)))


# Load imports after displaying help to get a fast menu
import angr, claripy

p = angr.Project(args.file, load_options={"auto_load_libs": False})
argv1 = claripy.BVS("argv1", 8 * 100)  # Setting to 100 max chars for argument
state = None
if args.args:
    state = p.factory.entry_state(args=[args.file, argv1])
else:
    if args.start:
        state = p.factory.blank_state(addr=int(args.start, 0))
    else:
        state = p.factory.entry_state()

if args.xref:
    angr_base_addr = p.loader.main_object.mapped_base
    string_xref = angr_base_addr + offset
    args.end = string_xref
else:
    args.end = int(args.end, 0)

print(
    "[+] Analyzing {} from {} to {} avoiding {}".format(
        args.file, args.start, hex(args.end), args.avoid
    )
)


pg = p.factory.simgr(state)
pg.explore(find=args.end, avoid=avoidList)
if len(pg.found):
    print("[+] Found path(s)")
    for path in pg.found:
        print("[+] STDIN: {}".format(path.posix.dumps(0)))
        print("[+] STDOUT: {}".format(path.posix.dumps(1)))
        if args.args:
            print("[+] argv1: {}".format(path.solver.eval(argv1, cast_to=bytes)))
