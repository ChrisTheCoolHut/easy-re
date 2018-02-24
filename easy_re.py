import argparse
parser = argparse.ArgumentParser(description="Quick Concolic Analysis")
parser.add_argument('-f', '--file', help='Binary File')
parser.add_argument('-s', '--start', help='Where to start analyzing from')
parser.add_argument('-e', '--end', help='Where to stop analyzing')
parser.add_argument('-a', '--args', help='Solve for a symbolic arg (optional)',default=False,action='store_true')
parser.add_argument('-x','--avoid',help='Where to avoid analysis, eg 0x12345678,0x12345678')

avoidList = []

args = parser.parse_args()

if args.avoid:
    avoidList = [int(x,16) for x in args.avoid.split(',')]

if args.file is None or args.file is '':
    print("[-] Missing file to analyze")
    exit(0)

#Load imports after displaying help to get a fast menu
import angr, claripy 
p = angr.Project(args.file,load_options={"auto_load_libs":False})
argv1 = claripy.BVS("argv1", 8 * 100) # Setting to 100 max chars for argument
state = None
if args.args:
    state = p.factory.path(args=[args.file,argv1])
else:
    state = p.factory.blank_state(addr=int(args.start,0))

print("[+] Analyzing {} from {} to {} avoiding {}".format(args.file,args.start,args.end,args.avoid))

pg = p.factory.simgr(state)
pg.explore(find=int(args.end,0),avoid=avoidList)
if len(pg.found):
    print("[+] Found path(s)")
    for path in pg.found:
        try:
            print("[+] STDIN: {}".format(path.state.posix.dumps(0)))
            print("[+] STDOUT: {}".format(path.state.posix.dumps(1)))
            if args.args:
                print("[+] argv1: {}".format(path.state.se.any_str(argv1)))
        except:
            print("[-] Error printing data. Found paths likely unsatisfiable")
