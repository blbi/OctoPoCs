import angr
import claripy
import logging
import sys
import os
import findPath
import followPath


#=====================================
# arg1 = cmd                         #
# arg2 = ep                          #
# arg3 = e_count                     #
# arg4 = oldpoc                      #
# arg5 = primitive                   #
# arg6 = prim_fd
#=====================================


def makeSimfile(oldpoc, newpoc):
    symsize = claripy.BVS('mysize', 64)
    #filesize = os.path.getsize(oldpoc)
    #filedata = claripy.BVS('filedata', (filesize)*8)
    simfile = angr.SimFile(newpoc, size=symsize)
    return simfile

def makeSimulator(argv, newpoc, simfile, oldpoc, ep, primitive, prim_fd, c_flag):
    proj = angr.Project(argv[0])
    
    state = proj.factory.entry_state(args = argv, concrete_fs = True)
    state.fs.insert(newpoc, simfile)
   
    with open(oldpoc, 'rb') as f:
        old_bytes = f.read()
    
    with open(primitive) as f:
        prim_list = [int(x,16) for x in f.read().split(',')]

    #if (c_flag):
   #     for offset in prim_list:
   #         if offset >= prim_fd[0]:
   #             continue

   #         value = old_bytes[offset]
   #         data, actual_size, npos = simfile.read(offset,1)
   #         state.solver.add(data == value)

    #else:
   #     for offset in prim_list:
   #         value = old_bytes[offset]
   #         data, actual_size, npos = simfile.read(offset,1)
   #         state.solver.add(data == value)

    simgr = proj.factory.simulation_manager(state)
    
    return proj, simgr, state, old_bytes, prim_list, simfile


if __name__ == '__main__':
    #==set arguments==
    cmd = sys.argv[1]
    ep = sys.argv[2]
    e_count = sys.argv[3]
    oldpoc = sys.argv[4]
    primitive = sys.argv[5]
    prim_fd = sys.argv[6]
    stacknum = sys.argv[7]
    c_flag = sys.argv[8]
    newpoc = sys.argv[9]

    argv = cmd.split(' ')

    simfile = makeSimfile(oldpoc, newpoc)
    cfg = findPath.makeCFG(argv, newpoc, simfile, stacknum)
    basePath = findPath.extractPath(cfg, ep, e_count, c_flag)

#explore with basePath
    (proj, simgr, state, old_bytes, prim_list, simfile) = makeSimulator(argv, newpoc, simfile, oldpoc, ep, primitive, prim_fd, c_flag)
    epaddr = cfg.kb.functions.function(name=ep).addr

    simgr = followPath.explore(proj, simgr, newpoc, epaddr, basePath, e_count, prim_list, prim_fd, old_bytes, c_flag)


    simfile.concretize()




#make proj for CFG
#proj without shared lib & with simfile
#generate CFG


#make proj for explore
#proj with shared lib & with simfile


