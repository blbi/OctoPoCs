import angr
import claripy
import sys
import logging
import time
l = logging.getLogger(__name__)

print(__name__)
def findLatestOtherChild(path):
    for item in path:
        if str(type(item)) == "<class 'list'>":
            enter_addr = path[path.index(item)-1]
            
            assert enter_addr in item
            for addr in item:
                if addr != enter_addr:
                    remain_addr = addr
            break
        
    if str(type(remain_addr)) == "<class 'list'>":
        print("[*]ERROR - followPath@findLatestOtherChild : Something go wrong!")
        return False

    return remain_addr, enter_addr

def findBranchIndex(path, branch_list, index):
    bindex = 0
    pindex = 0
    for item in path:
        if (type(item) is list) \
            and (item == [s.addr for s in branch_list[bindex][1]]) \
            and (path[path.index(item)+1] == branch_list[bindex][0]):
            if bindex < index:
                bindex += 1
                continue
            elif bindex == index:
                pindex = path.index(item)
                break

    assert pindex != 0
    return pindex
                

##have to compare incorrect branch by address
def findOtherChild(path, branch_index):
    enter_addr = path[branch_index-1]
    assert enter_addr in path[branch_index]
    for addr in path[branch_index]:
        if addr != enter_addr:
            other_addr = addr

    return other_addr, enter_addr
    
##nononono have to find exact rolling point!! it check just two branch
def rollBackPath(path, branch_index):
    for i in range(branch_index):
        del path[0]

    return path

def findDirection(base_path, addr, idx):
    path = base_path[idx:]
    if addr in path:
        idx = path.index(addr)+1+idx
        return base_path[idx], idx

    elif addr in base_path[:idx]:
        tempidx = base_path[:idx].index(addr)+1
        return base_path[tempidx], idx

    else:
        return False

def countBranchForLoop(real_path, branch):
    if real_path.count(branch) >= 50:
        state_addr = real_path[real_path.index(branch)-1]
        return state_addr
    else:
        return False
        

def explore(proj, simgr, newpoc, epaddr, base_path_o, e_count, primitive, prim_fd, old_bytes, c_flag):
    s_t = time.time()
    #base_path should be list of hex value
    base_path = []
    try:
        for i in base_path_o[1]:
            base_path.append(int(i.split('(')[0].split(' ')[1],16))
    except:
        for i in base_path_o[1]:
            base_path.append(int(i,16))
    base_path.reverse()

    real_path = [] #state addr
    prev_state = 0
    initial_state = [0,0] #parent addr, childs state
    prev_branch = initial_state[:]
    incorrect_branch = []
    dead_state_addr = 0
    follow_idx = 0
    ehit = 0

    while True:
        while len(simgr.active) == 1:
            if simgr.active[0].addr == epaddr:
                e_t = time.time()
                print(e_t - s_t)
                print("[+]find vuln func!")
                #!!!!!!!!!!!temp test!!!!!!!!!
                return 0
                ehit += 1
                if ehit >= e_count:
                    if (c_flag):
                        current_offset = simgr.active[0].solver.eval(simgr.active[0].posix.get_fd(0x3).read_pos)
                        gap = prim_fd[-1] - current_offset
                        print('[+]reach ep!')
                        print('[+] current pos :',hex(current_offset))
                        print('[+] gap :',hex(gap))

                        for offset in primitive:
                            if (offset >= prim_fd[-1]):
                                data, size, npos = simgr.active[0].fs.get(newpoc).read(offset - gap, 1)
                                simgr.active[0].solver.add(data == old_bytes[offset])
                                print(offset,':',old_bytes[offset])
                        print('[+] write data from',hex(prim_fd[-1]-gap),'to end')
                        tt = prev_state.fs.get(newpoc).concretize()
                        print(tt)

                    print("done explore!!")
                    return simgr
                else:
                    if (c_flag):
                        current_offset = prev_state.solver.eval(prev_state.posix.get_fd(0x3).read_pos)
                        gap = prim_fd[ehit-1] - current_offset
                        print('[+]reach ep!')
                        print('[+] current pos :',hex(current_offset))
                        print('[+] gap :',hex(gap))

                        for offset in primitive:
                            if (offset >= prim_fd[ehit-1]) and (offset < prim_fd[ehit]):
                                data, size, npos = prev_state.fs.get(newpoc).read(offset - gap,1)
                                prev_state.solver.add(data == old_bytes[offset])
                        print('[+] write data from',hex(prim_fd[ehit-1]-gap),'to',hex(prim_fd[ehit]-gap))
                        tt = prev_state.fs.get(newpoc).concretize()
                        print(tt)
                        simgr = proj.factory.simulation_manager(prev_state)
                        simgr.step()
                        simgr.step()
                        print('[+] fill prim constraints')
                    #when c_flag(combine flag) is set,
                    #set constraints of primitives
                    #at that simgr pos position
                    else:
                        #when c_flag is not set
                        #execute normally
                        real_path.insert(0, simgr.active[0].addr)
                        prev_state = simgr.active[0]
                        #print('[', simgr.active[0].addr,']')
                        simgr.step()

            else:
                real_path.insert(0,simgr.active[0].addr)
                prev_state = simgr.active[0]
                #print(simgr.active)
                #l.error('[',simgr.active[0].addr,']')
                simgr.step()
        
        if len(simgr.active) == 2:
            
            #when branch is loop
            #print("counter branch!!")
            #print(simgr.active)
            if (prev_branch != initial_state) and (str(simgr.active) == str(prev_branch[1])):
                exit_addr = findLatestOtherChild(real_path)[0]
                past_loop_state_addr = countBranchForLoop(real_path, [x.addr for x in simgr.active])
                #the order is important! exit addr before insert real path
                real_path.insert(0,[x.addr for x in simgr.active])                
                prev_branch[0] = prev_state.addr
                #prev_branch[1] = simgr.active[:]

                incorrect_branch.insert(0,[prev_state.addr, simgr.active[:]])
                if (past_loop_state_addr):
                    #exit loop
                    simgr.move(from_stash='active', to_stash='trash', filter_func = lambda s: s.addr == past_loop_state_addr)
                else:
                    #repeat loop again
                    simgr.move(from_stash='active', to_stash='trash', filter_func = lambda s: s.addr == exit_addr)
                #simgr.move(from_stash='active', to_stash='trash', filter_func = lambda s: s.addr != exit_addr)

            #when branch is not direct loop (it can be loop in large range)
            else:
                prev_branch[0] = prev_state.addr
                prev_branch[1] = simgr.active[:]

                past_loop_state_addr = countBranchForLoop(real_path, [x.addr for x in simgr.active])     
                past_loop_state_addr = False
                real_path.insert(0,[x.addr for x in simgr.active])

                if (past_loop_state_addr):
                    incorrect_branch.insert(0,[prev_state.addr, simgr.active[:]])
                    simgr.move(from_stash='active', to_stash='trash', filter_func = lambda s: s.addr == past_loop_state_addr) 
                
                else:
                    direction = findDirection(base_path, prev_state.addr, follow_idx)
                    
                    if (direction):
                        #print("go to specific!")
                        follow_idx = direction[1]
                       
                        simgr.move(from_stash='active', to_stash='trash', filter_func = lambda s: s.addr != direction[0])

                    else:
                        print("[+]!!!!something go wrong!!!!")
                        incorrect_branch.insert(0,[prev_state.addr, simgr.active[:]])

                        ad1 = simgr.active[0].addr
                        ad2 = simgr.active[1].addr
                        if (ad1 - prev_state.addr) > (ad2 - prev_state.addr):
                            simgr.move(from_stash='active', to_stash='trash', filter_func = lambda s: s.addr != ad2)
                        else:
                            simgr.move(from_stash='active', to_stash='trash', filter_func = lambda s: s.addr != ad1)
                        
            simgr.drop(stash='trash')
            assert len(simgr.active) == 1
                   

        elif len(simgr.active) == 0:
            print(simgr.active)
            redead_flag = 0
            #if len(incorrect_branch) == 0:
            #    prev_incorrect_branch = prev_branch
            #else:
            #    prev_incorrect_branch = incorrect_branch[-1]
            assert len(incorrect_branch) > 0
            prev_incorrect_branch = incorrect_branch[0][:]

            ####find index first, and pass the index data to findotherchild, rollbackpath function
            branch_index = findBranchIndex(real_path, incorrect_branch, 0)
            (other_addr, enter_addr) = findOtherChild(real_path, branch_index)
            
            if other_addr == dead_state_addr:
                #redead_flag = 1
                prev_incorrect_branch = incorrect_branch[1][:]
                branch_index = findBranchIndex(real_path, incorrect_branch, 1)
                (other_addr, enter_addr) = findOtherChild(real_path, branch_index)
                dead_state_addr = enter_addr
                del incorrect_branch[0]
            
            else:

                dead_state_addr = enter_addr

            for state in prev_incorrect_branch[1]:
                if state.addr == other_addr:
                    other_state = state

            assert other_state != None
            
            simgr = proj.factory.simulation_manager(other_state)
            real_path = rollBackPath(real_path, branch_index)

#have to change variable name findbranchindex -> findpathindexofbranch
# branchindex -"> pathinex


