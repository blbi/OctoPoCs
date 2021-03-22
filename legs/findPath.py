import angr
import claripy
import sys
import logging
from termcolor import colored

#==set global variables==
f = open("temppath",'w')
node_list = []
re = 0
vuln_hit = 0
main_hit = 0
findmax_flag = 0
base_path = [0,0] #recur, addr list
no_pre = []


#==find entry point of cfg recursively==
def findorigin(node, entry, epaddr, e_count, c_flag):
    global node_list
    global re
    global vuln_hit
    global main_hit
    global findmax_flag
    global base_path
    global f
    global no_pre
    
    #if find enough, just return
    if findmax_flag == 1:
        return

    node_list.append(str(node.block_id))
    f.write(str(node.block_id)+"\n")
    re += 1
    if node.addr == epaddr:
        f.write("reach to ep!!\n")
        print("reach to ep!")
        vuln_hit+=1
    
    #f.write("["+str(hex(node.addr))+"]\n")
    #if find entry point
    if node.addr == entry:
        #print('find main addr')
        if(c_flag):
        #when it doesn't visit ep sufficiently, just return
            if vuln_hit < e_count:
                re -= 1
                del node_list[-1]
                return
        

        #if it find correct path, store the path
        #print("find full path")
        f.write("find full path!!\n ")
        f.write("re : "+str(re)+"\n")
        for n in node_list[:-1]:
            f.write(n+"->")
        f.write(node_list[-1]+"\n")
        main_hit += 1
        
        #set base path as most recursive path
        if re > base_path[0]:
            base_path[0] = re
            base_path[1] = node_list[:]
        
        #if find path 50000, finish recursion
        if main_hit >= 10:
            findmax_flag = 1
            f.close()
        
        re -= 1
        del node_list[-1]
        return

    #trace prodecessors to find entry point
    else:
        if node.block_id in no_pre:
            f.write(colored("already in no pre",'blue')+'\n')
            re -= 1
            del node_list[-1]
            return

        #if it has no predecessors, return and keep tracing with next node
        if len(node.predecessors) == 0:
            f.write(colored("node has no predecessors",'red')+'\n')
            #f.write(str(hex(node.addr))+"has no predecessors\n")
            if node.block_id in no_pre:
                f.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
                exit()
            no_pre.append(node.block_id)
            re -= 1
            del node_list[-1]
            return

        
        for nd in node.predecessors:
            f.write(str(hex(nd.addr))+" ")
        f.write("\n")
        
        #explore predecessors
        for nd in node.predecessors:
            #if it visits a node more than e_count, 
            #think it as loop and return, keep tracing with next node
            if node_list.count(str(nd.block_id)) > e_count:
                f.write(colored('stop recur and restart at'+node_list[-1],'yellow')+'\n')
                #f.write("loop! stop recur and restart at "+str(node_list[-1])+"\n")
                continue
           
            findorigin(nd,entry, epaddr, e_count, c_flag)
            if findmax_flag == 1:
                return

        pre_flag = 0
        for nd in node.predecessors:
            if nd.block_id not in no_pre:
                pre_flag = 1
                break
        if pre_flag == 0:
            no_pre.append(node.block_id)
            f.write(colored("add parent nopre node",'red')+'\n')

    
    re -= 1
    del node_list[-1]

#==make cfg dynamically with simfile==
def makeCFG(argv, newpoc, simfile, stacknum, lib=None):
    global f
    if (lib):
        proj = angr.Project('/home/circuit/jpegpdf/openjpeg-2.1.1/build/bin/opj_dump', auto_load_libs=False, force_load_libs=lib)
    else:
        proj = angr.Project(argv[0], load_options={'auto_load_libs':False})
    #a=proj.loader.find_symbol('opj_j2k_read_header') 
    #print(a)
    #a=proj.loader.find_symbol('opj_read_header') 
    #print(a)
    state = proj.factory.entry_state(args=argv,concrete_fs=True)
    state.fs.insert(newpoc,simfile)
    
    #cfg = proj.analyses.CFGEmulated(initial_state = state, context_sensitivity_level = stacknum)
    #cfg = proj.analyses.CFGEmulated(initial_state = state, call_depth = stacknum)
    cfg = proj.analyses.CFGEmulated(initial_state = state, context_sensitivity_level = stacknum)
    #cfg = proj.analyses.CFGFast()
    f = open("path_"+argv[0].split("/")[-1],'w')

    return cfg

#==find path from ep to main==
def extractPath(cfg, ep, e_count, c_flag):
    global base_path
    
    epaddr = cfg.kb.functions.function(name=ep).addr
    target = cfg.model.get_any_node(epaddr, anyaddr=True)
    print(ep,":",str(hex(epaddr)))
    entry = cfg.kb.functions.function(name='main').addr
    print("main :", str(hex(entry)))
    sys.setrecursionlimit(2000)
    findorigin(target, entry, epaddr, e_count, c_flag)
    
    return base_path
    
