import angr
import sys
import pickle
import networkx as nx
import os
import re

if len(sys.argv) != 2:
    print("Wrong number of arguments. Please provide the file name")
    exit(0)

filepath = sys.argv[1]
filename = os.path.basename(sys.argv[1])

with open(f'cfg_{filename}.pkl', 'rb') as f:
    cfg = pickle.load(f)

with open(f'cfg_start_{filename}.pkl', 'rb') as f:
    entry_addr = pickle.load(f)

with open(f'proj_{filename}.pkl', 'rb') as f:
    proj = pickle.load(f)

new_graph =  nx.DiGraph()
syscall_count = 0


file_path = "syscall_64.txt"

# Read the system calls from the file
with open(file_path, 'r') as file:
    lines = file.readlines()

# Create a dictionary to map system calls to their syscall numbers
syscall_mapping = {}
for line in lines:
    # Split the line into columns
    columns = line.split()
    
    # Check if the line has at least 3 columns
    if len(columns) >= 3:
        syscall_number = int(columns[0])
        syscall_name = columns[2]
        syscall_mapping[syscall_name] = syscall_number

# Print the mapping
#for syscall, syscall_number in syscall_mapping.items():
#    print(f"{syscall_number}\t{syscall}")
def get_syscall_number(syscall_name, syscall_mapping):
    return syscall_mapping.get(syscall_name, -1)

def get_syscall_number_by_disassembly(start_node):
    reg = {}
    x64_registers = [
                            "rax", "eax", "ax", "al",
                            "rbx", "ebx", "bx", "bl",
                            "rcx", "ecx", "cx", "cl",
                            "rdx", "edx", "dx", "dl",
                            "rsi", "esi", "si", "sil",
                            "rdi", "edi", "di", "dil",
                            "rbp", "ebp", "bp", "bpl",
                            "rsp", "esp", "sp", "spl",
                            "r8", "r8d", "r8w", "r8b",
                            "r9", "r9d", "r9w", "r9b",
                            "r10", "r10d", "r10w", "r10b",
                            "r11", "r11d", "r11w", "r11b",
                            "r12", "r12d", "r12w", "r12b",
                            "r13", "r13d", "r13w", "r13b",
                            "r14", "r14d", "r14w", "r14b",
                            "r15", "r15d", "r15w", "r15b"
                        ]
    for register in x64_registers: reg[register]=-1
    pattern = r'^([0-9a-fA-F]+h|\d+)$'
        
        # Iterate through the instructions in the basic block
        #Below is the code to calculate sys call number
        
        #-----------------> Need to find out sys call number for more complicated cases
    for instn in start_node.block.disassembly.insns:
            #print(instn)
        op_str = instn.op_str.strip()  # Remove leading/trailing spaces
        opn = instn.mnemonic
        opd = op_str.split(",")
        if len(opd) == 2:
            #print(type(opd[1]))
            if opn == 'mov':
                    # Check if the operand is a hexadecimal value
                if opd[1].strip() not in x64_registers:
                        #print(instn)
                    if re.match(pattern,opd[1].strip()) is None:
                        continue
                    reg[opd[0].strip()] = int(opd[1].strip().replace("h", ""), 16)
                else:
                        # Check if the source operand is a valid register
                    reg[opd[0].strip()] = reg[opd[1].strip()]
            elif opn == 'xor' and opd[0].strip() == opd[1].strip():
                reg[opd[0].strip()] = 0
    #start_node.block.pp()
    syscall_number = reg['eax']
    return syscall_number


def explorer(ip_graph,curr_node_name,curr_node,local_visit,calr_addr):
    global syscall_count
    if curr_node.addr in local_visit: 
        return
    local_visit.add(curr_node.addr)
    for n in ip_graph.successors(curr_node):
        edge_type = ip_graph.get_edge_data(curr_node,n)['type']  
        if edge_type == 'call':
            for n_ret in ip_graph.successors(curr_node):
                if n_ret != n: 
                    ret_node_name = str(calr_addr)+'_'+str(n_ret.addr)
                    new_graph.add_node(ret_node_name)
                    #print(ret_node_name)
                    fun_gr(n.transition_graph,curr_node.addr,curr_node_name,ret_node_name)
        elif edge_type == 'fake_return': #already covered edge for fake ret above and below
            node_name = str(calr_addr)+'_'+str(n.addr)
            explorer(ip_graph,node_name,n,local_visit,calr_addr)
        elif edge_type == 'syscall':
            syscall_count = syscall_count+1
            for n_ret in ip_graph.successors(curr_node):
                if n_ret != n: 
                    node_name = str(calr_addr)+'_'+str(n.addr)
                    fake_ret_node_name = str(calr_addr)+'_'+str(n_ret.addr)
                    new_graph.add_node(node_name)
                    #if n.name != 'futex':
                    #print(cfg.get_any_node(curr_node.addr).block.disassembly.pp())
                    sys_num = get_syscall_number_by_disassembly(cfg.get_any_node(curr_node.addr))
                    #print(sys)
                    if sys_num != -1:
                        new_graph.add_edge(curr_node_name,node_name,label='syscall '+str(sys_num))
                    else:
                        new_graph.add_edge(curr_node_name,node_name,label='syscall '+str(get_syscall_number(n.name,syscall_mapping)))
                    #else:
                    #    new_graph.add_edge(curr_node_name,node_name,label='epsilon' )
                    new_graph.add_edge(node_name,fake_ret_node_name,label='epsilon')
        else:
            node_name = str(calr_addr)+'_'+str(n.addr)
            new_graph.add_node(node_name)
            new_graph.add_edge(curr_node_name,node_name,label='epsilon')
            explorer(ip_graph,node_name,n,local_visit,calr_addr)


def fun_gr(ip_graph,calr_addr,calr_name,ret_node_name):

    for n in ip_graph.nodes:
        if ip_graph.in_degree(n) == 0:
            #print("start_node",calr_name,n.addr)
            start_node = n
        if ip_graph.out_degree(n) == 0:
            if str(type(n)) == "<class 'angr.codenode.BlockNode'>":
                node_name = str(calr_addr)+'_'+str(n.addr)
                #print(node_name,ret_node_name)
                new_graph.add_edge(node_name,ret_node_name,label='epsilon')

    node_name=str(calr_addr)+'_'+str(start_node.addr)
    if node_name in new_graph.nodes:
        return

    new_graph.add_node(node_name)
    new_graph.add_edge(calr_name,node_name,label='epsilon')

    local_visit = set()

    explorer(ip_graph,node_name,start_node,local_visit,calr_addr)
    
new_graph.add_node('0_0')
new_graph.add_node('1_1')
fun_gr( cfg.kb.functions['main'].transition_graph,0,'0_0','1_1')

 
def bypass(curr_node,par_node,depth=0):
    flag= 1
    bypass_dest_list_to_return =[]
    successors = list(new_graph.successors(curr_node)).copy()
    for child in successors:
        #why did I even write this condition, I don't know.It just seemed to work. So need to know why it works and whther it works.
        if new_graph.has_edge(curr_node,child) ==0:
            continue       
        if new_graph.get_edge_data(curr_node,child) == {} :
            continue       
        jmp_knd=new_graph.get_edge_data(curr_node,child).get('label')
        if jmp_knd == None:
            print (new_graph.get_edge_data(curr_node,child),curr_node,child)

        if ((jmp_knd !='epsilon') & (jmp_knd !='bypass')):
            flag = 0
            if curr_node!=par_node:
                new_graph.add_edge(par_node,child,label=jmp_knd)
                bypass_dest_list_to_return.append(curr_node)
                print("appended node to list",curr_node)

                
        #elif (jmp_knd =='bypass'):
        #    print("bypass to ",child)
        #    bypass_dest_list = bypass(child,par_node,depth+1)
        else:
            num_predecessor = len(list(new_graph.predecessors(curr_node)))

            new_graph.remove_edge(curr_node,child)
            print("-----------|" * depth,"deleted edge b/w",curr_node,child)
            bypass_dest_list = bypass(child,par_node,depth+1) #bypass dest also part of bypass caveat(this is a list of node where bypass was done)
            #
            #                    1                                                               1
            #                    | epsilon                                                      /  \
            #                    v                                                     call    /    \  call
            #                    2                                                            v      v
            #                   / \                                                           5      4
            #        epsilon   /   \ call              =>     XXXXXX WRONG -> Bypass dest List=[5,4] (Are there issues with ideas???????? Yes)
            #                 V     V
            #                 3     4
            #           call  |
            #                 v
            #                 5
            #
            #There is a problem with the dest list because this example does not use bypass dest list.
            #The correct list should be [3,2] for 1. Atleast that is what I think now. In future when I am reading this i.e. now, this will not be intuitive
            #But my future self should not forget that the list is not meant for now. 
            #We add epsilon edges (or should I use a new type of edge called bypass edges) so that if indegree of a node > 1, then I would have deleted the edges
            #which come when we enter the basic block seconf time using the other incoming edge. Think it through, I am dumb but I believe in my future self. 
            #
            #part of bypass caveat below
            bypass_dest_list_to_return += bypass_dest_list
            
            #adding an optimization: if number of predecessor of current node is just 1 then skip adding edges from dest list
            if (new_graph.has_node(curr_node)):
                if ( num_predecessor > 0): 
                    for dest in bypass_dest_list:
                        new_graph.add_edge(curr_node,dest,label='bypass') #I give label bypass to so that later I can delete it after the scanning process ends
                        print("-----------|" * depth,"added bypass edge b/w",curr_node,dest)
            else:
                #print(len(curr_node.predecessors()),len(curr_node.successors()))
                new_graph.remove_node(curr_node)
                print("-----------|" * depth,"deleted node b/w",curr_node)
            
    return bypass_dest_list_to_return
                
visit = set()
def remove_epsilon(start_node):
    if start_node == None:
        return

    if start_node in visit:
        return
    
    visit.add(start_node)
    
    bypass(start_node,start_node)

    #since bypass call can be removing a node in this loop we need to check if current start node is available in graph
    if new_graph.has_node(start_node) == False:
        return
    for child in list(new_graph.successors(start_node)):
        remove_epsilon(child)
    

nodes_isolated=0    
def remove_epsilon_edges(start_node):
    edge_list=list(new_graph.edges).copy()
    for edge in edge_list:
        if new_graph.get_edge_data(*edge)['label'] == 'epsilon':
            new_graph.remove_edge(*edge)


def remove_isolated(start_node):
    global nodes_isolated
    #need to make a copy otherwise original list will keep changing since list is normally copied by reference
    flag = 1
    while flag ==1:
        flag = 0
        node_list=list(new_graph.nodes).copy()
        for i in node_list:
        #if (len(list(new_graph.successors(i))) == 0) & (len(list(new_graph.predecessors(i))) == 0):
            if (i != start_node) & (len(list(new_graph.predecessors(i))) == 0):
                flag = 1
                #print("deleting",i,list(new_graph.predecessors(i)))
                new_graph.remove_node(i)
                nodes_isolated += 1 
def remove_bypass():
    #need to make a copy otherwise original list will keep changing since list is normally copied by reference
    edge_list=list(new_graph.edges).copy()
    for i in edge_list:
        #print ("printer",i)
        if ((new_graph.get_edge_data(*i).get('label')=='bypass')):
            #print("deleting",i,list(new_graph.predecessors(i)))
            new_graph.remove_edge(*i) 
visit_list=[]

'''
def merger(start_node):
    succ_list=list(new_graph.successors(start_node)).copy()
    del_list=[]
    global visit_list
    visit_list.append(start_node)
    for node1 in succ_list:
        if node1 in del_list:continue
        for node2 in succ_list:
            if node1 == node2: continue
            if node2 in del_list: continue
            if (new_graph.get_edge_data(start_node,node1) == new_graph.get_edge_data(start_node,node2)):
                for child in new_graph.successors(node2):
                    new_graph.add_edge(node1,child,label=new_graph.get_edge_data(node2,child)['label'])
                new_graph.remove_edge(start_node,node2)
                del_list.append(node2)
    for node1 in new_graph.successors(start_node):
        if node1 not in visit_list:
            merger(node1)
'''
i_g = nx.nx_agraph.to_agraph(new_graph)
i_g.write("graph"+filename+".dot")
X3 = nx.nx_agraph.read_dot("graph"+filename+".dot") 
i_g.draw("graph_"+filename+".png", prog="dot")

remove_epsilon('0_0') #start_node.addr because nodes in intermediate graph are recognised by their address in cfg
remove_bypass()
remove_epsilon_edges('0_0') #changing this to remove any node with no incoming edges except start node 
remove_isolated('0_0')
remove_isolated('0_0')
print(len(list(new_graph.edges)))
print(len(list(new_graph.nodes)))
print(syscall_count)


i_g = nx.nx_agraph.to_agraph(new_graph)
i_g.write("graph"+filename+".dot")
X3 = nx.nx_agraph.read_dot("graph"+filename+".dot") 
i_g.draw("graph"+filename+".png", prog="dot")


#another issue with this code along with all other issues
#       b1      b3                          b1   b3
#       |       |                            \  /     
#       b2      b2    will be merged as       b2                Is it correct behaviour? If b2 is function then it is not. Need to check in case of jump
#               |                              |
#               b4                             b4

