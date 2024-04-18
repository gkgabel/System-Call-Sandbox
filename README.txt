To generate a graph generate a statically compiled binary and do following:
$ ./graph_gen <file_path>
This will generate a graph as a png and dot file with name graph_<filename>

-----------------old readme at the time of submission-------------
#To compile the mbedtls benchmark statically, apply the patch named as patchfile inside the cloned benchmark repo and run the make file

$git apply patchfile.patch
$make 

#The tool is divided into two parts, one is the pikl_dumper.py that generates a CFG using CFGFast analyses available in angr and stores it in a pikl file format
#The other script called test.py reads from the pikl file and generates a .dot file for the CFG

$python3 pikl_dumper.py <test_file_path>
$python3 test.py

#Output will be in the form of a dot file named graph.dot
#However if the the graph is small a png file for graph will be generated with the name graph.png 