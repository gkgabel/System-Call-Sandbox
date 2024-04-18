import angr
import sys
import pickle
import os

if len(sys.argv) != 2:
    print("Wrong number of arguments. Simply give the file name")
    exit(0)

# Get the filename from the command line argument
filepath = sys.argv[1]
filename = os.path.basename(sys.argv[1])

proj = angr.Project(filepath, auto_load_libs=False)
cfg = proj.analyses.CFGFast(show_progressbar=True)

# Save the project to a pickle file with the filename included
proj_pickle_filename = f'proj_{filename}.pkl'
with open(proj_pickle_filename, 'wb') as f:
    pickle.dump(proj, f)

# Save the CFG to a pickle file with the filename included
cfg_pickle_filename = f'cfg_{filename}.pkl'
with open(cfg_pickle_filename, 'wb') as f:
    pickle.dump(cfg, f)

# Save the entry point to a pickle file with the filename included
cfg_start_pickle_filename = f'cfg_start_{filename}.pkl'
with open(cfg_start_pickle_filename, 'wb') as f:
    pickle.dump(proj.entry, f)

#print(f"Pickled files: {proj_pickle_filename}, {cfg_pickle_filename}, {cfg_start_pickle_filename}")
