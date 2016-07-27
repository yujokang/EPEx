#!/usr/bin/python

# Filter the output of EPEx, in particular for Stage III.
import sys

from split_path import split_path
from print_sorted import print_sorted

# Parse command line arguments:
# -b: only bugs, as in Stage III
# -c: only correctly-handled paths
# Otherwise, just clean up the Stage II output.
if (len(sys.argv)<2):
	print "Usage: "+sys.argv[0]+ " <log-file> [-b|-c]"
	sys.exit(1)

f = open(sys.argv[1], 'r')
print_only_buggy = 0
print_only_correct = 0
if (len(sys.argv)==3):
	if (sys.argv[2] == "-b"):
		print_only_buggy = 1
	elif (sys.argv[2] == "-c"):
		print_only_correct = 1

# Look up handling status by function and location.
err_funcs = {}
# All of the functions in err_funcs
err_funcs_list = []
# The locations where each function was recorded
err_locs_lists = {}

# Parse and record log data.
for line in f:
	# Only handle the EPEx messages.
	if line.startswith("EPEx:"):
		if "warning:" in line:
			continue
		parts = line.split();
		err_location = parts[1]

		# Fix for <Spelling>
		if parts[2].startswith("<"):
			if parts[3].startswith("<"):
				err_func_name = parts[4]
			else:
				err_func_name = parts[3]
		else:
			err_func_name = parts[2]

		# Add an entries for newly-seen functions
		if (err_func_name not in err_funcs):
			err_funcs[err_func_name] = {}
			err_funcs_list.append(err_func_name)
			err_locs_lists[err_func_name] = []

		for p in parts:
			# Record handling status.
			if p.startswith("Return=") or p.startswith("return="):
				to_add = p.split("=")[1]
				if (err_location not in \
				    err_funcs[err_func_name]):

					err_funcs[err_func_name][err_location] = [to_add]
					err_locs_lists[err_func_name] \
						.append(err_location)
				else:
					if (to_add not in (err_funcs[err_func_name])[err_location]):
						(err_funcs[err_func_name][err_location]).append(to_add)

err_funcs_list.sort()

summary_keys = []
err_summary = {}
crrct_summary = {}

# Summarize log data according to user's option.
for e in err_funcs_list:
	out = e + ":\n"
	buggy = set([])
	correct = set([])
	if print_only_buggy:
		loc = e + ":\n"
	elif print_only_correct:
		loc = e + ":\n"
	
	err_cnt = 0
	non_err_cnt = 0
	tot_cnt = 0

	sorted_locs = err_locs_lists[e]
	sorted_locs.sort()

	# Count if error is maybe handled or not.
	for l in sorted_locs:
		call_sites = split_path(l)
		if ("noerror" in err_funcs[e][l]) or ("noerror_or_error" in err_funcs[e][l]):
			non_err_cnt += 1
			tot_cnt += 1

			for call_site in call_sites:
				buggy.add(call_site)

		elif ("error" in err_funcs[e][l]):
			err_cnt += 1
			tot_cnt += 1

			for call_site in call_sites:
				correct.add(call_site)

	# Save only bugs.
	if (print_only_buggy):
		if ((non_err_cnt < tot_cnt) and (non_err_cnt > 0)):
			err_summary[e] = buggy
			summary_keys.append(e)

	# Save only correctly-handled paths.
	elif (print_only_correct):
		if (err_cnt==tot_cnt):
			crrct_summary[e] = correct
			summary_keys.append(e)
	# Print Stage II output,
	# but mention if handling bugs would be counted in Stage III.
	elif (tot_cnt > 0):
		print out

		merged = []

		for member in buggy:
			merged.append(member + " ALERT")
		for member in correct:
			merged.append(member + " CORRECT")

		print_sorted(merged)

		print "Not returning error:" + str((non_err_cnt * 100) / tot_cnt) + "% Returning error:" + str((err_cnt * 100) / tot_cnt) + "%"
		if err_cnt < tot_cnt:
			if non_err_cnt < tot_cnt:
				print "COUNTED"
			else:
				print "NOT COUNTED"
		print "\n"

# Sort output.
summary_keys.sort()

# Print bug reports from Stage III and their count.
if (print_only_buggy):
	tot = 0 
	for e in summary_keys:
		bug_summary = err_summary[e]
		n_bugs = len(bug_summary)
		tot += n_bugs

		print e + " bug cnt=" + str(n_bugs)
		print_sorted(bug_summary)

	print "Total bugs = " + str(tot)

# Print correctly-handled paths and their count.
elif (print_only_correct):
	tot = 0 
	for c in summary_keys:
		tot += len(crrct_summary[c])
		print c + " crrct cnt=" + str(len(crrct_summary[c]))

	print "Total correct checks  = " + str(tot) 
