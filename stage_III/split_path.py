# Utility for splitting a path in the EPEx output
# into the contained call sites.

# delimiter before the line and column numbers
LOC_MARKER = ":"
DIGIT_MIN = "0"
DIGIT_MAX = "9"

# Seek the start of the next call site.
# path:		the path line
# start:	the beginning of he current path
# returns	the end of the current site, or the start of the next site
def find_next_site_start(path, start):
	# Find the positions before the line and column numbers.
	file_end = path.find(LOC_MARKER, start)
	if (file_end < 0):
		return -1
	line_end = path.find(LOC_MARKER, file_end + 1)
	if (line_end < 0):
		return -1
	column_start = line_end + 1
	end_i = column_start

	# Find the end of the column number.
	while (end_i < len(path) and path[end_i] >= DIGIT_MIN and \
	       path[end_i] <= DIGIT_MAX):
		end_i += 1
	return end_i

# Split a path into call sites.
# path:		the path line to split
# returns	a list of the call sites in the path
def split_path(path):
	call_sites = []
	site_start = 0

	while (site_start < len(path)):
		next_site_start = find_next_site_start(path, site_start)
		if (next_site_start < 0):
			return None
		call_sites += [path[site_start : next_site_start]]
		site_start = next_site_start
	return call_sites
