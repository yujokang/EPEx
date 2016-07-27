from os import sep, getcwd, chdir, listdir, remove, symlink
from os.path import islink, isdir, isfile, isabs, realpath, relpath
from sys import argv

# The name of the configuration file for EPEx.
CONFIG_NAME = "error_spec.txt"
# Prefix to go up a directory, to use the same file
# relative to a directory into which we have descended.
GO_UP = ".." + sep

# Recursively generate links.
# dst:		the current destination root path
# src:		the source file, which may be relative to the destination
# link_name:	the name of the configuration file link to create
def _gen_links(dst, src, link_name = CONFIG_NAME):
	dst += sep

	next_src = None
	# If the source path is absolute, keep it,
	# otherwise, for the children directories,
	# the relative path needs to go up a directory.
	if (isabs(src)):
		next_src = src
	else:
		next_src = GO_UP + src

	# Remove the old link, if it exists.
	link_path = dst + link_name
	if (islink(link_path)):
		remove(link_path)
	symlink(src, link_path)

	# Descend to child directories.
	members = listdir(dst)
	for member in members:
		member_path = dst + member
		if (isdir(member_path) and not islink(member_path)):
			_gen_links(member_path, next_src, link_name)

# Generate links.
# dst:		the current destination root path
# src:		the source file,
#		which may be relative to the current working directory
# link_name:	the name of the configuration file link to create
def gen_links(dst, src, link_name = CONFIG_NAME):
	if (not isabs(src)):
		full_src_path = realpath(src)
		old_cwd = getcwd()
		chdir(dst)
		src = relpath(full_src_path)
		chdir(old_cwd)

	_gen_links(dst, src, link_name)

if (__name__ == "__main__"):
	SRC_ID = 1
	DST_ID = SRC_ID + 1
	N_ARGS = DST_ID + 1

	if (len(argv) < N_ARGS):
		print "Usage: " + \
		      "%s [source file] [destination directory]"%(argv[0])
		exit(-1)

	src = argv[SRC_ID]
	dst = argv[DST_ID]
	if (not isfile(src)):
		print "No file exists for the source at %s"%(src)
		exit(-1)
	if (not isdir(dst)):
		print "No directory exists for the destination at %s"%(dst)
		exit(-1)

	gen_links(dst, src)
