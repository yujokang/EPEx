# Print a collection of text in lexicographical order.
# collection:	a collection of strings to print
# prefix:	the prefix to prepend to each entry
def print_sorted(collection, prefix = "\t"):
	sorted_list = []
	for member in collection:
		sorted_list.append(member)
	sorted_list.sort()

	for member in sorted_list:
		print prefix + member
