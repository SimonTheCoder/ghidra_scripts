# show current block with popup
#By SimonTheCoder
#@category SimonTheCoder
#@menupath Search.Find current block

memory = currentProgram.getMemory()
current_block = memory.getBlock(currentAddress)
read = "r" if current_block.isRead() else "-"
write = "w" if current_block.isWrite() else "-"
execute = "x" if current_block.isExecute() else "-"
show_string = "Currently in Block: %s [@ %X ,@ %X ] %s%s%s" % (current_block.name, current_block.start.offset, current_block.end.offset, read,write,execute)
print(show_string)
popup(show_string)