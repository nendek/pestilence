import subprocess

dump = subprocess.run(["objdump -S pestilence"], shell=True, stdout = subprocess.PIPE).stdout.decode("utf-8")

memcpy_addr = dump[dump.find("<ft_memcpy>:") + 13:]
memcpy_addr = memcpy_addr[:memcpy_addr.find(":")]
memcpy_addr = hex(int(memcpy_addr, 16))

end = dump[dump.find("<ft_end>:") + 10 :dump.find("<ft_memcpy>:") - 19]
end_start = end[:end.find(":")]
end_start = int(end_start, 16)
end_end = end[end.find("<jmp5>:") + 8:]
end_end = end_end[:end_end.find(":")]
end_end = int(end_end, 16)
end_size = hex(end_end + 5 - end_start)

loader = dump[dump.find("<loader>:") + 10:]
loader = loader[:loader.find("<ft_end>:") - 19]
loader_start = loader[:loader.find(":")]
loader_start = int(loader_start, 16)
loader_end = loader[loader.rfind("\n"):]
loader_end = loader_end[:loader_end.find(":")]
loader_end = int(loader_end, 16)
loader_size = hex(loader_end - loader_start + 5)

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

offset_3 = dump[dump.find("<inject_end>:") + 14:-1]
for i in range(0, 4): 
    offset_3 = offset_3[offset_3.find("\n") + 1:-1]
offset_3 = offset_3[0:offset_3.find(":")].strip()
offset_3 = hex(int(offset_3, 16) + 3)

offset_4 = dump[dump.find("<main>:") + 8:]
for i in range(0, 3):
    offset_4 = offset_4[offset_4.find(":") + 1:]
offset_4 = offset_4[offset_4.find(":") - 5: offset_4.find(":")]
offset_4 = hex(int(offset_4, 16))

print("memcpy_addr : {} || end_size : {} || loader_size : {} || payload_size : {} || main_offset : {} || offset_1 : {} || offset_2 : {} || offset_3 : {} || offset_4 : {}".format(memcpy_addr, end_size, loader_size, main_end, main_start, offset_1, offset_2, offset_3, offset_4))

f = open("includes/pestilence.h", "r")
content = f.readlines()
f.close()

f = open("includes/pestilence.h", "w")
for i in range(0, len(content)):
    if content[i].find("FT_MEMCPY_ADDR") == 9:
        content[i] = content[i][0:24] + memcpy_addr + content[i][30:-1] + "\n"
    if content[i].find("END_SIZE") == 9:
        content[i] = content[i][0:18] + end_size + content[i][22:-1] + "\n"
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

    f.write(content[i])
f.close()

payload_size = hex((int(main_end, 16) - int(memcpy_addr, 16) + 7))
print("payload_size : ", payload_size)

f = open("srcs_s/loader.s", "r")
content = f.readlines()
f.close()
f = open("srcs_s/loader.s", "w")

for i in range(0, len(content)):
    if content[i].find("|REPLACE1|") != -1:
        place = content[i].find("|REPLACE1|") - 7
        content[i] = content[i][0:place] + hex(int(payload_size, 16) + 0x1000) + content[i][place + 6:]
    if content[i].find("|REPLACE2|") != -1:
        place = content[i].find("|REPLACE2|") - 7
        content[i] = content[i][0:place] + payload_size + content[i][place + 6:]
    f.write(content[i])
f.close()
