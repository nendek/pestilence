import subprocess

dump = subprocess.run(["objdump -S pestilence"], shell=True, stdout = subprocess.PIPE).stdout.decode("utf-8")

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
offset_4 = offset_4[offset_4.find(":") + 1:]
offset_4 = offset_4[offset_4.find(":") + 1:]
offset_4 = offset_4[offset_4.find(":") + 1:]
offset_4 = offset_4[offset_4.find(":") - 5: offset_4.find(":")]
offset_4 = hex(int(offset_4, 16))

print(main_start, main_end, offset_1, offset_2, offset_3, offset_4)

f = open("includes/pestilence.h", "r")
content = f.readlines()
f.close()

f = open("includes/pestilence.h", "w")
for i in range(0, len(content)):
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
