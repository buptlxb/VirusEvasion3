#!/usr/local/bin/python
import re
import random
import sys
import os
dataSeg = """.data
first dd  0badbeefh
relo dd offset first
hole dd 1024 dup (0)
last dd 0badbeefh
"""
dataAddr = "0ffh"
dataFuncCode1 = """
data_func proc
	mov esi, offset relo
	cld
	lodsd
	mov ebx, eax
again:
	lodsd
"""
dataFuncCode2 = """
	je next
	add eax, ebx
	mov edi, eax
	lodsd
"""
dataFuncCode3 = """
	mov ecx, eax
	call decode
	jmp again
endp data_func
next:
    ret
decode proc
	push esi
	push edi
	cld
	mov esi, edi
decode@1:
	lodsb
"""

dataFuncCode4 = """
	stosb
	dec ecx
	jne decode@1
	pop edi
	pop esi
	ret
endp decode

"""
codeSeg = """.code
"""
markLine = """push 0badbeefh
"""
jmpPos = """target dd offset target
"""
startCode1 = """
    push ebp
    mov ebp, esp
"""
retCode2 = """
    mov esp, ebp
    pop ebp
    ret
"""
instruction = ("add", "sub", "and", "or", "xor", "mov")
register = ("eax", "ebx", "ecx", "edx")

finishCode = """finish:
    jmp [target]
"""


def deal_data_address(data_addr):
    addr = hex(data_addr)[2:]

    eax_addr = "0" + addr*4 + "h"
    al_addr = "0" + addr + "h"
    eax_code = """\txor eax,""" + eax_addr +"""
"""
    al_code = """\txor al,""" + al_addr + """
"""
    data_func_code = dataFuncCode1 + eax_code + dataFuncCode2 + eax_code+ dataFuncCode3 + al_code + dataFuncCode4
    return data_func_code


def generate_code(src_file, has_data=False, data_address=255, junk_times=50, call_times=1):
    data_func_code = deal_data_address(data_address)
    file_name = src_file
    fd = open(file_name, 'w+')

    list = []
    if has_data:
        list.append(dataSeg)
    list.append(codeSeg)
    list.append(markLine)
    list.append(jmpPos)
    list.append(finishCode)
    if has_data:
        data_func = """\tcall data_func
"""
        list.append(data_func)
    func_name_list = []
    func_code_buf = []
    for i in range(call_times):
        name = "func@"+str(i)
        func_name_list.append(name)
        call_code = "\tcall " + name + """
"""
        list.append(call_code)
        func_code_buf.extend(generate_func(func_name_list[i].strip(), junk_times))
    finish_jmp = """\tjmp finish
"""
    list.append(finish_jmp)
    if has_data:
        list.append(data_func_code)
    list.extend(func_code_buf)
    list.append(markLine)

    for lin in list:
        fd.write(lin)


def generate_func(entry, junk_times=50):
    L = []
    func_head = entry + """ proc
"""
    L.append(func_head)
    L.append(startCode1)
    junk_code = generate_junk_code(junk_times)
    L.extend(junk_code)
    L.append(retCode2)
    end_func = "endp " + entry + """
"""
    L.append(end_func)

    return L


def generate_junk_code(instruct_num):
    L = []
    for num in range(instruct_num):
        instr = random.choice(instruction)
        des_regis = random.choice(register)
        src_regis = random.choice(register)
        curr_instruction = "\t" + instr + " " + des_regis + "," + src_regis + """
"""
        L.append(curr_instruction)
    return L


def insert_include_asm(src_asm, include_asm, output_asm):
    file = open(src_asm, 'r+')
    res_list = file.readlines()
    sep = re.search(r'[\r\n]\n?$', res_list[1], re.I | re.M)
    include_str = "include " + os.path.split(include_asm)[1] + str(sep.group())
    file.close()
    res_list.reverse()
    res_index = 0
    for queuelin in res_list:
        result = re.search(r'^(\s)*(end)(\s)+(\w)*.*$', queuelin, re.I | re.M)
        if result:
            #print result.group()
            res_list.insert(res_index+1, include_str)
            break
        res_index += 1
    res_list.reverse()

    file = open(output_asm, 'w+')
    for lin in res_list:
        file.write(lin)
    file.close()
argPromotion = """ there are at most 6 arguments to choose:
    1:src.asm that you want to operate
    2:has_data decide the included file has data or not
    3:data address that you want to operate must be in [0,255],default is 255
    4:the function size in included file which default is 50
    5:the name of include file whose default value is 'magic.asm'
    6:the newly generated file whose default value is src01.asm
Attention :at least the first two args are  needed
"""
successPromotion = """operation success!
"""
if __name__ == "__main__":
    # includeAsm.py  main.asm  has_data=1 255 junk_times=20 include_asm output.asm

    includeAsm = 'magic.asm'
    junkTimes = 50
    dataAddress = 255
    arguments = sys.argv[1:]
    if arguments[0].strip() == "-h":
        print argPromotion
    else:
        count = len(arguments)

        if count < 2:
            print """you should type at least 2 arguments:
        you can input -h for help!"""
            sys.exit(0)
        else:
            isfile = os.path.isfile(arguments[0])
            if not isfile:
                print """ the asm file you want to deal is not exist
    you can input -h for help!"""
                sys.exit(0)
            else:
                srcAsm = arguments[0]
                hasData = arguments[1]
                outputAsm = srcAsm.split('.')[0]+"01.asm"
            if count == 2:
                print argPromotion
                print successPromotion
            elif count >= 3:
                dataAddress = int(arguments[2])
                assert (dataAddress <= 255) and (dataAddress >= 0)
                print """the 3th argument specified the data address to operate"""
                if count == 3:
                    print successPromotion
                elif count >= 4:
                    print """the 4th argument specified the function size in included file"""
                    junkTimes = int(arguments[3])
                    if count == 4:
                        print successPromotion

                    elif count >= 5:
                        print """the 5th argument specified the included file name"""
                        includeAsm = arguments[4]
                        if count == 5:
                            print successPromotion
                        elif count >= 6:
                            print """the 6th argument specified the output file name"""
                            outputAsm = arguments[5]
                            if count == 6:
                                print successPromotion
                            else:
                                print """you type too many arguments
you can input -h for help!
"""
        insert_include_asm(src_asm=srcAsm, include_asm=includeAsm, output_asm=outputAsm)
        generate_code(src_file=includeAsm, has_data=hasData, data_address=dataAddress, junk_times=junkTimes)
