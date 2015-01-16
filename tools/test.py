# -*- coding: utf-8 -*-

import os

root = r'D:\Virus'

for subdir in os.listdir(root):
    dirpath = os.path.join(root, subdir)
    if os.path.isdir(dirpath):
        for f in os.listdir(dirpath):
            if f.endswith('.exe~'):
                os.system('python VirusDetection.py ' + os.path.join(dirpath, f))
                break
        else:
            if os.path.exists(os.path.join(dirpath, 'Make.bat')):
                os.system('Make.bat')
                for f in os.listdir(dirpath):
                    if f.endswith('.exe~'):
                        os.system('python VirusDetection.py ' + os.path.join(dirpath, f))
            else:
                print 'Cannot find Make.bat in ' + dirpath