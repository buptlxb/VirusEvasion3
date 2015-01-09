#!/usr/bin/env python
import argparse
import sys

from version import *


class Args:
    def __init__(self, arguments=None):
        self.__args = None
        if not arguments:
            arguments = sys.argv[1:]
        self.__parse(arguments)

    def __parse(self, arguments):
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                         description="""description:
  VirusEvasion provides evasion for your virus.
""",
                                         epilog="""examples:
  VirusEvasion.py -e --binary ./virus.exe --output ./output.exe
  VirusEvasion.py -d --binary ./virus.exe --output ./output.exe

  """)

        parser.add_argument("-e", "--entry", action="store_true", help="Obfuscate binary entry with junk code")
        parser.add_argument("-d", "--data", action="store_true", help="Obfuscate binary .data section")
        parser.add_argument("-b", "--binary", type=str, metavar="<binary>", required=True, help="Specify a binary filename to obfuscate")
        parser.add_argument("-o", "--output", type=str, metavar="<output>", required=True, help="Specify the output file name")
        parser.add_argument("--version", action="version", version=PYVIRUSEVASION_VERSION, help="Show program's version number and exit")
        self.__args = parser.parse_args(arguments)
        print '[+] Parsing arguments completed.'

    def get_args(self):
        return self.__args

if __name__ == '__main__':
    print Args(['-h']).get_args()