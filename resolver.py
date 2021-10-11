import os.path
import socket
from argparse import ArgumentParser
import re


def process_single_file(filepath, output, prefix=""):
    with open(filepath, "r") as file:
        if output == "display":
            for line in file:
                # print(line, re.match("([a-z0-9A-Z-]+\.)*([a-z0-9A-Z-])+\.[a-z]+", line))
                if re.search("([a-z0-9A-Z-]+\.)*([a-z0-9A-Z-])+\.[a-z]+", line):
                    resolved = socket.gethostbyname(
                        re.search("([a-z0-9A-Z-]+\.)*([a-z0-9A-Z-])+\.[a-z]+", line).group(0))
                    print(resolved)
        else:
            if os.path.exists(output):
                with open(output, "a") as output_file:
                    for line in file:
                        if re.search("([a-z0-9A-Z-]+\.)*([a-z0-9A-Z-])+\.[a-z]+", line):
                            match = re.search("([a-z0-9A-Z-]+\.)*([a-z0-9A-Z-])+\.[a-z]+", line).group(0)
                            resolved = socket.gethostbyname(match)
                            if prefix == "":
                                output_file.write(str(resolved + "\n"))
                            else:
                                output_file.write(f"{match}{prefix}{resolved}\n")
            else:
                with open(output, "w") as output_file:
                    for line in file:
                        if re.search("([a-z0-9A-Z-]+\.)*([a-z0-9A-Z-])+\.[a-z]+", line):
                            match = re.search("([a-z0-9A-Z-]+\.)*([a-z0-9A-Z-])+\.[a-z]+", line).group(0)
                            resolved = socket.gethostbyname(match)
                            if prefix == "":
                                output_file.write(str(resolved + "\n"))
                            else:
                                output_file.write(f"{match}{prefix}{resolved}\n")


if __name__ == "__main__":
    main_parser = ArgumentParser()
    main_parser.add_argument("-i", "--input", type=str, help="Input file or directory", default="input.txt")
    # main_parser.add_argument("--input-prefix", type=str, help="Prefix in lines of input file")
    main_parser.add_argument("-p", "--prefix", help="Output file prefix", default="")
    main_parser.add_argument("-f", "--format", type=str, help="Ouptut file format", default="txt")
    main_parser.add_argument("-o", "--out", type=str, help="Output file path", default="display")
    args = main_parser.parse_args()
    if os.path.exists(args.input):
        if os.path.isdir(args.input):
            for f in os.listdir(args.input):
                if args.format in f:
                    process_single_file(f, args.out, args.prefix)
        else:
            process_single_file(args.input, args.out, args.prefix)
