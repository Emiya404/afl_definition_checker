import argparse
import os
import sys
import struct

transition_dict = {}

def bytes_to_set(byte_map):
    map_len = len(byte_map)
    result_set = set()
    for x in range(map_len):
        if byte_map[x] == 0x01:
            result_set.add(x)
    return result_set

def process_units(file_content, unit_size):
    
    pos = 0
    file_size = len(file_content)
    prev_state = None
    prev_map = None

    while pos + 4 + unit_size <= file_size:
        curr_state = struct.unpack('<I', file_content[pos:pos+4])[0]
        pos += 4
        curr_map = bytes(file_content[pos:pos+unit_size])
        pos += unit_size
        if prev_state is not None:
            transition = f"{prev_state},{curr_state}"
            if transition not in transition_dict:
                transition_dict[transition] = {}
                transition_dict[transition]["union"] = bytes_to_set(prev_map)
                transition_dict[transition]["intersection"] = bytes_to_set(prev_map)
            else:
                transition_dict[transition]["union"] = transition_dict[transition]["union"] | bytes_to_set(prev_map)
                transition_dict[transition]["intersection"] = transition_dict[transition]["intersection"] & bytes_to_set(prev_map)
            prev_state = curr_state
            prev_map = curr_map
        else:
            # first time no transition
            prev_state = curr_state
            prev_map = curr_map

    return

def process_files(dir_path, unit_size):
    for file_no in range(150000):
        file_path = os.path.join(dir_path, f"fstate_{str(file_no)}")
        try:
            with open(file_path, 'rb') as f:
                print(f"deal with {file_path}")
                content = f.read()
                process_units(content, unit_size)
        except IOError as e:
            print(f"read {file_path} err")
            return False
    return

def main():
    parser = argparse.ArgumentParser(description='analyse union and intersection')
    parser.add_argument('unit_size', type=int, help='unit size')
    parser.add_argument('directory', type=str, help='file dir path')
    
    args = parser.parse_args()
    
    if args.unit_size <= 0:
        print("a positive int", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isdir(args.directory):
        print(f"dir {args.directory} do not exist", file=sys.stderr)
        sys.exit(1)
    
    process_files(args.directory, args.unit_size)

    for key, value in transition_dict.items():
        print(f"{key},{len(value['union'])},{len(value['intersection'])}")

if __name__  == '__main__':
    main()