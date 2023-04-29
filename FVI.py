'''
Firmware Version Inspector by shchmue
Inspects firmware version from Nintendo Switch NAND dump
'''

import datetime
import os
import sys
from crypto import XTSN

CLUSTER_SIZE = 0x4000

def print_usage():
    '''print usage instructions'''
    print('Usage:', sys.argv[0], '[-b=/path/to/biskeyfile] <dumpfile>')
    print(' biskeyfile must contain the following lines:')
    print('   BIS Key 2 (crypt): <32-digit hex key>')
    print('   BIS Key 2 (tweak): <32-digit hex key>')
    print('  or')
    print('   bis_key_02 = <64-digit hex key>')
    print('  omit -b if System partition already decrypted (eg. dumped with HacDiskMount)')
    print(' dumpfile must be NAND dump (eg. Hekate rawnand.bin dump) or System partition')
    print('')

def is_fat32(buffer):
    '''return boolean whether buffer is a FAT32 boot sector or not'''
    return buffer[0x52:0x52+5] == b'FAT32'

def read_cluster_from_file(file, address):
    '''returns cluster from file at address and decrypts if needed'''
    file.seek(address + system_offset)
    return_block = file.read(CLUSTER_SIZE)
    if is_encrypted:
        return_block = xts.decrypt(return_block, address//CLUSTER_SIZE, CLUSTER_SIZE)
    return return_block

def read_fat_attributes(buffer):
    '''read and return dict of attributes from buffer'''
    return {
        'bytes per sector': int.from_bytes(buffer[0xb:0xb+2], 'little'),
        'sectors per cluster': int.from_bytes(buffer[0xd:0xd+1], 'little'),
        'sectors before FAT': int.from_bytes(buffer[0xe:0xe+2], 'little'),
        'number of FATs': int.from_bytes(buffer[0x10:0x10+1], 'little'),
        'sectors per FAT': int.from_bytes(buffer[0x24:0x24+4], 'little')
    }

def get_cluster(buffer, addr):
    '''get cluster number from file entry, subtract 2 by convention'''
    return int.from_bytes(buffer[addr+0x1a:addr+0x1a+2] +
                          buffer[addr+0x14:addr+0x14+2], 'little') - 2

def get_modify_date_and_time(buffer, addr):
    '''get modify date and time string from file entry'''
    date = int.from_bytes(buffer[addr+0x18:addr+0x1a], 'little')
    time = int.from_bytes(buffer[addr+0x16:addr+0x18], 'little')
    try:
        d = datetime.datetime(1980 + (date >> 9), (date >> 5) & 0xf, date & 0x1f,
                            time >> 11, (time >> 5) & 0x3f, (time & 0x1f) * 2)
    except ValueError:
        return "Invalid date"
    return '{:%Y-%m-%d %H:%M:%S}'.format(d)

def cluster_to_address(cluster_num, root):
    '''return real address from cluster number given root address'''
    return FAT['bytes per sector'] * (cluster_num * FAT['sectors per cluster']) + root

def find_record_by_filename(buffer, name: bytes):
    '''return offset for file record matching name'''
    offset = 0
    name = name.ljust(8, b' ') # space-pad short names to avoid false positives
    if len(name) > 8:
        name = name[:8]
    while buffer[offset:offset+len(name)] != name and offset < len(buffer):
        offset += 0x20

    if offset >= len(buffer):
        return None

    return offset

def unpack_lfn(buffer):
    '''return filename from long file name entry'''
    if buffer[0] == 0xe5:
        return ''
    lfn = bytes()
    for lfn_index in range(buffer[0] & 0x1f):
        lfn_entry = buffer[0x20*lfn_index:0x20*lfn_index+0x20]
        lfn = lfn_entry[1:0xa:2] + lfn_entry[0xe:0x19:2] + lfn_entry[0x1c::2] + lfn
    lfn = lfn[:lfn.find(b'\x00')].decode('ascii')
    return lfn

print('Firmware Version Inspector - by shchmue')
print('')

if len(sys.argv) not in [2, 3]:
    print_usage()
    sys.exit()

firmware_titles_path = os.path.join(os.path.split(os.path.realpath(sys.argv[0]))[0], 'firmware_titles.db') 
if not os.path.exists(firmware_titles_path):
    sys.exit('firmware_titles.db file missing. Please update release.')

with open(firmware_titles_path, 'r') as ftf:
    titles = [t.rstrip() for t in ftf.readlines()]

SYSTEM_VERSION_TITLES = list()
for t in titles[titles.index('svt')+1:titles.index('pkgc')]:
    SYSTEM_VERSION_TITLES.append(t.split(','))

EXFAT_PACKAGEC_TITLES = dict()
for t in titles[titles.index('pkgc')+1:]:
    pair = t.split(',')
    EXFAT_PACKAGEC_TITLES[pair[0]] = pair[1]

bis_key_file = None
for arg in sys.argv[1:]:
    if arg[:3].lower() == '-b=':
        bis_key_file = arg[3:]
    else:
        dump_file = arg

if not os.path.exists(dump_file):
    sys.exit('Dump file ' + dump_file + ' not found.')

system_offset = 0
dump_file_size = os.stat(dump_file).st_size
if dump_file_size == 0x747c00000:
    print('Dump is full EMMC raw NAND.')
    system_offset = 0x7800000
if dump_file_size == 0x80000000:
    print('Dump is 2gb part of full EMMC raw NAND.')
    if not dump_file[-14:]=="rawnand.bin.00":
        sys.exit('Error! Use fisrt 2gb part (rawnand.bin.00)')
    system_offset = 0x7800000
elif dump_file_size == 0xa0000000:
    print('Dump is System partition.')
elif dump_file_size == 0x748400000:
    print('Dump is emuMMC.')
    system_offset = 0x8000000
else:
    sys.exit('Unrecognized file size.')

# check if we need BIS keys
is_encrypted = False
if bis_key_file:
    is_encrypted = True
    if not os.path.exists(bis_key_file):
        sys.exit('BIS key file ' + bis_key_file + ' not found.')
    crypt, tweak = bytes(), bytes()
    with open(bis_key_file, 'r') as bf:
        line = bf.readline()
        bf.seek(0)
        if ':' in line:
            separator = ':'
            for line in bf:
                key_type = line[:line.find(separator)]
                key_index = len(key_type) + 2
                if key_type.lower() == 'bis key 2 (crypt)':
                    crypt = bytes.fromhex(line[key_index:key_index+0x20])
                elif key_type.lower() == 'bis key 2 (tweak)':
                    tweak = bytes.fromhex(line[key_index:key_index+0x20])
        elif '=' in line:
            separator = '='
            for line in bf:
                key_type = line[:line.find(separator)-1]
                key_index = len(key_type) + 3
                if key_type.lower() == 'bis_key_02':
                    crypt = bytes.fromhex(line[key_index:key_index+0x20])
                    tweak = bytes.fromhex(line[key_index+0x20:key_index+0x40])
                    break
        else:
            sys.exit('First line of BIS key file does not contain a key.')

    if not crypt or not tweak:
        print_usage()
        sys.exit('Unable to find BIS keys in biskeyfile.')

    print('Loaded BIS keys.')
    print('')

    # init crypto class
    xts = XTSN(crypt, tweak)
else:
    print('BIS keys not provided. Assuming dump already decrypted.')

with open(dump_file, 'rb') as f:
    cluster = read_cluster_from_file(f, 0)
    if not is_encrypted and not is_fat32(cluster):
        cluster = read_cluster_from_file(f, 0)
        if not is_fat32(cluster):
            sys.exit('FAT boot sector not found! Check BIS keys.')

    print('Found FAT boot sector!')
    FAT = read_fat_attributes(cluster)

    root_sector = FAT['sectors per FAT'] * FAT['number of FATs'] + FAT['sectors before FAT']
    root_addr = FAT['bytes per sector'] * root_sector
    cluster = read_cluster_from_file(f, root_addr)

    print('')
    print('Scanning root for /Contents/...')
    dir_table_offset = find_record_by_filename(cluster, b'CONTENTS')

    if not dir_table_offset:
        sys.exit('/Contents/ not found.')

    contents_cluster = get_cluster(cluster, dir_table_offset)
    contents_addr = cluster_to_address(contents_cluster, root_addr)
    print('/Contents/ found at cluster', hex(contents_cluster + 2),
          'address', hex(contents_addr))

    print('')
    print('Scanning root for /save/...')
    dir_table_offset = find_record_by_filename(cluster, b'SAVE')

    if not dir_table_offset:
        sys.exit('/save/ not found.')

    save_cluster = get_cluster(cluster, dir_table_offset)
    save_addr = cluster_to_address(save_cluster, root_addr)
    print('/save/ found at cluster', hex(save_cluster + 2),
          'address', hex(save_addr))

    cluster = read_cluster_from_file(f, save_addr)

    print('')
    print('Scanning /save/ for System Savegame 8000000000000060...')
    block_ptr = 0
    most_recent_boot = ''
    while block_ptr < len(cluster):
        # if this is a LFN entry, the 3rd byte is the empty
        # upper byte of a UCS-2 encoded ASCII character
        if cluster[block_ptr + 2] != 0:
            block_ptr += 0x20
        elif cluster[block_ptr:block_ptr+4] == b'\x00\x00\x00\x00':
            break
        else:
            lfn_length = 0x20 * ((cluster[block_ptr] & 0x1f) + 1)
            filename = unpack_lfn(cluster[block_ptr:block_ptr+lfn_length])
            if filename == '8000000000000060':
                print('Success! Found /save/8000000000000060.')
                while cluster[block_ptr:block_ptr+6] != b'800000':
                    block_ptr += 0x20
                most_recent_boot = get_modify_date_and_time(cluster, block_ptr)
            block_ptr += lfn_length

    cluster = read_cluster_from_file(f, contents_addr)

    print('')
    print('Scanning /Contents/ for /registered/...')
    dir_table_offset = find_record_by_filename(cluster, b'REGIST~1')

    if not dir_table_offset:
        sys.exit('/registered/ not found.')

    registered_cluster = get_cluster(cluster, dir_table_offset)
    registered_addr = cluster_to_address(registered_cluster, root_addr)
    print('/registered/ found at cluster', hex(registered_cluster + 2),
          'address', hex(registered_addr))

    print('')
    print('Scanning FAT for fragmentation...')
    FAT_addr = FAT['bytes per sector'] * FAT['sectors before FAT']
    registered_cluster_list = [registered_cluster]
    while registered_cluster_list[-1] != 0x0fffffff - 2:
        cluster_map_offset = (registered_cluster_list[-1] + 2) * 4
        cluster = read_cluster_from_file(f, FAT_addr + cluster_map_offset -
                                         cluster_map_offset % CLUSTER_SIZE)
        cluster_map_offset %= CLUSTER_SIZE
        registered_cluster_list += [int.from_bytes(
            cluster[cluster_map_offset:cluster_map_offset + 4],
            'little') - 2]
    registered_cluster_list.pop()
    print('/registered/ clusters: ', [hex(x + 2) for x in registered_cluster_list])

    # collapse the whole file list together
    cluster = b''.join([read_cluster_from_file(f, cluster_to_address(x, root_addr))
                        for x in registered_cluster_list])

    print('Buffered', len(cluster)//CLUSTER_SIZE, '/registered/ clusters. Reading filenames...')
    block_ptr = 0
    filename_list = list()
    while block_ptr < len(cluster):
        # if this is a LFN entry, the 3rd byte is the empty
        # upper byte of a UCS-2 encoded ASCII character
        if cluster[block_ptr + 2] != 0:
            block_ptr += 0x20
        elif cluster[block_ptr:block_ptr+4] == b'\x00\x00\x00\x00':
            break
        else:
            lfn_length = 0x20 * ((cluster[block_ptr] & 0x1f) + 1)
            filename = unpack_lfn(cluster[block_ptr:block_ptr+lfn_length])
            if filename[-4:] == '.nca':
                filename_list += [filename]
            block_ptr += lfn_length
    if not filename_list:
        sys.exit('Unable to retrieve filenames.')

    print('')
    print('Success! Found', len(filename_list), 'NCA filenames.')

    for version in SYSTEM_VERSION_TITLES:
        if version[1] in filename_list:
            print('')
            print('Firmware version found:', version[0], end='')
            if EXFAT_PACKAGEC_TITLES[version[0]] in filename_list:
                print(' (exFAT)')
            else:
                print(' (no exFAT)')
            print('Most recent boot:', most_recent_boot)
            break
    else:
        sys.exit('System Version Title not found!')
