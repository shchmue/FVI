'''
Firmware Version Inspector by shchmue
Inspects firmware version from Nintendo Switch NAND dump
'''

import datetime
import os
import sys
from crypto import XTSN

CLUSTER_SIZE = 0x4000

SYSTEM_VERSION_TITLES = [ # NCA filenames for System Version Title
    ['8.1.0', '7eedb7006ad855ec567114be601b2a9d.nca'],
    ['8.0.1', '6c5426d27c40288302ad616307867eba.nca'],
    ['8.0.0', '4fe7b4abcea4a0bcc50975c1a926efcb.nca'],
    ['7.0.1', 'e6b22c40bb4fa66a151f1dc8db5a7b5c.nca'],
    ['7.0.0', 'c613bd9660478de69bc8d0e2e7ea9949.nca'],
    ['6.2.0', '6dfaaf1a3cebda6307aa770d9303d9b6.nca'],
    ['6.1.0', '1d21680af5a034d626693674faf81b02.nca'],
    ['6.0.1', '663e74e45ffc86fbbaeb98045feea315.nca'],
    ['6.0.0', '258c1786b0f6844250f34d9c6f66095b.nca'],
    ['6.0.0 (pre-release)', '286e30bafd7e4197df6551ad802dd815.nca'],
    ['5.1.0', 'fce3b0ea366f9c95fe6498b69274b0e7.nca'],
    ['5.0.2', 'c5758b0cb8c6512e8967e38842d35016.nca'],
    ['5.0.1', '7f5529b7a092b77bf093bdf2f9a3bf96.nca'],
    ['5.0.0', 'faa857ad6e82f472863e97f810de036a.nca'],
    ['4.1.0', '77e1ae7661ad8a718b9b13b70304aeea.nca'],
    ['4.0.1', 'd0e5d20e3260f3083bcc067483b71274.nca'],
    ['4.0.0', 'f99ac61b17fdd5ae8e4dda7c0b55132a.nca'],
    ['3.0.2', '704129fc89e1fcb85c37b3112e51b0fc.nca'],
    ['3.0.1', '9a78e13d48ca44b1987412352a1183a1.nca'],
    ['3.0.0', '7bef244b45bf63efb4bf47a236975ec6.nca'],
    ['2.3.0', 'd1c991c53a8a9038f8c3157a553d876d.nca'],
    ['2.2.0', '7f90353dff2d7ce69e19e07ebc0d5489.nca'],
    ['2.1.0', 'e9b3e75fce00e52fe646156634d229b4.nca'],
    ['2.0.0', '7a1f79f8184d4b9bae1755090278f52c.nca'],
    ['1.0.0', '117f7b9c7da3e8cef02340596af206b3.nca']
]

EXFAT_PACKAGEC_TITLES = { # NCA filenames for exFAT variant of Package C Titles
    '8.1.0': '96f4b8b729ade072cc661d9700955258.nca',
    '8.0.1': 'b2708136b24bbe206e502578000b1998.nca',
    '8.0.0': 'b2708136b24bbe206e502578000b1998.nca',
    '7.0.1': '02a2cbfd48b2f2f3a6cec378d20a5eff.nca',
    '7.0.0': '58c731cdacb330868057e71327bd343e.nca',
    '6.2.0': '97cb7dc89421decc0340aec7abf8e33b.nca',
    '6.1.0': 'd5186022d6080577b13f7fd8bcba4dbb.nca',
    '6.0.1': 'd5186022d6080577b13f7fd8bcba4dbb.nca',
    '6.0.0': 'd5186022d6080577b13f7fd8bcba4dbb.nca',
    '6.0.0 (pre-release)': '711b5fc83a1f07d443dfc36ba606033b.nca',
    '5.1.0': 'c9e500edc7bb0fde52eab246028ef84c.nca',
    '5.0.2': '432f5cc48e6c1b88de2bc882204f03a1.nca',
    '5.0.1': '432f5cc48e6c1b88de2bc882204f03a1.nca',
    '5.0.0': '432f5cc48e6c1b88de2bc882204f03a1.nca',
    '4.1.0': '458a54253f9e49ddb044642286ca6485.nca',
    '4.0.1': '090b012b110973fbdc56a102456dc9c6.nca',
    '4.0.0': '090b012b110973fbdc56a102456dc9c6.nca',
    '3.0.2': 'e7dd3c6cf68953e86cce54b69b333256.nca',
    '3.0.1': '17f9864ce7fe3a35cbe3e3b9f6185ffb.nca',
    '3.0.0': '9e5c73ec938f3e1e904a4031aa4240ed.nca',
    '2.3.0': '4a94289d2400b301cbe393e64831f84c.nca',
    '2.2.0': '4a94289d2400b301cbe393e64831f84c.nca',
    '2.1.0': '4a94289d2400b301cbe393e64831f84c.nca',
    '2.0.0': 'f55a04978465ebf5666ca93e21b26dd2.nca',
    '1.0.0': '3b7cd379e18e2ee7e1c6d0449d540841.nca'
}

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
    d = datetime.datetime(1980 + (date >> 9), (date >> 5) & 0xf, date & 0x1f,
                          time >> 11, (time >> 5) & 0x3f, time & 0x1f)
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

bis_key_file = None
for arg in sys.argv[1:]:
    if arg[:3].lower() == '-b=':
        bis_key_file = arg[3:]
    else:
        dump_file = arg

if not os.path.exists(dump_file):
    sys.exit('Dump file ' + dump_file + ' not found.')

system_offset = 0
if os.stat(dump_file).st_size == 0x747c00000:
    print('Dump is full EMMC raw NAND.')
    system_offset = 0x7800000
elif os.stat(dump_file).st_size == 0xa0000000:
    print('Dump is System partition.')
else:
    print('Unrecognized file size.')

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
        if os.stat(dump_file).st_size >= 0x7800000 + CLUSTER_SIZE:
            system_offset = 0x7800000
            cluster = read_cluster_from_file(f, 0)
            if not is_fat32(cluster):
                sys.exit('FAT boot sector not found! Check BIS keys.')
        else:
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
