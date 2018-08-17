# Firmware Version Inspector ![License](https://img.shields.io/badge/License-GPLv3-blue.svg)
Scans a Nintendo Switch NAND dump and identifies its firmware version and whether exFAT is present based on the names of the .nca files in SYSTEM:/Contents/registered.

## Usage
Requires Python 3 with pycryptodome (pycrypto works too):
```
pip install pycryptodome
```
`FVI` uses BIS key 2 if the System partition is still encrypted (i.e. a backup made with [Hekate](https://github.com/CTCaer/hekate)). Get BIS keys with [biskeydump](https://github.com/rajkosto/biskeydump) and save the output to a text file to pass to `FVI` via the -b option.

Then run from command line:
```
python FVI.py [-b=/path/to/biskeyfile] <dumpfile>

 biskeyfile must contain the following lines:
   BIS Key 2 (crypt): <32-digit hex key>
   BIS Key 2 (tweak): <32-digit hex key>
  omit -b if System partition already decrypted (eg. dumped with HacDiskMount)

 dumpfile must be NAND dump (eg. Hekate rawnand.bin dump) or System partition
```

Tested under Windows 10 with Anaconda Python 3.6.5 and Ubuntu 16.04 LTS with Python 3.5.2.

## Theory
Until now, this could only be done by manually checking the files in that folder after mounting with [HacDiskMount](https://switchtools.sshnuke.net/) or [memloader](https://github.com/rajkosto/memloader) then either comparing to an existing list or decrypting and inspecting each .nca file with [hactool](https://github.com/SciresM/hactool) in search of the [System Version Title](https://switchbrew.org/index.php?title=System_Version_Title).

This program consults a hard-coded file list obtained using these techniques. It will be updated as future firmware versions are released to keep it fast and low on dependencies.

## Credits
`crypto.py` module is from [switchfs](https://github.com/ihaveamac/switchfs/blob/master/switchfs/crypto.py) under MIT license - it was in turn ported to Python 3 from [crypto.py](https://gist.github.com/plutooo/fd4b22e7f533e780c1759057095d7896) gist by [plutooo](https://github.com/plutooo)

Big thanks to [the Wikipedia entry on FAT layout](https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system) :) - being able to read the dump disjointly means `FVI` only needs to fetch and decrypt a small handful of clusters rather than the entire 2 or 32GB file!
