# LostCoins
 - This is a modified version [VanitySearch](https://github.com/JeanLucPons/VanitySearch/). 
Huge thanks [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in LostCoins.
## Quick start
- Сonvert addresses into binary hashes RIPEMD160 use [b58dec.exe](https://github.com/phrutis/LostCoins/blob/main/Others/b58dec.exe) Сommand: ```b58dec.exe 1.txt 2.bin```
- It is important to sort the 2.bin file otherwise the Bloom search filter will not work as expected.
- To sort 2.bin use the program [RMD160-Sort.exe](https://github.com/phrutis/LostCoins/blob/main/Others/RMD160-Sort.exe) Сommand: ```RMD160-Sort.exe 2.bin addresse160-Sort.bin``` 
- The minimum number of hashes160 in addresse160-Sort.bin must be at least 1000
- For Multi GPUs use LostCoins.exe -t 0 --gpu --gpux 256,256,256,256 --gpui 0,1 -f test.bin -r 2 -n 64
- Default auto Grid size. Example my RTX2070 in auto -x 256,128 I added LostCoins.exe -t 0 -g -i 0 -x 288,512 the speed has doubled.
- Do not use the GPU+CPU will drop the speed. Run 2 copies of the program one on the CPU and the second on the GPU
- You can search hashes160 of other coins, if it finds it, it will give an empty legacy address and positive private key. Ctrl + C (exit)
## Parametrs:
```
C:\Users\user>LostCoins.exe -h
Usage: LostCoins [options...]
Options:
    -v, --version          Print version. For help visit https://github.com/phrutis/LostCoins
    -c, --check            Check the working of the code LostCoins
    -u, --uncomp           Search only uncompressed addresses
    -b, --both             Search both (uncompressed and compressed addresses)
    -g, --gpu              Enable GPU calculation
    -i, --gpui             GPU ids: 0,1...: List of GPU(s) to use, default is 0
    -x, --gpux             GPU gridsize: g0x,g0y,g1x,g1y, ...: Specify GPU(s) kernel gridsize, default is 8*(MP number),128
    -t, --thread           ThreadNumber: Specify number of CPUs thread, default is number of core
    -o, --out              Outputfile: Output results to the specified file, default: Found.txt
    -m, --max              Specify maximun number of addresses found by each kernel call
    -s, --seed             PassPhrase   (Start bit range)
    -z, --zez              PassPhrase 2 (End bit range)
    -e, --nosse            Disable SSE hash function
    -l, --list             List cuda enabled devices
    -r, --rkey             Number of random modes
    -n, --nbit             Number of letters and number bit range 1-256
    -f, --file             RIPEMD160 binary hash file path
    -d, --diz              Display modes -d 0 [info+count], -d 1 SLOW speed [info+hex+count], Default -d 2 [count] HIGH speed
    -k, --color            Colors: 1-255 Recommended 3, 10, 11, 14, 15, 240 (White-black)
    -h, --help             Shows this pagethis page

 ```
## Mode 0 (For CPU) 
### Constant generation random new hashes in a given range +- ~ 4 bit
 ```
C:\Users\user>LostCoins.exe -t 6 -f test.bin -r 0 -n 64

 LostCoins v1.0

 SEARCH MODE  : COMPRESSED
 DEVICE       : CPU
 CPU THREAD   : 6
 GPU IDS      : 0
 GPU GRIDSIZE : -1x128
 RANDOM MODE  : 0
 ROTOR SPEED  : HIGH
 CHARACTERS   : 64
 PASSPHRASE   :
 PASSPHRASE 2 :
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 MAX FOUND    : 256
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 00000208E842B400
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Aug 19 11:10:12 2021

  Random mode : 0
  Mode        : Constant generation random hashes
  Reload      : Every 1 hex new
  How work R0 : Cores generate hashes into a buffer
  How work R0 : After they are sent to the device for checking with a bloom filter to find a positive bitcoin address.
  How work R0 : Good speed for CPUs. For GPUs -r 0 slow! Use other mode -r 1,2,3,4 for speed
  Range bit   : 64 (bit) recommended -n 256 (256 searches in the 256-252 range and below)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

 [00:01:26] [CPU+GPU: 13,83 Mk/s] [GPU: 0,00 Mk/s] [T: 1,193,570,304] [F: 0]
 ```
## Mode 1 
### Random search between start and end hash
 ```
 C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 1 -s ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000 -z ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff

 LostCoins v1.0

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 1
 ROTOR SPEED  : HIGH
 CHARACTERS   : 0
 PASSPHRASE   : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f0000000
 PASSPHRASE 2 : ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61ffffffff
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 MAX FOUND    : 256
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 00000278FADDCBF0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Aug 19 11:21:51 2021

  Random mode : 1
  Random      : Finding in a ranges
  Global start: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F0000000 (256 bit)
  Global end  : BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61FFFFFFFF (256 bit)
  Global range: FFFFFFF (28 bit)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [00:00:22] [CPU+GPU: 1217,95 Mk/s] [GPU: 1217,95 Mk/s] [T: 27,179,089,920] [F: 0]

=================================================================================
* PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
* Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
* Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
=================================================================================

 [00:00:24] [CPU+GPU: 1216,69 Mk/s] [GPU: 1216,69 Mk/s] [T: 29,896,998,912] [F: 1]

=================================================================================
* PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
* Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
* Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
=================================================================================



=================================================================================
* PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
* Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
* Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
=================================================================================

 [00:00:30] [CPU+GPU: 1215,80 Mk/s] [GPU: 1215,80 Mk/s] [T: 37,144,756,224] [F: 3]

=================================================================================
* PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
* Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
* Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
=================================================================================



=================================================================================
* PubAddress: 1PoQRMsXyQFSqCCRek7tt7umfRkJG9TY8x
* Priv (WIF): p2pkh: L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm
* Priv (HEX): BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
=================================================================================

 [00:00:32] [CPU+GPU: 1161,06 Mk/s] [GPU: 1161,06 Mk/s] [T: 38,956,695,552] [F: 5]

BYE
 ```
 
 ## Mode 2 (Best speed GPU)
 ### Exact accurate bit by bit search in a range
 - For CPU ```LostCoins.exe -t 6 -f test.bin -r 2 -n 64```
 - For GPU ```LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 2 -n 64```
 ```
 C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 2 -n 64

 LostCoins v1.0

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 2
 ROTOR SPEED  : HIGH
 CHARACTERS   : 64
 PASSPHRASE   :
 PASSPHRASE 2 :
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 MAX FOUND    : 256
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000020DFA65CAC0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Aug 19 12:29:08 2021

  Random mode : 2
  Random      : Finding in a range
  Use range   : 64 (bit)
  Rotor       : Random generate hex in range 64 (bit)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [00:01:03] [CPU+GPU: 1274,81 Mk/s] [GPU: 1274,81 Mk/s] [T: 77,007,421,440] [F: 0]
 ```
 ## Mode 3
 ### Search randomly for hash part + -n values (0-f)
 For finding a puzzles 64 example: 
 LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 3 -n 15 -s 8 -d 1
 ```
 C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 3 -n 10 -s f01cfea414140de5dae2223b0036 -d 1

 LostCoins v1.0

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 3
 ROTOR SPEED  : SLOW (hashes sha256 are displayed)
 CHARACTERS   : 10
 PASSPHRASE   : f01cfea414140de5dae2223b0036
 PASSPHRASE 2 :
 DISPLAY MODE : 1
 TEXT COLOR   : 15
 MAX FOUND    : 50
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 000001BE7A7EC9D0
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Aug 19 13:34:39 2021

  Random mode : 3
  Random      : Finding a puzzle in a ranges
  Start       : f01cfea414140de5dae2223b00360000000001
  Finish      : f01cfea414140de5dae2223b0036ffffffffff
  Range       : f01cfea414140de5dae2223b0036 + 10 x (0-f)
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [F01CFEA414140DE5DAE2223B0036A3F92F05BA] (152 bit)
 ```
 
  ## Mode 4 (Best speed GPU)
  ### Exact random search between specified ranges
 ```
 C:\Users\user>LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 4 -s 64 -z 72

 LostCoins v1.0

 SEARCH MODE  : COMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 4
 ROTOR SPEED  : HIGH
 CHARACTERS   : 0
 PASSPHRASE   : 64
 PASSPHRASE 2 : 72
 DISPLAY MODE : 2
 TEXT COLOR   : 15
 MAX FOUND    : 50
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

 Loading      : 100 %
 Loaded       : 75,471 address

Bloom at 0000024CFFD6D970
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Thu Aug 19 13:49:09 2021

  Random mode : 4
  Random      : Finding in a range
  Start range : 64 (bit)
  End range   : 72 (bit)
  Rotor       : Generate random hex in ranges 64 <~> 72
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [00:01:46] [CPU+GPU: 1284,81 Mk/s] [GPU: 1214,81 Mk/s] [T: 124,117,843,968] [F: 0]
 ```
## Modes 5-54 (additional)
### Find lost coins using a passphrase 
### Find lost coins with mnemonic 12 random words
- [List of additional 5-54 modes](https://github.com/phrutis/LostCoins/blob/main/Others/Modes.md)

## Building
- Microsoft Visual Studio Community 2019
- CUDA version 10.22
## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9
## License
LostCoins is licensed under GPL v3.0
## Disclaimer
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.
