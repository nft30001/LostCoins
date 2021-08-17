# LostCoins v1.0
![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/4.jpg "LostCoins")
This is a modified version [VanitySearch](https://github.com/JeanLucPons/VanitySearch/). 
Huge thanks [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in LostCoins.
## Project idea to find orphaned lost BitCoins
 - When Satoshi Nakamoto launched Bitcoin in 2009, he used Uncopressed addresses.
 - He found out about the existence of Compressed addresses only at the beginning of 2012.
 - The developer suggested using compressed addresses to ease the load on the network.
 - On March 31, 2012, BitCoin Core v0.6 was released in which Compressed was used to generate new addresses.
 - Outwardly, you will not see the difference between Legacy compressed and uncompressed addresses! 
 - From dumps transactions on 03/31/2012, I collected a [database](https://github.com/phrutis/LostCoins/blob/main/Others/Un-all.txt) of uncompressed addresses with a positive balance for today.
 - Until 03/31/2012, most addresses were created using a [passphrase converted to a hash of Sha256](https://brainwalletx.github.io/) Bitcoin then cost a penny, the phrases were lost, and with them coins.
 - The task is to find a passphrase for old addresses from the database.For this task, LostCoins has many built-in word selection modes. 
 - Choose the best mode and start looking for coins 
You may be interested - [Why random is faster than brute force](https://github.com/phrutis/LostCoins/blob/main/Others/Random.md)
### For reference.
 - A total of 3,157,143 uncompressed addresses were created.
 - Today with a positive balance in total: 464.005 uncompressed [download](https://github.com/phrutis/LostCoins/blob/main/Others/Un-all.txt) addresses.
 - Sorted uncompressed addresses from 0.1 btc and higher. Happened: 75462 [download](https://github.com/phrutis/LostCoins/blob/main/Others/Un01.txt) addresses
 - Total words found [18972](https://allprivatekeys.com/hacked-brainwallets-with-balance) with addresses on which there were coins 
 - To check, we take any address from the file. We go to the blockchain and see the date of the first transaction. 
 - The first transaction must be before 03/31/2012, this confirms that the address is not compressed. 
## How to start
- For the program to work, you need to convert Legacy addresses (which start with 1) into binary hashes 160 RIPEMD160.
- Use the program to convert b58dec.exe Сommand: ```b58dec.exe 1.txt 2.bin```
- It is important to sort the 2.bin file otherwise the Bloom search filter will not work as expected.
- To sort 2.bin use the program RMD160-Sort.exe Сommand: ```RMD160-Sort.exe 2.bin addresse160-Sort.bin```
- The minimum number of hashes160 in addresse160-Sort.bin must be at least 1000
- There is a ready-made file for tests is `test.bin` inside 4 words of 3 letters Uncomressed: cat, gaz, for, car Compressed abc, cop, run, zip. [Make your own](https://brainwalletx.github.io/) addressed for test
- For Multi GPUs use LostCoins.exe -t 0 --gpu --gpux 256,256,256,256 --gpui 0,1 -f test.bin -r 4 -n 3
- -x default auto Grid size. Example my RTX2070 in auto -x 256,128 I added LostCoins.exe -t 0 -g -i 0 -x 288,512 -f test.bin -r 4 -n 3 the speed has doubled.
- Do not use the GPU + CPU will drop the speed. It is better to run 2 copies of the program one on the CPU and the second on the GPU
- **For search words USE modes -u or -b** It is slower then increases the chance of finding a word
- You can search hashes160 of other coins, if it finds it, it will give an empty legacy address
## Parametrs:
```
Usage: LostCoins [options...]
Options:
    -v, --version          Print version. For help visit https://github.com/phrutis/LostCoins
    -c, --check            Check the working of the code
    -u, --uncomp           Search only uncompressed addresses Default: search compressed addresses
    -b, --both             Search both (uncompressed and compressed addresses)
    -g, --gpu              Enable GPU calculation
    -i, --gpui             GPU ids: 0,1...: List of GPU(s) to use, default is 0
    -x, --gpux             GPU gridsize: g0x,g0y,g1x,g1y, ...: Specify GPU(s) kernel gridsize, default is 8*(MP number),128
    -o, --out              Outputfile: Output results to the specified file, default: Found.txt
    -m, --max              Maximum positive results of addresses. Default: 100
    -t, --thread           threadNumber: Specify number of CPU thread, default is number of core
    -e, --nosse            Disable SSE hash function
    -l, --list             List cuda enabled devices
    -r, --rkey             0-60 number random modes
    -n, --nbit             Number of letters in word or number bit range 1-256
    -f, --file             RIPEMD160 binary hash file path
    -s, --seed             PassPhrase   (Start bit range)
    -z, --zez              PassPhrase 2 (End bit range)
    -d, --diz              Display modes -d 1 Show hashes, SLOW speed. -d 2 only counters, the fastest speed. -d 0 default
    -k, --color            Color text in console 1-255 Recommended colors: 3, 10, 11, 14, 15, 240(White-black) Default: 15
    -h, --help             Shows this page

 ```
## Example of work 
 ```
C:\Users\user>LostCoins.exe -b -t 0 -g -i 0 -x 288,512 -f test.bin -r 5 -n 3 -d 1

 LostCoins v1.0

 SEARCH MODE  : COMPRESSED & UNCOMPRESSED
 DEVICE       : GPU
 CPU THREAD   : 0
 GPU IDS      : 0
 GPU GRIDSIZE : 288x512
 RANDOM MODE  : 5
 ROTOR SPEED  : SLOW (hashes sha256 are displayed)
 CHARACTERS   : 3
 PASSPHRASE   :
 PASSPHRASE 2 :
 DISPLAY MODE : 1
 TEXT COLOR   : 15
 MAX FOUND    : 100
 HASH160 FILE : test.bin
 OUTPUT FILE  : Found.txt

Loading       : 100 %
Loaded        : 75,471 address

Bloom at 000002B4B4F6C900
  Version     : 2.1
  Entries     : 150942
  Error       : 0,0000010000
  Bits        : 4340363
  Bits/Elem   : 28,755175
  Bytes       : 542546 (0 MB)
  Hash funcs  : 20

  Start Time  : Tue Aug 17 00:12:58 2021

  Random mode : 5
  Passphrase  : (not supported)
  Using       : 26 letters
  List        : abcdefghijklmnopqrstuvwxyz
  Rotor       : Generation of 3 random letters
  Site        : https://github.com/phrutis/LostCoins
  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  GPU         : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)

 [iwp] [A0D9E4213834CE56775CF203FD8F0C93FC55D73EA905B669D4834EDE19A9A6C6]
 ```
# Examples of how to use modes in LostCoins
 ![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/2.jpg "LostCoins")
## Mode 0
### Generate passphrase from 3-9 random letters (a-z test)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 0```
## Mode 1
### Generate random public keys in bit range (Rotor-Cuda-R1)
#### Constant random generation of new hashes
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 1 -n 256```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 1 -n 256```
## Mode 2
### Generate random public keys in bit range (Rotor-Cuda)
#### Generating random hashes +value. Loading new hashes every 50.000.000.000 on the counter 
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 2 -n 256```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 2 -n 256```
## Mode 3
### Generate random public keys in bit range (Rotor-Cuda)
#### Generating random hashes +value. Loading new hashes every 100.000.000.000 on the counter 
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 3 -n 256```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 3 -n 256```
## Mode 4
### Generate passphrase from -n ? random digits (0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 4 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 4 -n 8```
## Mode 5
### Generate passphrase from -n ? random letters (ab-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 5 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 5 -n 8```
## Mode 6
### Generate passphrase from -n ? random letters (A-Z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 6 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 6 -n 8```
## Mode 7
### Generate passphrase from -n ? random letters (a-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 7 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 7 -n 8```
## Mode 8
### Generate passphrase from -n ? random letters (A-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 8 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 8 -n 8```
## Mode 9
### Generate passphrase from -n ? random letters (A-Za-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 9 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 9 -n 8```
## Mode 10
### Generate passphrase from -n ? random letters (a-zA-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 10 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 10 -n 8```
## Mode 11
### Generate passphrase from -n ? random letters (a-zA-Z0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 11 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 11 -n 8```
## Mode 12
### Generate passphrase from -n ? random russian letters (а-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 12 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 12 -n 8```
## Mode 13
### Generate passphrase from -n ? random russian letters (А-Я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 13 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 13 -n 8```
## Mode 14
### Generate passphrase from -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 14 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 14 -n 8```
## Mode 15
### Generate passphrase from -n ? random russian letters (А-Яа-я0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 15 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 15 -n 8```
## Mode 16
### Generate passphrase from -n ? random russian letters (А-Я-я0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 16 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 16 -n 8```
## Mode 17
### Generate passphrase from words+ -n ? random digits (0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 17 -n 8 -s Word word2 word3 is work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 17 -n 8 -s Word word2 word3 is work```
## Mode 18
### Generate passphrase from words+ -n ? random letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 18 -n 8 -s Bitcoin```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 18 -n 8 -s Bitcoin```
## Mode 19
### Generate passphrase from words+ -n ? random letters (A-Z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 19 -n 8 -s Bitcoin```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 19 -n 8 -s Bitcoin```
## Mode 20
### Generate passphrase from words+ -n ? random letters (a-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 20 -n 8 -s Bitcoin```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 20 -n 8 -s Bitcoin```
## Mode 21
### Generate passphrase from words+ -n ? random letters (A-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 21 -n 8 -s Bitcoin```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 21 -n 8 -s Bitcoin```
## Mode 22
### Generate passphrase from words+ -n ? random letters (A-Za-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 22 -n 8 -s Bitcoin```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 22 -n 8 -s Bitcoin```
## Mode 23
### Generate passphrase from words+ -n ? random letters (a-zA-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 23 -n 8 -s Bitcoin```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 23 -n 8 -s Bitcoin```
## Mode 24
### Generate passphrase from words+ -n ? random letters (a-zA-Z0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 24 -n 8 -s Bitcoin Bitcoin2 is work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 24 -n 8 -s Bitcoin Bitcoin2 is work```
## Mode 25
### Generate passphrase from words+ -n ? random russian letters (а-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 25 -n 8 -s Привет```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 25 -n 8 -s Можно слова через пробел```
## Mode 26
### Generate passphrase from words+ -n ? random russian letters (А-Я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 26 -n 8 -s Привет```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 26 -n 8 -s Слова можно через пробел```
## Mode 27
### Generate passphrase from words+ -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 27 -n 8 -s Привет```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 27 -n 8 -s Слова можно через пробел``` 
## Mode 28
### Generate passphrase from words+ -n ? random russian letters (А-Яа-я0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 28 -n 8 -s Привет```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 28 -n 8 -s Слова можно через пробел``` 
## Mode 29
### Generate passphrase from words+ -n ? random russian letters (А-Яа-я0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 29 -n 8 -s Привет```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 29 -n 8 -s Слова можно через пробел``` 
## Mode 30
### Generate passphrase from words(space)+ -n ? random letters (0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 30 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 30 -n 8 -s HELLO its work```
## Mode 31
### Generate passphrase from words(space)+ -n ? random letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 31 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 31 -n 8 -s HELLO its work```
## Mode 32
### Generate passphrase from words(space)+ -n ? random letters (A-Z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 32 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 32 -n 8 -s HELLO its work```
## Mode 33
### Generate passphrase from words(space)+ -n ? random letters (a-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 33 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 33 -n 8 -s HELLO its work```
## Mode 34
### Generate passphrase from words(space)+ -n ? random letters (A-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 34 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 34 -n 8 -s HELLO its work```
## Mode 35
### Generate passphrase from words(space)+ -n ? random letters (A-Za-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 35 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 35 -n 8 -s HELLO its work```
## Mode 36
### Generate passphrase from words(space)+ -n ? random letters (A-Za-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 36 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 36 -n 8 -s HELLO its work```
## Mode 37
### Generate passphrase from words(space)+ -n ? random letters (A-Za-z0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 37 -n 8 -s HELLO its work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 37 -n 8 -s HELLO its work```
## Mode 38
### Generate passphrase from words(space)+ -n ? random russian letters (а-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 38 -n 8 -s Юля```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 38 -n 8 -s Вася```
## Mode 39
### Generate passphrase from words(space)+ -n ? random russian letters (А-Я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 39 -n 8 -s Юля```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 39 -n 8 -s Вася```
## Mode 40
### Generate passphrase from words(space)+ -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 40 -n 8 -s Юля```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 40 -n 8 -s Вася```
## Mode 41
### enerate passphrase from words(space)+ -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 41 -n 8 -s Юля```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 41 -n 8 -s Вася```
## Mode 42
### Generate passphrase from words(space)+ -n ? random russian letters (А-Яа-я0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 42 -n 8 -s Юля```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 42 -n 8 -s Вася```
## Mode 43
### Generate passphrase use mask L(llllllll)dd
#### Generate a words Alex78, Julia92...
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 43 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 43 -n 8```
## Mode 44
### Generate passphrase use mask L(llllllll)dddd
#### Generate a words Alex1978, Julia1992...
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 44 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 44 -n 8```
## Mode 45
### Generate passphrase use mask L(llllllll)dddddd
#### Generate a words Alex301978, Julia201992...
 - For CPU: LostCoins.exe -t 1 -f test.bin -r 45 -n 8
 - For GPU: LostCoins.exe -t 0 -g -i 0 -f test.bin -r 45 -n 8 
## Mode 46
### Generate random 2 word 3-9 letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 46```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 46```
## Mode 47
### Passphrase(space) + random 2 word 3-9 letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 47 -s LostCoins is work```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 47 -s LostCoins is work```
## Mode 48
### Mnemonic 12 words 3-5 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 48```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 48```
## Mode 49
### Mnemonic 12 words 3-7 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 49```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 49``` 
## Mode 50
### Mnemonic 12 words 3-10 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 50```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 50``` 
## Mode 51
### Passphrase(space)+ 2 random words 3-9 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 51 -n 8 -s HELLO```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 51 -n 8 -s HELLO```
## Mode 52
### Start hex+ -n random value(0-f)
#### Examle for puzzle 64
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 52 -n 15 -s 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 52 -n 15 -s 8```
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 52 -n 10 -s 800000```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 52 -n 10 -s 800000```
## Mode 53
### Generate random Public keys in a specific bit range 1-256 bit
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 53 -n 256```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 53 -n 256```
#### For random in all ranges use -n 0 to display hashes, use -d 1
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 53 -n 0 -d 1```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 53 -n 0 -d 1```
## Mode 54 In development
### Sequential continuation of the starting word
#### Very slow algaritm (For one CPU core only!)
#### Passphrase -> Passphrasf -> PaszzzzzzZ - ZZZZZZZZZZZ (Uld)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 54 -s Example```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 54 -s Hello```
## Mode 55
### Generate pass from -n ? random symbols
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 55 -n 8```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 55 -n 8```
## Mode 56
### Random generation in the range between the start and end hash
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 56 -s 4c844bcb8681f0fedd56d5babf -z 8526c8820af81a94616040745a633eaf89 -d 1```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 56 --s 1c844bcb8681f0fedd56d5babf -z d526c8820af81a94616040745a633eaf89 -d 1```
 - After the tests, disable the display of hashes -d 2
## Mode 57-99 Possible modes.
 - Generate a mnemonic of words from a file
 - Loading phrases from a text file
 - Sequential generation of letters on the GPU Example: aaa, aab, aaZ, ZZZZ...
 - Setting a mask for generating words [Example mask](https://github.com/hashcat/maskprocessor)
 - The function of adding different languages to generate passphrases
 - If you are a programmer and can implement additional functions for LostCoins, this is welcome.
## Building
- Microsoft Visual Studio Community 2019
- CUDA version 10.22
## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9
