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
### Generate passphrase from -n ? random letters (ab-zA-Z0-9)
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

