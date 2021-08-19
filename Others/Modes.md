![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/4.jpg "LostCoins")
## Project idea to find orphaned lost BitCoins
 - When Satoshi Nakamoto launched Bitcoin in 2009, he used Uncopressed addresses.
 - He found out about the existence of Compressed addresses only at the beginning of 2012.
 - The developer suggested using compressed addresses to ease the load on the network.
 - On March 31, 2012, BitCoin Core v0.6 was released in which Compressed was used to generate new addresses.
 - Outwardly, you will not see the difference between Legacy compressed and uncompressed addresses! 
 - From [dumps](https://blockchair.com/dumps) transactions on 03/31/2012, I collected a [database](https://github.com/phrutis/LostCoins/blob/main/Others/Un-all.txt) of uncompressed addresses with a positive balance for today.
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

- There is a ready-made file for tests is `test.bin` inside 4 words of 3 letters Uncomressed: cat, gaz, for, car Compressed abc, cop, run, zip. [Make your own](https://brainwalletx.github.io/) addressed for test
- **For search words USE modes -u or -b** It is slower then increases the chance of finding a word

# Examples of how to use modes in LostCoins
 ![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/3.jpg "LostCoins")
## Mode 5
### Generate passphrase from -n ? random digits (0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 5 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 5 -n 8 -d 0```
## Mode 6
### Generate passphrase from -n ? random letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 6 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 6 -n 8 -d 0```
## Mode 7
### Generate passphrase from -n ? random letters (A-Z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 7 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 7 -n 8 -d 0```
## Mode 8
### Generate passphrase from -n ? random letters (a-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 8 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 8 -n 8 -d 0```
## Mode 9
### Generate passphrase from -n ? random letters (A-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 9 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 9 -n 8 -d 0```
## Mode 10
### Generate passphrase from -n ? random letters (A-Za-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 10 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 10 -n 8 -d 0```
## Mode 11
### Generate passphrase from -n ? random letters (ab-zA-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 11 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 11 -n 8 -d 0```
## Mode 12
### Generate passphrase from -n ? random letters (a-zA-Z0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 12 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 12 -n 8 -d 0```

 ![alt text](https://github.com/phrutis/LostCoins/blob/main/Others/2.jpg "LostCoins")
## Mode 13
### Generate passphrase from -n ? random russian letters (а-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 13 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 13 -n 8 -d 0```
## Mode 14
### Generate passphrase from -n ? random russian letters (А-Я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 14 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 14 -n 8 -d 0```
## Mode 15
### Generate passphrase from -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 15 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 15 -n 8 -d 0```
## Mode 16
### Generate passphrase from -n ? random russian letters (А-Яа-я0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 16 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 16 -n 8 -d 0```
## Mode 17
### Generate passphrase from -n ? random russian letters (А-Я-я0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 17 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 17 -n 8 -d 0```
## Mode 18
### Generate passphrase from words+ -n ? random digits (0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 18 -n 8 -s Word word2 word3 is work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 18 -n 8 -s Word word2 word3 is work -d 0```
## Mode 19
### Generate passphrase from words+ -n ? random letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 19 -n 8 -s Bitcoin -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 19 -n 8 -s Bitcoin -d 0```
## Mode 20
### Generate passphrase from words+ -n ? random letters (A-Z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 20 -n 8 -s Bitcoin -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 20 -n 8 -s Bitcoin -d 0```
## Mode 21
### Generate passphrase from words+ -n ? random letters (a-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 21 -n 8 -s Bitcoin -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 21 -n 8 -s Bitcoin -d 0```
## Mode 22
### Generate passphrase from words+ -n ? random letters (A-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 22 -n 8 -s Bitcoin -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 22 -n 8 -s Bitcoin -d 0```
## Mode 23
### Generate passphrase from words+ -n ? random letters (A-Za-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 23 -n 8 -s Bitcoin -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 23 -n 8 -s Bitcoin -d 0```
## Mode 24
### Generate passphrase from words+ -n ? random letters (a-zA-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 24 -n 8 -s Bitcoin -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 24 -n 8 -s Bitcoin -d 0```
## Mode 25
### Generate passphrase from words+ -n ? random letters (a-zA-Z0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 25 -n 8 -s Bitcoin Bitcoin2 is work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 25 -n 8 -s Bitcoin Bitcoin2 is work -d 0```
## Mode 26
### Generate passphrase from words+ -n ? random russian letters (а-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 26 -n 8 -s Приве -d 0т```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 26 -n 8 -s Можно слова через пробел -d 0```
## Mode 27
### Generate passphrase from words+ -n ? random russian letters (А-Я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 27 -n 8 -s Привет -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 27 -n 8 -s Слова можно через пробел -d 0```
## Mode 28
### Generate passphrase from words+ -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 28 -n 8 -s Привет -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 28 -n 8 -s Слова можно через пробел -d 0``` 
## Mode 29
### Generate passphrase from words+ -n ? random russian letters (А-Яа-я0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 29 -n 8 -s Привет -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 29 -n 8 -s Слова можно через пробел -d 0``` 
## Mode 30
### Generate passphrase from words+ -n ? random russian letters (А-Яа-я0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 30 -n 8 -s Привет -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 30 -n 8 -s Слова можно через пробел -d 0``` 
## Mode 31
### Generate passphrase from words(space)+ -n ? random letters (0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 31 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 31 -n 8 -s HELLO its work -d 0```
## Mode 32
### Generate passphrase from words(space)+ -n ? random letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 32 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 32 -n 8 -s HELLO its work -d 0```
## Mode 33
### Generate passphrase from words(space)+ -n ? random letters (A-Z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 33 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 33 -n 8 -s HELLO its work -d 0```
## Mode 34
### Generate passphrase from words(space)+ -n ? random letters (a-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 34 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 34 -n 8 -s HELLO its work -d 0```
## Mode 35
### Generate passphrase from words(space)+ -n ? random letters (A-Z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 35 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 35 -n 8 -s HELLO its work -d 0```
## Mode 36
### Generate passphrase from words(space)+ -n ? random letters (A-Za-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 36 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 36 -n 8 -s HELLO its work -d 0```
## Mode 37
### Generate passphrase from words(space)+ -n ? random letters (A-Za-z0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 37 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 37 -n 8 -s HELLO its work -d 0```
## Mode 38
### Generate passphrase from words(space)+ -n ? random letters (A-Za-z0-9+symbols)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 38 -n 8 -s HELLO its work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 38 -n 8 -s HELLO its work -d 0```
## Mode 39
### Generate passphrase from words(space)+ -n ? random russian letters (а-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 39 -n 8 -s Юля -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 39 -n 8 -s Вася -d 0```
## Mode 40
### Generate passphrase from words(space)+ -n ? random russian letters (А-Я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 40 -n 8 -s Юля -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 40 -n 8 -s Вася -d 0```
## Mode 41
### Generate passphrase from words(space)+ -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 41 -n 8 -s Юля -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 41 -n 8 -s Вася -d 0```
## Mode 42
### enerate passphrase from words(space)+ -n ? random russian letters (А-Яа-я)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 42 -n 8 -s Юля -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 42 -n 8 -s Вася -d 0```
## Mode 43
### Generate passphrase from words(space)+ -n ? random russian letters (А-Яа-я0-9)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 43 -n 8 -s Юля -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 43 -n 8 -s Вася -d 0```
## Mode 44
### Generate passphrase use mask L(llllllll)dd
#### Generate a words Alex78, Julia92...
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 44 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 44 -n 8 -d 0```
## Mode 45
### Generate passphrase use mask L(llllllll)dddd
#### Generate a words Alex1978, Julia1992...
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 45 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 45 -n 8 -d 0```
## Mode 46
### Generate passphrase use mask L(llllllll)dddddd
#### Generate a words Alex301978, Julia201992...
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 46 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 46 -n 8 -d 0```
## Mode 47
### Generate random 2 word 3-9 letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 47 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 47 -d 0```
## Mode 48
### Passphrase(space) + random 2 word 3-9 letters (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 48 -s LostCoins is work -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 48 -s LostCoins is work -d 0```
## Mode 49
### Mnemonic 12 words 3-5 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 49 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 49 -d 0```
## Mode 50
### Mnemonic 12 words 3-7 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 50 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 50 -d 0``` 
## Mode 51
### Mnemonic 12 words 3-10 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 51 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 51 -d 0``` 
## Mode 52
### Passphrase(space)+ 2 random words 3-9 (a-z)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 52 -n 8 -s HELLO -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 52 -n 8 -s HELLO -d 0```
## Mode 53 In development
### Sequential continuation of the starting word
#### Very slow algaritm (For one CPU core only!)
#### Passphrase -> Passphrasf -> PaszzzzzzZ - ZZZZZZZZZZZ (Uld)
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 53 -s Example -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 53 -s Hello -d 0```
## Mode 54
### Generate pass from -n ? random symbols
 - For CPU: ```LostCoins.exe -t 1 -f test.bin -r 54 -n 8 -d 0```
 - For GPU: ```LostCoins.exe -t 0 -g -i 0 -f test.bin -r 54 -n 8 -d 0```

## Mode 55-99 Possible modes.
 - Generate a mnemonic of words from a file
 - Loading phrases from a text file
 - Sequential generation of letters on the GPU Example: aaa, aab, aaZ, ZZZZ...
 - Setting a mask for generating words [Example mask](https://github.com/hashcat/maskprocessor)
 - The function of adding different languages to generate passphrases
 - If you are a programmer and can implement additional functions for LostCoins, this is welcome.

