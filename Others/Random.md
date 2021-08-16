## Conjecture why random is better than brute force
<br>Having studied a large number of Private Keys, including which once had coins, I came to a conclusion. 
<br>Almost never come across 3 identical symbols in a row, let alone 4, 5 ...

<br>Private Keys are created by encrypting the password (or several words) in SHA256, and we will get a unique hash at the output.
<br>Or randomly generating a Private Key in Bitcoin Core when creating an address. In both cases, there are practically no 3 identical symbols.
<br>Let's take a hash to iterate over
<br>**2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824**
<br>in a month it will be
<br>**2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e7000000000000000**
<br>How many times did 3,4,5,6,7 identical symbols occur in succession in this search?
<br>If you get to 3 identical characters where the last character equals the year of the search ??? Wasted year?
<br>If you roughly count how many times in the example above 000, 111, 222 - fff + shift along the bit range to the left. 
<br>Without going into numbers, this is practically a waste of electricity and card resources. 
<br>I think it's better to mine than such an overkill. The exception is to look for puzzles.

<br>Random generates unique hashes in a 256-bit range in which there are practically no 3 identical symbols in a row. 
<br>As in words, there are almost never 3 identical letters in a row. There are exceptions where there are 3 identical letters in a row. 
<br>For example, the letter "e" in the words: Long-necked, crooked, serpentine ...

<br>**For visual understanding**
Private Keys Range:<br>
**FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4141**
<br>Equal to number:
<br>**115 792 089 237 316 195 423 570 985 008 687 907 852 837564 279 074 994 382 605 163 141 518 161 494 337**
<br>At a speed of 1,000,000,000 hashes per second. brute force is not advisable, it is better to mine!
<br>Therefore, BitCrack and similar brute force programs are ineffective.

<br>Let's go back to the random and my hypothesis.
<br>Private Key Range:
<br>**FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 414**
<br>It can be clearly seen that random will not produce 4 identical FFFFs at the beginning of this range.
<br>Based on this, when randomly generating addresses in BitCoin Core, this range will be skipped. And this is not enough!
<br>~~FFFF~~ **FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 414**
<br>~~8888~~ **FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 414**
<br>Should the first 4 characters of the range 0000-FFFF be skipped + other duplicate?

<br>More specifically. The number for random matching is greatly reduced.
<br>Instead of a number:
<br>**115 792 089 237 316 195 423 570 985 008 687 907 852 837564 279 074 994 382 605 163 141 518 161 494 337**
<br>Perhaps we will get a number (did not count):
<br>**985 008 687 907 852 837564 279 074 994 382 605 163 141 518 161 494 337**
<br>**Cons of randomness:**
<br>Random is only very effective on long ranges. Brut is better on short ranges 

<br>**Pros of randomness:**
<br>If we compare the sums and compare the search speeds.
<br>Range enumeration speed: 1,000,000,000 hashes per second.
<br>The speed of the random is hypothetically approximately (did not count): 1.000.000.000.000.000.000 hashes per second.
<br>There is a chance of generating a repeated hash, but it is as unlikely as finding an address.
<br>I think that with randomness the chance of winning the lottery is much higher.

**Good luck in finding!** 
