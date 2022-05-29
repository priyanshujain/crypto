# Advanced encryption algorithm

- Block size: 128 bit
- Key size: 128 bit, 192 bit, 256 bit

## Basic Process

Each block of plaintext is 128 bit and can be represented into a table.

|     |     |     |     |     |
| --- | --- | --- | --- | --- |
| b0  | b4  | b8  | b12 |
| b1  | b5  | b9  | b13 |
| b2  | b6  | b10 | b14 |
| b3  | b7  | b11 | b15 |

Plaintext -> XOR ->

[ substitute bytes --> shift rows --> mix columns --> add round key ] // round

### rounds

- 128 bit key --> 10 rounds
- 192 bit key --> 12 rounds
- 256 bit key --> 10 rounds

### XOR

1st round includes XOR operation with first expanded key.

Plain text (128 bit) `XOR` k0

### Key expansion

There is a different key in each round and it's expanded to round keys using key schedule.

### Byte substitution

apply byte substitution function `S` each byte in the block

|       |       |        |        |     |
| ----- | ----- | ------ | ------ | --- |
| S(b0) | S(b4) | S(b8)  | S(b12) |
| S(b1) | S(b5) | S(b9)  | Sb13)  |
| S(b2) | S(b6) | S(b10) | S(b14) |
| S(b3) | S(b7) | S(b11) | S(b15) |

### Shift rows

Rules

- no shift for first now
- 1 place shift to left for first row
- 2 place shift to left for second row
- 3 place shift to left for third row

|     |     |     |     |     |
| --- | --- | --- | --- | --- |
| b0  | b4  | b8  | b12 |
| b5  | b9  | b13 | b1  |
| b10 | b14 | b2  | b6  |
| b15 | b3  | b7  | b11 |

### Mix columns


<!-- $\begin{bmatrix}
    c_{0}\\
    c_{1}\\
    c_{2}\\
    c_{3}\\
\end{bmatrix}
=
\begin{bmatrix}
    2 & 3 & 1 & 1 \\
    1 & 2 & 3 & 1 \\
    1 & 1 & 2 & 3 \\
    3 & 1 & 1 & 2 \\
\end{bmatrix}
\times
\begin{bmatrix}
    c_{0}\\
    c_{1}\\
    c_{2}\\
    c_{3}\\
\end{bmatrix}$ --> 

<img style="transform: translateY(0.1em); background: white;" src="images/oylSsyClrV.svg">


### Add round key
it's again another XOR with the round key 



## AES modes 

- ECB(electronic code book): Each block of plaintext is encrypted independently using the same key. 
![ECB](images/ECB_encryption.png)


- CBC(cipher block chaining): The input to the block cipher is the XOR of the next block of plaintext nd the preceding block. 
![CBC](images/CBC_encryption.png)

NOTE: Input to the first block is the value called `Initialization Vector or IV`. IV should be random and non-repeating by nature. IV is used to make sure that different cipher values are produced for the same first block of plaintext. 

- CFB(cipher feedback): Input is produced s bits at a time. Preceding ciphertext is used as input to the encryption algorithm to produce pseudorandom output, which is XORed with plaintext to produce next unit of ciphertext. 

![CFB](images/CFB_encryption.png)

- CTR (Counter): Each block of plaintext is XORed with an encrypted counter(nounce + 1). The counter is incremented for each subsequent block.
![CTR](images/CTR_encryption.png)

- GCM (galois counter): TBD

## AES padding