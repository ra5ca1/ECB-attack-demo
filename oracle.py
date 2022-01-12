#!/usr/bin/env python3
# Author: Geoff Lucas geoff@xanthus.io

import string
import curses
from curses import wrapper
from curses import color_pair as color_pair
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


screen = curses.initscr()
curses.curs_set(0)
curses.start_color()
num_rows, num_cols = screen.getmaxyx()

# lines, columns, start line, start column
inputWin = curses.newwin(1, num_cols, 0, 0)
ptxctWin = curses.newwin(2, num_cols, 1, 0)
blocksizeWin = curses.newwin(7, 72, 4, 0)
offsetWin = curses.newwin(7, 72, 4, 75)
bruteWin = curses.newwin(13, num_cols, 15, 1)
quitWin = curses.newwin(1, num_cols, num_rows - 1, 0)

oracleWin = curses.newwin(7, num_cols, num_rows - 9, 0)

curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)


def oracle(key, userInput):
    secret = f"someotherdata{userInput}ThisIsASecret!!"
    cipher = AES.new(key, AES.MODE_ECB)
    padSize = 32 - (len(secret) % 32)  # Modulo defines block size
    secret += "X" * padSize
    ciphertext = cipher.encrypt(secret.encode("utf-8"))
    displayOracleInput(secret, padSize, ciphertext)
    return ciphertext


def displayOracleInput(secret, blockSize, ciphertext):
    oracleWin.addstr(0, 0, "### Input as Seen by Oracle Function ###")
    oracleWin.addstr(2, 0, f"Block Size: {str(blockSize)}")
    oracleWin.addstr(3, 0, f"Ciphertext Length: {str(len(ciphertext))}")
    oracleWin.addstr(4, 0, f"Plaintext Length: {str(len(secret) - blockSize)}")
    oracleWin.addstr(5, 0, f"Plaintext : {str(secret)}")
    oracleWin.refresh()
    curses.napms(60)


def findBlockSize(key):
    initialSize = int(len(oracle(key, "A")))
    ctLength = 0
    iter = 1
    while ctLength < initialSize * 2:
        oracleInput = "A" * iter
        cText = oracle(key, oracleInput)
        ctLength = len(cText)
        iter += 1
        displayBlockSize(oracleInput, cText)
    displayBlockSize(oracleInput, cText)
    subiter = iter
    while ctLength < initialSize * 3:
        oracleInput = "A" * subiter
        cText = oracle(key, oracleInput)
        ctLength = len(cText)
        subiter += 1
        displayBlockSize(oracleInput, cText)
    blockSize = subiter - iter
    displayBlockSize(oracleInput, cText, blockSize)
    return blockSize


def displayBlockSize(input, ciphertext, blockSize=0):
    inNum = len(input) + 7
    inputWin.addstr(0, 0, f"Input: {input}")
    inputWin.addstr(0, inNum, f" ({str(len(input) + 1)})")
    inputWin.refresh()
    ctList = split_len(ciphertext, 32)
    blocksizeWin.addstr(0, 0, f"Block0: {ctList[0].hex()}")
    if len(ctList) > 1:
        blocksizeWin.addstr(1, 0, f"Block1: {ctList[1].hex()}")
    if len(ctList) > 2:
        blocksizeWin.addstr(2, 0, f"Block2: {ctList[2].hex()}")
    if len(ctList) > 3:
        blocksizeWin.addstr(3, 0, f"Block3: {ctList[3].hex()}")
    if len(ctList) > 4:
        blocksizeWin.addstr(4, 0, f"Block4: {ctList[4].hex()}")
    blocksizeWin.refresh()
    if blockSize != 0:
        blocksizeWin.addstr(6, 0, f"Block Size: {str(blockSize)}")
        blocksizeWin.refresh()


def findOffset(key, blockSize):
    offsetFound = False
    iter = 0
    while offsetFound is False:
        oracleInput = "B" * iter + "A" * blockSize * 2
        ciphertext = oracle(key, oracleInput)
        ctList = split_len(ciphertext, blockSize)
        displayOffset(oracleInput, ctList)
        if ctList[1].hex() == ctList[2].hex():
            offsetFound = True
        iter += 1
    offset = iter
    offset = offset - 1
    displayOffset(oracleInput, ctList, offset)
    return offset


def displayOffset(input, ciphertextList, offset=0):
    inNum = len(input) + 7
    inputWin.addstr(0, 0, f"Input: {input}")
    inputWin.addstr(0, inNum, f"({str(len(input) + 1)})")
    inputWin.refresh()
    offsetWin.addstr(0, 0, f"Block0: {ciphertextList[0].hex()}")
    if len(ciphertextList) > 1:
        offsetWin.addstr(1, 0, f"Block1: {ciphertextList[1].hex()}")
    if len(ciphertextList) > 2:
        offsetWin.addstr(2, 0, f"Block2: {ciphertextList[2].hex()}")
    if len(ciphertextList) > 3:
        offsetWin.addstr(3, 0, f"Block3: {ciphertextList[3].hex()}")
    if offset != 0:
        offsetWin.addstr(6, 0, f"Offset: {str(offset)}")
    offsetWin.refresh()


def bruteForce(key, blockSize, offset):
    iter = 1
    found = False
    secret = ""
    oracleWin.clear()
    while found is False:
        oracleInput = "B" * offset + "A" * (blockSize - iter)
        ciphertext = oracle(key, oracleInput)
        cList = split_len(ciphertext, blockSize)
        target = cList[-2]
        subiter = 0
        for i in string.printable:
            input = oracleInput + secret + i
            ctBrute = oracle(key, oracleInput + secret + i)
            subiter += 1
            cList = split_len(ctBrute, blockSize)
            attempt = cList[-2]
            displayBrute(input, target, attempt, secret, offset, blockSize, i, cList)
            if attempt == target:
                secret += i
                iter += 1
                subiter = 0
                break
        if subiter > 0:
            found = True


def displayBrute(input, target, attempt, secret, offset, blockSize, i, cList):
    inNum = len(input) + 7
    inputWin.clear()
    try:
        inputWin.addstr(0, 0, f"Input: {input}")
        inputWin.addstr(0, inNum, f" ({str(len(input) + 1)})")
    except curses.error:
        pass
    inputWin.refresh()
    bruteWin.addstr(0, 0, "Decrypting...")
    bruteWin.addstr(2, 0, f"Secret Block {cList[-1].hex()}")
    bruteWin.addstr(4, 0, "Target ----------- ")
    bruteWin.addstr(5, 0, "Attempt ---------- ")
    bruteWin.addstr(6, 0, "Attempt (plain) -- ")
    if target == attempt:
        bruteWin.addstr(4, 19, target.hex() + " MATCHED!", color_pair(2))
        bruteWin.addstr(5, 19, attempt.hex() + " MATCHED!", color_pair(2))
        bruteWin.addstr(6, 19, "P" * (blockSize - offset) + input)
        bruteWin.refresh()
        curses.napms(500)
    else:
        bruteWin.addstr(4, 19, target.hex() + " " * 10)
        bruteWin.addstr(5, 19, attempt.hex() + " " * 10)
    bruteWin.addstr(6, 19, "P" * (blockSize - offset) + input)

    bruteWin.addstr(7, offset + (blockSize - offset) + 18, "|")
    bruteWin.addstr(8, offset + (blockSize - offset) + 13, "Offset")

    bruteWin.addstr(7, 18 + (blockSize - offset), "|")
    bruteWin.addstr(8, 2 + (blockSize - offset), "Uncontrolled Data")

    bruteWin.addstr(7, 18 + (blockSize * 2) - len(secret), "|")
    bruteWin.addstr(7, 18 + (blockSize * 2) - len(secret) + 1, " ")
    bruteWin.addstr(8, 18 + (blockSize * 2) - len(secret), "|")
    bruteWin.addstr(8, 18 + (blockSize * 2) - len(secret) + 1, " ")
    bruteWin.addstr(9, (blockSize * 2) - len(secret), "Recovered Plaintext")
    bruteWin.addstr(9, 19 + (blockSize * 2) - len(secret), " ")

    bruteWin.addstr(11, 0, f"Secret: {secret}")
    bruteWin.refresh()


def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]


def main(screen):
    key = get_random_bytes(32)  # Generate random 32 byte key
    quitWin.addstr(0, 0, "Press any key to continue...")
    quitWin.refresh()
    quitWin.getch()
    quitWin.clear()
    quitWin.refresh()

    blockSize = findBlockSize(key)
    quitWin.addstr(0, 0, "Press any key to continue...")
    quitWin.refresh()
    quitWin.getch()
    quitWin.clear()
    quitWin.refresh()

    offset = findOffset(key, blockSize)
    quitWin.addstr(0, 0, "Press any key to continue...")
    quitWin.refresh()
    quitWin.getch()
    quitWin.clear()
    quitWin.refresh()

    bruteForce(key, blockSize, offset)
    quitWin.addstr(0, 0, "Press any key to quit...")
    quitWin.refresh()
    quitWin.getch()

    curses.endwin()


if __name__ == '__main__':
    wrapper(main)
