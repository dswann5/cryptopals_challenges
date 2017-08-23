#!/usr/bin/env python2.7

import base64
import binascii
import string

def hex_to_base64(hex_string):
    ''' Set 1 Challenge 1:
        Convert hex to base64
    '''
    decoded_string = binascii.unhexlify(hex_string)
    return base64.b64encode(decoded_string).decode('ascii')


def fixed_xor(buf1, buf2):
    ''' Set 1 Challenge 2:
        Write a function that takes two equal-length buffers and produces their XOR combination.
    '''
    assert len(buf1) == len(buf2)
    decoded_buf1 = binascii.unhexlify(buf1).decode('ascii')
    decoded_buf2 = binascii.unhexlify(buf2).decode('ascii')
    return [ord(i) ^ ord(j) for i, j in zip(decoded_buf1, decoded_buf2)]


def single_byte_xor_cipher(hex_string, plaintext):
    ''' Set 1 Challenge 2:
        Decrypts a single-character encoded hex string
        Tests the decrypted plaintext against the given plaintext
        Returns the byte char which results in a match when used as the decryption key
    '''
    score_threshold = 3

    decoded_string = binascii.unhexlify(hex_string)
    # Iterate through all printable ascii characters
    for char1 in string.printable:
        phrase = [ord(char1) ^ ord(char2) for char2 in decoded_string]
        decoded_phrase = ''.join([chr(c) for c in phrase])
        score = score_plaintext(decoded_phrase)
        if score > score_threshold:
            print str(score) + '\t ' + decoded_phrase
        if decoded_phrase == plaintext:
            print '"%s" matches the given plaintext with score %s' % (decoded_phrase, score)
            return char1


def score_plaintext(plaintext):
    """ From https://en.wikipedia.org/wiki/Letter_frequency """
    char_freq = {'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702, 'f': .02228,
                 'g': .02015, 'h': .06094, 'i': .06966, 'j': .00153, 'k': .00772, 'l': .04025,
                 'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929, 'q': .00095, 'r': .05987,
                 's': .06327, 't': .09056, 'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
                 'y': .01974, 'z': .00074}
    penalty = 10

    # Calculate score for the phrase, ensure ASCII and ignoring puncuation
    score = 0
    for char in plaintext:
        if ord(char) > 127:
            score -= penalty
        elif ord(char) < 32 and not (ord(char) == 10 or ord(char) == 13):
            score += -5
        else:
            # ignore punctuation
            if char in char_freq:
                score += char_freq[char]
    return score/float(len(plaintext)) * 100


def main():
    '''  Main function '''

    # Unit test assertion for challenge1
    sample_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    sample_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert hex_to_base64(sample_input) == sample_output

    # Unit test assertion for challenge2
    sample_input1 = '1c0111001f010100061a024b53535009181c'
    sample_input2 = '686974207468652062756c6c277320657965'
    sample_output = '746865206b696420646f6e277420706c6179'
    assert fixed_xor(sample_input1, sample_input2)

    # Unit test assertion for challenge3
    # Byte key is 'X' in ascii or '120'
    sample_ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    sample_plaintext = "Cooking MC's like a pound of bacon"
    assert single_byte_xor_cipher(sample_ciphertext, sample_plaintext) == 'X'

if __name__ == '__main__':
    main()
