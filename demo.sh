#! /bin/bash

echo "DES implementation in Python"
echo "Author: Brendan Sweeney"
echo "Course: CSS 527"
echo "  Date: October 14, 2014"
echo
echo
#echo " == Run 0.1 - Get cryptic help message =="
#echo
#echo "./des"
#./des
#echo
#echo
#echo " == Run 0.2 - Get more useful help about 'genkey' =="
#echo
#echo "./des genkey -h"
#./des genkey -h
#echo
#echo
echo " == Run 1 - Generate a key file =="
echo
echo "./des genkey 'oogiblah' test.key"
./des genkey 'oogiblah' test.key
echo
echo " == Take a look at the key =="
echo
echo "base64 test.key"
base64 test.key
echo
echo
#echo " == Run 1.1 - Get useful help about 'encrypt' =="
#echo
#echo "./des encrypt -h"
#./des encrypt -h
#echo
#echo
echo " == Run 2 - Encrypt a short text file =="
echo
echo "./des encrypt short.txt test.key short.des"
./des encrypt short.txt test.key short.des
echo
echo " == Take a look at the ciphertext =="
echo
echo "base64 short.des"
base64 short.des
echo
echo
#echo " == Run 2.1 - Get useful help about 'decrypt' =="
#echo
#echo "./des decrypt -h"
#./des decrypt -h
#echo
#echo
echo " == Run 3 - Decrypt some short ciphertext =="
echo
echo "./des decrypt short.des test.key new-short.txt"
./des decrypt short.des test.key new-short.txt
echo
echo " == Take a look at the new text =="
echo
echo "cat new-short.txt"
cat new-short.txt
echo
echo " == Compare with the original =="
echo
echo "diff -s short.txt new-short.txt"
diff -s short.txt new-short.txt
echo
echo
echo " == Run 4 - Encrypt an empty file =="
echo
echo "./des encrypt empty.txt test.key empty.des"
./des encrypt empty.txt test.key empty.des
echo
echo " == Ciphertext should appear similar to short ciphertext =="
echo
echo "base64 empty.des"
base64 empty.des
echo
echo
echo " == Run 5 - Decrypt some more short ciphertext =="
echo
echo "./des decrypt empty.des test.key new-empty.txt"
./des decrypt empty.des test.key new-empty.txt
echo
echo " == Take a look at the new empty file =="
echo
echo "cat new-empty.txt"
cat new-empty.txt
echo
echo " == Compare with the original =="
echo
echo "diff -s empty.txt new-empty.txt"
diff -s empty.txt new-empty.txt
echo
echo
echo " == Run 6 - Encrypt a multi-block text file =="
echo
echo "./des encrypt long.txt test.key long.des"
./des encrypt long.txt test.key long.des
echo
echo " == Take a look at the ciphertext =="
echo
echo "base64 long.des"
base64 long.des
echo
echo
echo " == Run 7 - Decrypt some multi-byte ciphertext =="
echo
echo "./des decrypt long.des test.key new-long.txt"
./des decrypt long.des test.key new-long.txt
echo
echo " == Take a look at the new text =="
echo
echo "cat new-long.txt"
cat new-long.txt
echo
echo " == Compare with the original =="
echo
echo "diff -s long.txt new-long.txt"
diff -s long.txt new-long.txt
echo
echo
echo " == Run 8 - Encrypt a multi-block binary file =="
echo
echo "./des encrypt face.png test.key face.des"
./des encrypt face.png test.key face.des
echo
echo
echo " == Run 9 - Decrypt some multi-byte ciphertext =="
echo
echo "./des decrypt face.des test.key new-face.png"
./des decrypt face.des test.key new-face.png
echo
echo " == Compare with the original =="
echo
echo "diff -s face.png new-face.png"
diff -s face.png new-face.png
echo
echo "Done!"
