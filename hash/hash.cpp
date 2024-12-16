#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>

using namespace std;
using namespace CryptoPP;

int main () {
    SHA1 hash;
    cout << "Имя: " << hash.AlgorithmName() << endl;
    cout << "Числовой размер: " << hash.DigestSize() << endl;
    cout << "Размер блока: " << hash.BlockSize() << endl;
    string msg = "";
    string str;
    ifstream f("/home/stud/for_random_thigs/CryptoProg/hash/files/file");
    while (getline(f, str)) {
        msg += str;
    }
    vector<byte> digest(hash.DigestSize());
    hash.Update((const byte*)msg.data(), msg.size());
    hash.Final(digest.data());
    cout << "Сообщение: " << msg << endl;
    cout << "Числа: ";
    StringSource(digest.data(), digest.size(), true, new HexEncoder(new FileSink(cout)));
    cout << endl;
    return 0;
}
