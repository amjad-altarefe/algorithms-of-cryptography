/******************************************************************************

                   • Encryption and decryption algorithms in c++.
                            
                                • Participants:
                                - Amjad Qandeel

*******************************************************************************/

#include <iostream>
#include <cmath>  
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <string>
#include <sstream>
#include <bitset>
#include <vector>

using namespace std;

//---------------------------------------------------------------------- DES ----------------------------------------------------------------------//

// The PC1 table
int pc1[56] = { 57,49,41,33,25,17,9,
                 1,58,50,42,34,26,18,
                10,2,59,51,43,35,27,
                19,11,3,60,52,44,36,
                63,55,47,39,31,23,15,
                 7,62,54,46,38,30,22,
                14,6,61,53,45,37,29,
                21,13,5,28,20,12,4};
// The PC2 table
int pc2[48] = { 14,17,11,24, 1, 5,
                 3,28,15, 6,21,10,
                23,19,12, 4,26, 8,
                16, 7,27,20,13, 2,
                41,52,31,37,47,55,
                30,40,51,45,33,48,
                44,49,39,56,34,53,
                46,42,50,36,29,32};

int initial_permutation[64] = { 58,50,42,34,26,18,10,2,
                                60,52,44,36,28,20,12,4,
                                62,54,46,38,30,22,14,6,
                                64,56,48,40,32,24,16,8,
                                57,49,41,33,25,17, 9,1,
                                59,51,43,35,27,19,11,3,
                                61,53,45,37,29,21,13,5,
                                63,55,47,39,31,23,15,7};

int expansion_table[48] = { 32, 1, 2, 3, 4, 5, 4, 5,
                             6, 7, 8, 9, 8, 9,10,11,
                            12,13,12,13,14,15,16,17,
                            16,17,18,19,20,21,20,21,
                            22,23,24,25,24,25,26,27,
                            28,29,28,29,30,31,32, 1};
                            
// should contain values from 0 to 15 in any order.
int substition_boxes[8][4][16] =
{ 
    {
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    } 
};

int permutation_tab[32] = {16, 7,20,21,29,12,28,17,
                            1,15,23,26, 5,18,31,10,
                            2, 8,24,14,32,27, 3, 9,
                           19,13,30, 6,22,11, 4,25};
                            
int inverse_permutation[64] = { 40,8,48,16,56,24,64,32,
                                39,7,47,15,55,23,63,31,
                                38,6,46,14,54,22,62,30,
                                37,5,45,13,53,21,61,29,
                                36,4,44,12,52,20,60,28,
                                35,3,43,11,51,19,59,27,
                                34,2,42,10,50,18,58,26,
                                33,1,41, 9,49,17,57,25};

// String to hold the plain text
string pt;

///////////////////////////////////////////////////////////////
string convertHexToBinary(char hex)
{
    switch (hex) 
    {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'A':
        case 'a': return "1010";
        case 'B':
        case 'b': return "1011";
        case 'C':
        case 'c': return "1100";
        case 'D':
        case 'd': return "1101";
        case 'E':
        case 'e': return "1110";
        case 'F':
        case 'f': return "1111";
        default: return ""; // Invalid hexadecimal character
    }
}

///////////////////////////////////////////////////////////////

string convertDecimalToBinary(int decimal) 
{
    string binary;
    while (decimal != 0) 
    {
        binary = (decimal % 2 == 0 ? "0" : "1") + binary;
        decimal = decimal / 2;
    }
    while (binary.length() < 4) 
        binary = "0" + binary;
    
    return binary;
}
//////////////////////////////////////////////////////////////////

int convertBinaryToDecimal(string binary) 
{
    int decimal = 0;
    int counter = 0;
    int size = binary.length();
    for (int i = size - 1; i >= 0; i--) 
    {
        if (binary[i] == '1') 
            decimal += pow(2, counter);
        counter++;
    }
    return decimal;
}
//////////////////////////////////////////////////////////////////

string shift_bit(string s, int n)
{
    string k = "";
    for (int i = n; i < s.size(); i++)
        k += s[i];

    for (int i = 0; i < n; i++)
        k += s[i];

    return k;
}
//////////////////////////////////////////////////////////////////

// Function to compute xor between two strings
string Xor(string a, string b) 
{
    string result = "";
    for (int i = 0; i < b.size(); i++) 
    {
        if (a[i] != b[i])
            result += "1";
        else 
            result += "0";
    }
    return result;
}
//////////////////////////////////////////////////////////////////

// Array to hold 16 keys
string round_keys[16];
// Function to generate the 16 keys.
void generate_keys(string key) 
{
    // 1. Compressing the key using the PC1 table
    string perm_key = "";
    for (int i = 0; i < 56; i++) 
    {
        perm_key += key[pc1[i] - 1];
    }
    // 2. Dividing the key into two equal halves
    string left = perm_key.substr(0, 28);
    string right = perm_key.substr(28, 28);
    for (int i = 0; i < 16; i++) 
    {
        // 3.1. For rounds 1, 2, 9, 16 the key_chunks
        // are shifted by one.
        if (i == 0 || i == 1 || i == 8 || i == 15) {
            left = shift_bit(left , 1);
            right = shift_bit(right , 1);
        }
        // 3.2. For other rounds, the key_chunks
        // are shifted by two
        else 
        {
            left = shift_bit(left , 2);
            right = shift_bit(right , 2);
        }
        // Combining the two chunks
        string combined_key = left + right;
        string round_key = "";
        // Finally, using the PC2 table to transpose the key bits
        for (int i = 0; i < 48; i++) {
            round_key += combined_key[pc2[i] - 1];
        }
        round_keys[i] = round_key;
    }
}

// Implementing the algorithm for encryption and decryption
string DES(string text, bool isEncrypt) 
{
    // Applying the initial permutation
    string perm = "";
    for (int i = 0; i < 64; i++) {
        perm += text[initial_permutation[i] - 1];
    }
    // Dividing the result into two equal halves
    string left = perm.substr(0, 32);
    string right = perm.substr(32, 32);
    for (int i = 0; i < 16; i++) 
    {
        string right_expanded = "";
        // The right half of the plain text is expanded
        for (int j = 0; j < 48; j++) 
        {
            right_expanded += right[expansion_table[j] - 1];
        }
        // The result is xored with a key
        string xored = Xor(round_keys[isEncrypt ? i : 15 - i], right_expanded);
        string res = "";
        // The result is divided into 8 equal parts and passed
        // through 8 substitution boxes. After passing through a
        // substitution box, each box is reduced from 6 to 4 bits.
        for (int j = 0; j < 8; j++) {
            // Finding row and column indices to lookup the
            // substitution box
            string row1 = xored.substr(j * 6, 1) + xored.substr(j * 6 + 5, 1);
            int row = convertBinaryToDecimal(row1);
            string col1 = xored.substr(j * 6 + 1, 4);
            int col = convertBinaryToDecimal(col1);
            int val = substition_boxes[j][row][col];
            res += convertDecimalToBinary(val);
        }
        // Another permutation is applied
        string perm2 = "";
        for (int j = 0; j < 32; j++) 
        {
            perm2 += res[permutation_tab[j] - 1];
        }
        // The result is xored with the left half
        xored = Xor(perm2, left);
        // The left and the right parts of the plain text are swapped
        left = xored;
        if (i < 15) 
        {
            string temp = right;
            right = xored;
            left = temp;
        }
        // Printing intermediate results after each round
        //cout << "Round " << i + 1 << " Left: " << left << " Right: " << right << " Round key: " << round_keys[isEncrypt ? i : 15 - i] << endl;
    }
    // The halves are combined
    string combined_text = left + right;
    string result_text = "";
    // The inverse of the initial permutation is applied
    for (int i = 0; i < 64; i++) 
    {
        result_text += combined_text[inverse_permutation[i] - 1];
    }
    return result_text;
}

string stringToBinary(const string& input) 
{
    string binaryString;

    for (char c : input) 
    {
        binaryString += bitset<8>(c).to_string();
    }

    return binaryString;
}
string binaryToString(const string& binaryInput) 
{
    string asciiString;

    // Process each 8-bit chunk of the binary string
    for (size_t i = 0; i < binaryInput.size(); i += 8) 
    {
        // Extract 8-bit chunk from the binary input string
        string byte = binaryInput.substr(i, 8);

        // Convert binary chunk to character
        char c = static_cast<char>(bitset<8>(byte).to_ulong());

        // Append the character to the resulting string
        asciiString += c;
    }

    return asciiString;
}

//---------------------------------------------------------------------- AES ----------------------------------------------------------------------//

string stringToHex(const string& input) 
{
    stringstream hexStream;
    hexStream << hex << setfill('0');

    for (char c : input) 
        hexStream << setw(2) << static_cast<int>(static_cast<unsigned char>(c));

    return hexStream.str();
}

// AES S-Box
static const unsigned char sBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0x6c, 0x52, 0x3b, 0x7f, 0x55, 0x5e, 0x11,
    0x9e, 0x64, 0x52, 0x2f, 0x8b, 0x42, 0x21, 0x36,
    0x48, 0x8b, 0x6f, 0x72, 0x72, 0x58, 0x53, 0x6c,
    0x69, 0x3f, 0x7e, 0x5d, 0xb7, 0x8f, 0x5d, 0x6f,
    0x8f, 0x75, 0x59, 0x69, 0xb2, 0x5b, 0x78, 0x5f,
    0x49, 0x42, 0x71, 0x74, 0x13, 0x65, 0x47, 0x03,
    0x59, 0x35, 0xa5, 0x77, 0x92, 0xb2, 0x8e, 0x6b,
    0x4b, 0x66, 0x85, 0x79, 0x59, 0x51, 0x67, 0x66,
    0x3d, 0x7b, 0x1e, 0x77, 0xe5, 0x56, 0x1d, 0xa2,
    0x0b, 0x52, 0x6f, 0x6e, 0x22, 0x35, 0x2b, 0x9d,
    0x3a, 0x72, 0x1f, 0x38, 0x1e, 0x58, 0x22, 0x6b,
    0x4e, 0x53, 0xd2, 0x79, 0x2d, 0x93, 0x73, 0x65,
    0xa5, 0x45, 0x96, 0x57, 0x0b, 0x45, 0x74, 0x61,
    0x93, 0xd3, 0x65, 0x35, 0x8e, 0x4d, 0x3d, 0xd6,
    0x6a, 0x56, 0x4f, 0x36, 0x2a, 0x26, 0x43, 0x6e,
    0x61, 0x88, 0x67, 0x67, 0x36, 0x53, 0x48, 0x55,
    0x54, 0x6d, 0x32, 0xa9, 0x56, 0x65, 0xd2, 0x63,
    0x8f, 0x0d, 0x32, 0x78, 0x34, 0x1e, 0x70, 0x88,
    0x43, 0x9a, 0x3a, 0x49, 0x8b, 0x25, 0x4b, 0x2e,
    0xa7, 0xa2, 0x36, 0x1b, 0x3f, 0x7e, 0x75, 0xb4,
    0x59, 0x89, 0x6b, 0xa3, 0x44, 0x4f, 0x1e, 0x57,
    0xd3, 0x76, 0x56, 0x9b, 0x0e, 0x58, 0x41, 0x38
};

// AES Inverse S-Box
static const unsigned char invSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0x22, 0x33, 0x88,
    0x2e, 0x43, 0x65, 0x31, 0x18, 0x1e, 0x63, 0x53,
    0x45, 0x5f, 0x87, 0x80, 0x92, 0x79, 0x7d, 0x7c,
    0x7b, 0x3a, 0x45, 0x88, 0x95, 0x61, 0x6e, 0x1a,
    0x37, 0x4d, 0x64, 0x56, 0x79, 0x7d, 0x32, 0x99,
    0x3b, 0x8f, 0x5f, 0x9c, 0x52, 0x72, 0x76, 0x23,
    0x0b, 0x94, 0x4c, 0x9c, 0x76, 0x77, 0x1c, 0x47,
    0x5b, 0x5e, 0x5c, 0x59, 0x47, 0x7f, 0x7e, 0x48,
    0x74, 0x77, 0x59, 0x42, 0x1c, 0x23, 0x8a, 0x56,
    0xa4, 0x98, 0xd0, 0xd1, 0x58, 0xc6, 0x25, 0x75,
    0x39, 0x9c, 0x22, 0x3d, 0xe6, 0x63, 0x99, 0x87,
    0x56, 0x97, 0x69, 0x56, 0x66, 0x75, 0x35, 0x64,
    0x80, 0x9d, 0x7c, 0x52, 0x6f, 0x3e, 0x2a, 0x58,
    0x7e, 0x79, 0xd7, 0xd0, 0xd1, 0x75, 0x38, 0x52,
    0x6f, 0x70, 0xa9, 0x66, 0xd6, 0xe7, 0x7f, 0x3a,
    0x75, 0x5d, 0x71, 0x7f, 0x88, 0x7c, 0x63, 0x72,
    0x4b, 0x67, 0x63, 0xe4, 0x9c, 0x5b, 0x7c, 0x4d
};


// AES Rcon
static const unsigned char Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

void printState(const vector<vector<unsigned char>>& state) 
{
    for (int i = 0; i < 4; ++i) 
    {
        for (int j = 0; j < 4; ++j)
            cout << hex << setw(2) << setfill('0') << (int)state[j][i];
            
        cout << endl;
    }
    cout << endl;
}
// Rotate a word
void rotWord(vector<unsigned char>& word) 
{
    unsigned char temp = word[0];
    
    for (int i = 0; i < 3; ++i) 
        word[i] = word[i + 1];
        
    word[3] = temp;
}

// Substitute a word using the S-Box
void subWord(vector<unsigned char>& word) 
{
    for (int i = 0; i < 4; ++i)
        word[i] = sBox[word[i]];
}

void keyExpansion(const vector<unsigned char>& key, vector<vector<unsigned char>>& expandedKey)
{
    int keySize = key.size() / 4;
    int expandedKeySize = expandedKey.size();

    for (int i = 0; i < keySize; ++i) 
    {
        for (int j = 0; j < 4; ++j) 
            expandedKey[i][j] = key[i * 4 + j];
    }

    vector<unsigned char> temp(4);

    for (int i = keySize; i < expandedKeySize; ++i) 
    {
        for (int j = 0; j < 4; ++j)
            temp[j] = expandedKey[i - 1][j];
        
        if (i % keySize == 0) 
        {
            rotWord(temp);
            subWord(temp);
            temp[0] ^= Rcon[i / keySize - 1];
        }
        for (int j = 0; j < 4; ++j) 
            expandedKey[i][j] = expandedKey[i - keySize][j] ^ temp[j];
    }
}

void addRoundKey(vector<vector<unsigned char>>& state, const vector<vector<unsigned char>>& roundKey) 
{
    for (int i = 0; i < 4; ++i) 
    {
        for (int j = 0; j < 4; ++j)
            state[j][i] ^= roundKey[j][i];
    }
}

void subBytes(vector<vector<unsigned char>>& state) 
{
    for (int i = 0; i < 4; ++i) 
    {
        for (int j = 0; j < 4; ++j)
            state[i][j] = sBox[state[i][j]];
    }
}

void invSubBytes(vector<vector<unsigned char>>& state) 
{
    for (int i = 0; i < 4; ++i) 
    {
        for (int j = 0; j < 4; ++j)
            state[i][j] = invSBox[state[i][j]];
    }
}

void shiftRows(vector<vector<unsigned char>>& state) 
{
    vector<unsigned char> temp(4);
    for (int i = 1; i < 4; ++i) 
    {
        for (int j = 0; j < 4; ++j) 
            temp[j] = state[i][(j + i) % 4];
        
        for (int j = 0; j < 4; ++j) 
            state[i][j] = temp[j];
    }
}

void invShiftRows(vector<vector<unsigned char>>& state) 
{
    vector<unsigned char> temp(4);
    for (int i = 1; i < 4; ++i) 
    {
        for (int j = 0; j < 4; ++j) 
            temp[j] = state[i][(j - i + 4) % 4];
        
        for (int j = 0; j < 4; ++j) 
            state[i][j] = temp[j];
    }
}

// Galois Field multiplication
unsigned char gfMul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for (int i = 0; i < 8; ++i) 
    {
        if (b & 1) 
            p ^= a;
            
        bool hiBitSet = a & 0x80;
        a <<= 1;
        if (hiBitSet) 
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void mixColumns(vector<vector<unsigned char>>& state) 
{
    unsigned char temp[4];
    for (int i = 0; i < 4; ++i) 
    {
        temp[0] = gfMul(0x02, state[0][i]) ^ gfMul(0x03, state[1][i]) ^ state[2][i] ^ state[3][i];
        temp[1] = state[0][i] ^ gfMul(0x02, state[1][i]) ^ gfMul(0x03, state[2][i]) ^ state[3][i];
        temp[2] = state[0][i] ^ state[1][i] ^ gfMul(0x02, state[2][i]) ^ gfMul(0x03, state[3][i]);
        temp[3] = gfMul(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ gfMul(0x02, state[3][i]);

        for (int j = 0; j < 4; ++j) 
            state[j][i] = temp[j];
    }
}

void invMixColumns(vector<vector<unsigned char>>& state) 
{
    unsigned char temp[4];
    for (int i = 0; i < 4; ++i) 
    {
        temp[0] = gfMul(0x0e, state[0][i]) ^ gfMul(0x0b, state[1][i]) ^ gfMul(0x0d, state[2][i]) ^ gfMul(0x09, state[3][i]);
        temp[1] = gfMul(0x09, state[0][i]) ^ gfMul(0x0e, state[1][i]) ^ gfMul(0x0b, state[2][i]) ^ gfMul(0x0d, state[3][i]);
        temp[2] = gfMul(0x0d, state[0][i]) ^ gfMul(0x09, state[1][i]) ^ gfMul(0x0e, state[2][i]) ^ gfMul(0x0b, state[3][i]);
        temp[3] = gfMul(0x0b, state[0][i]) ^ gfMul(0x0d, state[1][i]) ^ gfMul(0x09, state[2][i]) ^ gfMul(0x0e, state[3][i]);

        for (int j = 0; j < 4; ++j)
            state[j][i] = temp[j];
    }
}

void aesEncrypt(vector<vector<unsigned char>>& state, const vector<unsigned char>& key) 
{
    vector<vector<unsigned char>> expandedKey(44, vector<unsigned char>(4, 0));
    keyExpansion(key, expandedKey);

    addRoundKey(state, vector<vector<unsigned char>>(expandedKey.begin(), expandedKey.begin() + 4));

    for (int round = 1; round <= 10; ++round) 
    {
        subBytes(state);
        shiftRows(state);
        if (round != 10) 
            mixColumns(state);

        addRoundKey(state, vector<vector<unsigned char>>(expandedKey.begin() + 4 * round, expandedKey.begin() + 4 * (round + 1)));

        cout << "Round " << round << " end state:" << endl;
        printState(state);
    }
}

void aesDecrypt(vector<vector<unsigned char>>& state, const vector<unsigned char>& key) 
{
    vector<vector<unsigned char>> expandedKey(44, vector<unsigned char>(4, 0));
    keyExpansion(key, expandedKey);

    addRoundKey(state, vector<vector<unsigned char>>(expandedKey.begin() + 40, expandedKey.begin() + 44));

    for (int round = 9; round >= 0; --round) 
    {
        invShiftRows(state);
        invSubBytes(state);

        addRoundKey(state, vector<vector<unsigned char>>(expandedKey.begin() + 4 * round, expandedKey.begin() + 4 * (round + 1)));

        if (round != 0) invMixColumns(state);

        cout << "Round " << 10 - round << " end state:" << endl;
        printState(state);
    }
}

vector<unsigned char> parseHex(const string& hexStr) 
{
    vector<unsigned char> result;
    for (size_t i = 0; i < hexStr.length(); i += 2) 
    {
        string byteStr = hexStr.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteStr.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

//---------------------------------------------------------------------- RSA ----------------------------------------------------------------------//

bool isPrime(int n) 
{
    if (n <= 1) 
        return false;
    if (n <= 3) 
        return true;

    if (n % 2 == 0 || n % 3 == 0) return false;

    for (int i = 5; i * i <= n; i += 6)
        if (n % i == 0 || n % (i + 2) == 0)
            return false;

    return true;
}

int gcd(int a, int b) 
{
    if (b == 0) 
        return a;
    else
        return gcd(b, a % b);
}

//function to find modular inverse using extended Euclidean algorithm
int modInverse(int a, int m) 
{
    int m0 = m;
    int y = 0, x = 1;

    if (m == 1)
        return 0;

    while (a > 1) 
    {
        int q = a / m;
        int t = m;

        m = a % m, a = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0)
        x += m0;

    return x;
}

void generateKeys(int p, int q, int& e, int& d, int& n) 
{
    if (!isPrime(p) || !isPrime(q)) 
    {
        cerr << "Both numbers must be prime." << endl;
        return;
    }

    n = p * q;
    int phi = (p - 1) * (q - 1);

    for (e = 2; e < phi; e++) 
    {
        if (gcd(e, phi) == 1)
            break;
    }

    d = modInverse(e, phi);
}

int encrypt(int msg, int e, int n) 
{
    return (int)pow(msg, e) % n;
}

int decrypt(int encryptedMsg, int d, int n) 
{
    return (int)pow(encryptedMsg, d) % n;
}

//---------------------------------------------------------------------- trial method ----------------------------------------------------------------------//
// Function to check if a number is prime
bool isPrime(unsigned long long num) {
    if (num <= 1) return false;
    for (unsigned long long i = 2; i <= std::sqrt(num); ++i) {
        if (num % i == 0) return false;
    }
    return true;
}

// Function to perform trial division
void trialDivision(unsigned long long N) {
    std::cout << "Factoring N = " << N << " using trial division..." << std::endl;

    for (unsigned long long i = 2; i <= std::sqrt(N); ++i) {
        if (N % i == 0) { // Check if i is a factor
            unsigned long long p = i;
            unsigned long long q = N / i;

            // Print the factors
            std::cout << "Found factors: p = " << p << ", q = " << q << std::endl;

            // Check if the factors are prime
            bool isPPrime = isPrime(p);
            bool isQPrime = isPrime(q);

            if (!isPPrime || !isQPrime) {
                throw std::runtime_error(
                    "Error: One or both factors are not prime numbers."
                );
            }

            std::cout << "Both factors are prime. Proceeding." << std::endl;
            return;
        }
    }

    throw std::runtime_error("No factors found. N might be a prime number.");
}

//---------------------------------------------------------------------- El-Gamal ----------------------------------------------------------------------//

// Function to perform modular exponentiation
long long mod_exp(long long base, long long exp, long long mod) 
{
    long long result = 1;
    base = base % mod;
    while (exp > 0) 
    {
        if (exp % 2 == 1)  // If exp is odd, multiply base with result
            result = (result * base) % mod;
        
        exp = exp >> 1; // Divide exp by 2
        base = (base * base) % mod; // Square the base
    }
    return result;
}

//generate a random number in range
long long random_number(long long min, long long max) 
{
    return min + rand() % (max - min + 1);
}
void key_generation(long long& p, long long& g, long long& x, long long& y) 
{
    cout << "Enter a large prime number p: ";
    cin >> p;
    cout << "Enter a primitive root g of p: ";
    cin >> g;

    x = random_number(1, p - 2); // Private key
    y = mod_exp(g, x, p);      // Public key
}

pair<long long, long long> encrypt(long long p, long long g, long long y, long long m) 
{
    long long k = random_number(1, p - 2); // Random number
    long long c1 = mod_exp(g, k, p);
    long long c2 = (mod_exp(y, k, p) * m) % p;
    return make_pair(c1, c2);
}

long long decrypt(long long p, long long x, pair<long long, long long> ciphertext) 
{
    long long c1 = ciphertext.first;
    long long c2 = ciphertext.second;
    long long s = mod_exp(c1, x, p);
    long long m = (c2 * mod_exp(s, p - 2, p)) % p; // Using Fermat's Little Theorem for modular inverse
    return m;
}

//---------------------------------------------------------------------- Existential Forgery ----------------------------------------------------------------------//

// دالة لحساب القوة مع المود (Modular Exponentiation)
long long modExp(long long base, long long exp, long long mod) 
{
    long long result = 1;
    base = base % mod;

    while (exp > 0) 
    {
        if (exp % 2 == 1) 
            result = (result * base) % mod;
        
        exp = exp / 2;
        base = (base * base) % mod;
    }

    return result;
}

//------------------------------------------------------------------- Digital Signature -------------------------------------------------------------------//

unsigned long long gcd(unsigned long long a, unsigned long long b) 
{
    while (b != 0) 
    {
        unsigned long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to compute modular exponentiation (base^exp % mod)
unsigned long long modExp(unsigned long long base, unsigned long long exp, unsigned long long mod) 
{
    unsigned long long result = 1;
    base = base % mod;
    while (exp > 0) 
    {
        if (exp % 2 == 1) 
            result = (result * base) % mod; // If exp is odd, multiply base with result
        
        exp = exp >> 1; // Divide exp by 2
        base = (base * base) % mod; // Square the base
    }
    return result;
}

// Function to find modular multiplicative inverse of e under modulo phi using Extended Euclidean Algorithm
unsigned long long modInverse(unsigned long long e, unsigned long long phi) 
{
    long long t = 0, newT = 1;
    long long r = phi, newR = e;
    while (newR != 0) 
    {
        long long quotient = r / newR;
        t = t - quotient * newT;
        swap(t, newT);
        r = r - quotient * newR;
        swap(r, newR);
    }
    if (r > 1) return -1; // e is not invertible
    if (t < 0) t += phi;
    return t;
}

void generateRSAKeys(unsigned long long& n, unsigned long long& e, unsigned long long& d, unsigned long long p, unsigned long long q) 
{
    n = p * q;
    unsigned long long phi = (p - 1) * (q - 1);

    // Choose e
    for (e = 2; e < phi; e++) 
        if (gcd(e, phi) == 1)
            break;

    // Compute d
    d = modInverse(e, phi);
}

unsigned long long signMessage(unsigned long long message, unsigned long long d, unsigned long long n) 
{
    return modExp(message, d, n);
}

// Function to verify a signature
bool verifySignature(unsigned long long message, unsigned long long signature, unsigned long long e, unsigned long long n) 
{
    unsigned long long verification = modExp(signature, e, n);
    return verification == message;
}

//---------------------------------------------------------------------- Elliptic Curve ----------------------------------------------------------------------//

class Point 
{
    public:
        long long x, y;
        bool is_infinity;
    
        Point() : x(0), y(0), is_infinity(true) {}
        Point(long long x, long long y) : x(x), y(y), is_infinity(false) {}
    
        bool operator==(const Point& other) const 
        {
            if (is_infinity && other.is_infinity) 
                return true;
            if (is_infinity || other.is_infinity) 
                return false;
            return x == other.x && y == other.y;
        }
};

class EllipticCurve 
{
    public:
        long long a, b, p;
    
        EllipticCurve(long long a, long long b, long long p) : a(a), b(b), p(p) {}
    
        Point add(const Point& P, const Point& Q) 
        {
            if (P.is_infinity) 
                return Q;
            if (Q.is_infinity)  
                return P;
            if (P.x == Q.x && P.y != Q.y) 
                return Point();
    
            long long m;
            if (P == Q)  // Point doubling
                m = (3 * P.x * P.x + a) * inverse_mod(2 * P.y, p) % p;
            else // Point addition
                m = (Q.y - P.y) * inverse_mod(Q.x - P.x, p) % p;

            long long x_r = (m * m - P.x - Q.x) % p;
            long long y_r = (m * (P.x - x_r) - P.y) % p;
    
            // Ensure the result is in the range [0, p-1]
            x_r = (x_r + p) % p;
            y_r = (y_r + p) % p;
    
            return Point(x_r, y_r);
        }
    
        Point negate(const Point& P) 
        {
            return Point(P.x, (p - P.y) % p);
        }
    
    private:
        long long inverse_mod(long long k, long long p)
        {
            if (k == 0) 
                throw std::invalid_argument("Inverse does not exist");
            if (k < 0) 
                return p - inverse_mod(-k, p);
    
            long long s = 0, old_s = 1;
            long long t = 1, old_t = 0;
            long long r = p, old_r = k;
    
            while (r != 0) 
            {
                long long quotient = old_r / r;
                long long temp;
    
                temp = r;
                r = old_r - quotient * r;
                old_r = temp;
    
                temp = s;
                s = old_s - quotient * s;
                old_s = temp;
    
                temp = t;
                t = old_t - quotient * t;
                old_t = temp;
            }
    
            return (old_s + p) % p;
        }
};

//---------------------------------------------------------------------- main ----------------------------------------------------------------------//

int main() 
{

    string plaintextStr;
    int n;
 cout << " Enter : \n 1 -------- DES --------\n";
    cout << " 2 -------- AES -------- \n";
    cout << " 3 -------- RSA -------- \n";
    cout << " 4 ----- trial method -----\n";
    cout << " 5 ------ ElGamal ------ \n";
    cout << " 6 ------ Existential Forgery ------ \n";
    cout << " 7 - Digital Signature - \n";
    cout << " 8 -- Elliptic  Curve -- \n";

    cin >> n;

////////////////////////////////////////////////////////////////// DES //////////////////////////////////////////////////////////////////

    if (n == 1) {
       
        string key_hex, pt_hex;
        cout << "Enter a 16-character key (in hexadecimal): ";
        cin >> key_hex;
        if (key_hex.length() != 16) {
            cout << "Key must be 16 characters long." << endl;
            return 1;
        }

        string input;
        cout << "Enter a 16-character plain text : ";
        cin >> input;

        string binaryOutput = stringToBinary(input);
        cout << "plaintext (Binary): " << binaryOutput << endl;


         // Convert hexadecimal strings to binary
        string key_binary = "", pt_binary = "";
        for (char c : key_hex) {
            key_binary += convertHexToBinary(c);
        }
        for (char c : pt_hex) {
            pt_binary += convertHexToBinary(c);
        }

        // Print the key and plain text in binary
        cout << "Key (binary): " << key_binary << endl;

        generate_keys(key_binary);

        cout << "------------------------ Encryption --------------------\n" << endl;
        string ciphertext = DES(binaryOutput, true);
        cout << "Ciphertext: " << ciphertext << "\n" << endl;

        string binaryInput;

        if (binaryInput.size() % 8 != 0) {
            cout << "Invalid binary string length. Length should be a multiple of 8." << endl;
            return 1;
        }

        string asciiOutput = binaryToString(ciphertext);
        cout << "ASCII representation (cipher text) : " << asciiOutput <<"\n"<< endl;


        // Decrypt the ciphertext
        cout << "------------------------ Decryption --------------------\n" << endl;
        string decrypted_text = DES(ciphertext, false);
        cout << "Decrypted text: " << decrypted_text << "\n" << endl;

        string asciiOutput2 = binaryToString(decrypted_text);
        cout << "ASCII representation (cipher text) : " << asciiOutput2 <<"\n"<< endl;

    }

////////////////////////////////////////////////////////////////// AES //////////////////////////////////////////////////////////////////

    else if (n == 2) {

        cout << "Enter plaintext with 16 digits to encrypt : ";
        string input;
        cin >> input;

        string hexOutput = stringToHex(input);
        cout << "Hexadecimal representation: " << hexOutput << endl;
        plaintextStr = hexOutput;

       // cout << "Enter 128-bit plaintext (16 bytes in hex) : ";
       // cin >> plaintextStr;
        // Parse plaintext from input

        vector<unsigned char> plaintext = parseHex(plaintextStr);

        // Initialize state matrix with plaintext
        vector<vector<unsigned char>> state(4, vector<unsigned char>(4, 0));
        for (int i = 0; i < 16; ++i) {
            state[i % 4][i / 4] = plaintext[i];
        }

        cout << "Plaintext:" << endl;
        printState(state);

        string keyStr = "4a8e151628aed2a6abf7158809c55555";
        cout << "key is : " << keyStr <<endl;

        vector<unsigned char> key = parseHex(keyStr);

        aesEncrypt(state, key);


        cout << "Ciphertext:" << endl;
        printState(state);


        aesDecrypt(state, key);


        cout << "Decrypted text:" << endl;
        printState(state);
    }

////////////////////////////////////////////////////////////////// RSA //////////////////////////////////////////////////////////////////

    else if (n == 3) {
        int p1, q1, e1=0, d1=0, n1=0;

        cout << "Enter two prime numbers: ";
        cin >> p1 >> q1;

        generateKeys(p1, q1, e1, d1, n1);

        cout << "Public Key (e, n): (" << e1 << ", " << n1 << ")" << endl;
        cout << "Private Key (d, n): (" << d1 << ", " << n1 << ")" << endl;

        int msg1;
        cout << "Enter a message to encrypt: ";
        cin >> msg1;

        int encryptedMsg = encrypt(msg1, e1, n1);
        cout << "Encrypted message: " << encryptedMsg << endl;

        int decryptedMsg = decrypt(encryptedMsg, d1, n1);
        cout << "Decrypted message: " << decryptedMsg << endl;
    }

///////////////////////////////////////////////////////////// trial method /////////////////////////////////////////////////////////////
    else if (n == 4) {

    	unsigned long long N;
    	string response;

    	do {
    	    try {
    	        cout << "Enter the RSA modulus N (product of two primes): ";
    	        cin >> N;
	
	            trialDivision(N);

        	    }
           	 catch (const std::runtime_error& e) {
           	 cerr << e.what() << endl;
           	 }

        	cout << "Do you want another session? (yes/no): ";
        	cin >> response;

        	} 
		while (response == "yes" || response == "y");

        	cout << "Exiting. Thank you!" << endl;
    }

/////////////////////////////////////////////////////////////// Al-Gamal ///////////////////////////////////////////////////////////////

    else if (n == 5) {

        srand(time(0));

        long long p, g, x, y;
        key_generation(p, g, x, y);

        cout << "Public key (p, g, y): (" << p << ", " << g << ", " << y << ")\n";
        cout << "Private key x: " << x << "\n";

        long long message;
        cout << "Enter the message to encrypt (as a number): ";
        cin >> message;

        pair<long long, long long> ciphertext = encrypt(p, g, y, message);
        cout << "Encrypted message: (" << ciphertext.first << ", " << ciphertext.second << ")\n";

        long long decrypted_message = decrypt(p, x, ciphertext);
        cout << "Decrypted message: " << decrypted_message << "\n";


    }
  
////////////////////////////////////////////////////////// Existential Forgery//////////////////////////////////////////////////////////

    else if (n == 6) {

    	// المفاتيح العامة (n, e)
    	long long n; 
   	 cout << "Please enter a value of n: " ;
   	 cin >> n;
   	 long long e;
   	 cout << "Please enter a value of e: ";
   	 cin >> e;
    
   	 // المهاجم يختار توقيعًا عشوائيًا s
   	 long long s = rand() % n; // اختيار قيمة عشوائية أقل من n
	
	    // حساب الرسالة المقابلة للتوقيع
	    long long x = modExp(s, e, n); // x = s^e mod n
	
	    // طباعة النتائج
	    cout << "Public Key (n, e): (" << n << ", " << e << ")" << endl;
	    cout << "Chosen Signature (s): " << s << endl;
	    cout << "Computed Message (x): " << x << endl;
	
	    // التحقق من صحة التوقيع
    	    cout << "Verification: (s^e mod n == x): " << (modExp(s, e, n) == x ? "Valid" : "Invalid") << endl;

    }
////////////////////////////////////////////////////////////////// DSS //////////////////////////////////////////////////////////////////
    else if (n == 7) {

        // Input primes p and q
        unsigned long long p, q;
        cout << "Enter a prime number p: ";
        cin >> p;
        while (!isPrime(p)) {
            cout << "p is not prime. Enter a prime number p: ";
            cin >> p;
        }

        cout << "Enter a prime number q: ";
        cin >> q;
        while (!isPrime(q)) {
            cout << "q is not prime. Enter a prime number q: ";
            cin >> q;
        }

        // RSA key generation
        unsigned long long n, e, d;
        generateRSAKeys(n, e, d, p, q);


        unsigned long long message;
        cout << "Enter a message (integer in the range 1 to " << n - 1 << ") to sign: ";
        cin >> message;

        // Ensure message is in range
        if (message < 1 || message >= n) {
            cout << "Invalid message. Please enter an integer in the range 1 to " << n - 1 << ".\n";
            return 1;
        }

        // Sign the message
        unsigned long long signature = signMessage(message, d, n);

        // Display keys, message, and signature
        cout << "Public Key (n, e): (" << n << ", " << e << ")\n";
        cout << "Private Key (n, d): (" << n << ", " << d << ")\n";
        cout << "Message: " << message << "\n";
        cout << "Signature: " << signature << "\n";


        bool isVerified = verifySignature(message, signature, e, n);
        if (isVerified) {
            cout << "Signature verified successfully.\n";
        }
        else {
            cout << "Signature verification failed.\n";
        }

    }

//////////////////////////////////////////////////////////// Elliptic Curve ////////////////////////////////////////////////////////////

    else if (n == 8) {

        long long a, b, p;
        cout << "Enter curve parameters (a, b, p): ";
        cin >> a >> b >> p;

        EllipticCurve curve(a, b, p);

        long long x1, y1, x2, y2;
        cout << "Enter coordinates of point P (x1, y1): ";
        cin >> x1 >> y1;
        Point P(x1, y1);

        cout << "Enter coordinates of point Q (x2, y2): ";
        cin >> x2 >> y2;
        Point Q(x2, y2);

        Point R = curve.add(P, Q);
        cout << "R = (" << R.x << ", " << R.y << ")\n";

    }

    return 0;
}