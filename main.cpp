#include "includes.h"
using namespace std;
#include "config.h"

/*

    POC to see if we can make XOR safe/usable
    first github project!
    to compile: g++ -std=c++11 filename.cpp -lcrypto

*/

class enc_tools{
    public:
    string datagen(int datagenamount) // alphabet soup, for salt + key
    {
        srand(time(NULL));
        string randdata[63] = {"0","1","2","3","4","5","6","7","8","9", "a", "b", "c", "d", "e", "f", "g", "h", 
        "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "~", "@",
        "#", "]", "[", "}", "{", "|", "\\", ">", "<", ",", ".", "?", ";", "`", "=", "+", ")", "(", "*", "&", "^", "%", "$", "'", "\""};
        string gendata;
        for(int i=0; i<datagenamount; i++){
            gendata += randdata[(rand() % 63)];
        }
        return gendata;
    };
    string base64_encode( const string &str ) // *possible memory leak* http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
    {
        BIO *base64_filter = BIO_new( BIO_f_base64() );
        BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );
        BIO *bio = BIO_new( BIO_s_mem() );
        BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL );
        bio = BIO_push( base64_filter, bio );
        BIO_write( bio, str.c_str(), str.length() );
        BIO_flush( bio );
        char *new_data;
        long bytes_written = BIO_get_mem_data( bio, &new_data );
        string result( new_data, bytes_written );
        BIO_free_all( bio );
        return result;
    };
    string base64_decode( const string &str ) // *possible memory leak* http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
    {
        BIO *bio, *base64_filter, *bio_out;
        char inbuf[512];
        int inlen;
        base64_filter = BIO_new( BIO_f_base64() );
        BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );
        bio = BIO_new_mem_buf( (void*)str.c_str(), str.length() );
        bio = BIO_push( base64_filter, bio );
        bio_out = BIO_new( BIO_s_mem() );
        while( (inlen = BIO_read(bio, inbuf, 512)) > 0 ){
            BIO_write( bio_out, inbuf, inlen );
        }
        BIO_flush( bio_out );
        char *new_data;
        long bytes_written = BIO_get_mem_data( bio_out, &new_data );
        string result( new_data, bytes_written );
        BIO_free_all( bio );
        BIO_free_all( bio_out );
        return result;
    };    
};

class enc{
    public:
    string encrypt_decrypt(string to_encrypt, string xor_key) //xor
    {
        char key[xor_key.size()+1];
        strcpy(key, xor_key.c_str());
        string output = to_encrypt;
        for (int i = 0; i < to_encrypt.size(); i++)
        {
            output[i] = to_encrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];
        }
        return output; // implied memory release
    };
    string strip_salt(string encrypted_msg){
        vector<string> salt_strip_vect;
        boost::split(salt_strip_vect, encrypted_msg, boost::is_any_of("?")); // splits the string
        return salt_strip_vect[0];
    };
};



int main(int argc, char *argv[]){
    srand(time(NULL));
    enc_tools et;
    enc e;
    setup s;
    if(argc==3 || argc==5){
        string flag_find = argv[1],  to_enc = argv[2], salt, xor_pass, xor_pass_2, stripped_salt, encrypted_fin;
        if(flag_find.find("-e") != -1){
            if(et.base64_encode(to_enc).size() > stoi(s.max_key_length)){
                cout << "Using max key length of " << stoi(s.max_key_length) << " chars" << endl;
                xor_pass =  et.datagen((rand()%(stoi(s.max_key_length)-stoi(s.max_key_length)/2 + 1) + stoi(s.max_key_length)/2));
                xor_pass_2 =  et.datagen((rand()%(stoi(s.max_key_length)-stoi(s.max_key_length)/2 + 1) + stoi(s.max_key_length)/2));
            } else{
                xor_pass =  et.datagen(to_enc.size());
                sleep(2); // time as a seed
                xor_pass_2 =  et.datagen((rand()%(to_enc.size() - to_enc.size()/2+1) +to_enc.size()/2));
            }
            sleep(2);
            salt = et.base64_encode(e.encrypt_decrypt(et.base64_encode(to_enc), xor_pass)) + string("?") + et.base64_encode(et.datagen((rand()%(35-5+ 1) + 5)));
            encrypted_fin = et.base64_encode(e.encrypt_decrypt(et.base64_encode(salt), xor_pass_2));
            cout << "Encrypted string: " << encrypted_fin << endl;
            cout <<  "Pass 1: " << et.base64_encode(xor_pass) << endl;
            cout <<  "Pass 2: " << et.base64_encode(xor_pass_2) << endl;
        } else if(argc==5 && flag_find.find("-d") != -1){
            xor_pass = argv[3];
            xor_pass_2 = argv[4];
            cout << "First XOR pass being used: " << xor_pass << endl;
            cout << "Second XOR pass being used: " << xor_pass_2 << endl;
            stripped_salt = e.strip_salt(et.base64_decode(e.encrypt_decrypt(et.base64_decode(to_enc), et.base64_decode(xor_pass_2))));
            cout << "Decrypted string: " << et.base64_decode(e.encrypt_decrypt(et.base64_decode(stripped_salt), et.base64_decode(xor_pass)))  << endl; //black code
        }
    } else{
      cout << "Program name, string to enc ex: ./a.out -e \"string to encrypt\"" << endl;  
      cout << "Program name, string to decrypt ex: ./a.out -d \"string to encrypt\" \"xorpass1\" \"xorpass2\" " << endl;
    }
    
    return 0;
}