// Transperancy_Messenger_Client.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <queue>
//JSON
#include <nlohmann/json.hpp>
//#include <boost/property_tree/ptree.hpp>
//#include <boost/property_tree/json_parser.hpp>
//GUI
#include <wx/wx.h>



//#include <gtk/gtk.h>

namespace fs = boost::filesystem;
//namespace pt = boost::property_tree;
using namespace std;
using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
using namespace CryptoPP;
using json = nlohmann::json;


std::string encryptAESKeyWithPublicKey(const std::string& publicKeyString, const std::string& aesKey)
{
    try
    {
        // Load the public key from a string
        CryptoPP::RSA::PublicKey publicKey;
        StringSource publicKeySource(publicKeyString, true);
        publicKey.Load(publicKeySource);

        // Convert the AES key from string to byte array
        byte aesKeyArray[AES::DEFAULT_KEYLENGTH];
        memcpy(aesKeyArray, aesKey.data(), AES::DEFAULT_KEYLENGTH);

        // Encrypt the AES key using the public key
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        size_t ciphertextLength = encryptor.CiphertextLength(AES::DEFAULT_KEYLENGTH);
        SecByteBlock encryptedKey(ciphertextLength);
        AutoSeededRandomPool prng;
        encryptor.Encrypt(prng, aesKeyArray, AES::DEFAULT_KEYLENGTH, encryptedKey);

        // Convert the encrypted key to hexadecimal format
        std::string encryptedKeyHex;
        StringSource(encryptedKey, encryptedKey.size(), true,
            new HexEncoder(new StringSink(encryptedKeyHex)));

        return encryptedKeyHex;
    }
    catch (const Exception& ex)
    {
        std::cerr << "Crypto++ library exception: " << ex.what() << std::endl;
        return "";
    }
}


std::string decryptAESKeyWithPrivateKey(const std::string& privateKeyString, const std::string& encryptedAESKeyHex)
{
    try
    {
        // Load the private key from a string
        CryptoPP::RSA::PrivateKey privateKey;
        StringSource privateKeySource(privateKeyString, true);
        privateKey.Load(privateKeySource);

        // Convert the encrypted key from hexadecimal to byte array
        std::string encryptedKey;
        StringSource(encryptedAESKeyHex, true,
            new HexDecoder(new StringSink(encryptedKey)));

        // Decrypt the AES key using the private key
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        size_t decryptedLength = decryptor.FixedCiphertextLength();
        SecByteBlock decryptedKey(decryptedLength);
        AutoSeededRandomPool prng;
        ArraySource as(reinterpret_cast<const byte*>(encryptedKey.data()), encryptedKey.size(), true);
        as.Attach(new PK_DecryptorFilter(prng, decryptor,
            new ArraySink(decryptedKey, decryptedLength)));
        as.PumpAll();

        // Convert the decrypted key to string
        std::string decryptedKeyString(reinterpret_cast<const char*>(decryptedKey.data()), decryptedLength);

        return decryptedKeyString;
    }
    catch (const Exception& ex)
    {
        std::cerr << "Crypto++ library exception: " << ex.what() << std::endl;
        return "";
    }
}


void generateKeyPair(const std::string& privateKeyPath, const std::string& publicKeyPath)
{
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);

    CryptoPP::RSA::PublicKey publicKey(privateKey);

    CryptoPP::ByteQueue privateKeyBytes;
    privateKey.Save(privateKeyBytes);

    CryptoPP::ByteQueue publicKeyBytes;
    publicKey.Save(publicKeyBytes);

    CryptoPP::FileSink privateKeyFile(privateKeyPath.c_str());
    privateKeyBytes.CopyTo(privateKeyFile);

    CryptoPP::FileSink publicKeyFile(publicKeyPath.c_str());
    publicKeyBytes.CopyTo(publicKeyFile);
}

bool checkKeysExist(const std::string& privateKeyPath, const std::string& publicKeyPath)
{
    return fs::exists(privateKeyPath) && fs::exists(publicKeyPath);
}

void loadKeyPair(const std::string& privateKeyPath, const std::string& publicKeyPath,
    CryptoPP::RSA::PrivateKey& privateKey, CryptoPP::RSA::PublicKey& publicKey)
{
    CryptoPP::ByteQueue privateKeyBytes;
    CryptoPP::FileSource privateKeyFile(privateKeyPath.c_str(), true /*pumpAll*/);
    privateKeyFile.TransferTo(privateKeyBytes);
    privateKeyBytes.MessageEnd();
    privateKey.Load(privateKeyBytes);

    CryptoPP::ByteQueue publicKeyBytes;
    CryptoPP::FileSource publicKeyFile(publicKeyPath.c_str(), true /*pumpAll*/);
    publicKeyFile.TransferTo(publicKeyBytes);
    publicKeyBytes.MessageEnd();
    publicKey.Load(publicKeyBytes);
}

void do_read(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, std::array<char, 1024>& read_buffer )
{
    socket.async_read_some(boost::asio::buffer(read_buffer),
        [&socket,&read_buffer](const boost::system::error_code& error, size_t length) {
            if (!error) {

                std::string recieved = std::string(read_buffer.data(), length);
                std::cout << "Received: " << recieved << std::endl;
                do_read(socket,read_buffer);    
            }
        }

    );

}

void do_write(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket, std::array<char, 1024>& write_buffer)
{
    socket.async_write_some(boost::asio::buffer(write_buffer),


        [write_buffer](const boost::system::error_code& error, size_t length) {
            if (!error) {
                cout << "Successfully written: " << write_buffer.data() << endl;
            }
            else
            {
                cout << "Failed to write: " << write_buffer.data() << endl;

            }

        }
        

    );
}

void console_adaptor(queue<string> &que,mutex &m)
{
    while (1)
    {
        std::array<char, 1024> myArray;
        std::cout << "Enter a string: ";

        // Read input from console
        std::string input;
        std::getline(std::cin, input);
        m.lock();
        que.push(input);
        m.unlock();

    }


}

void Clear_Queue(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket,queue<string>& que, boost::asio::io_context& io_context,mutex &m)
{

    m.lock();

    while(!que.empty())
    {
        std::array<char, 1024> myArray{}; // Destination array
        string myString = que.front() ;
        que.pop();
        std::copy(myString.begin(), myString.end(), myArray.begin());
        do_write(socket,myArray);
    }
    m.unlock();

    io_context.post([&socket, &que, &io_context, &m]() {Clear_Queue(socket,que,io_context,m); });

}

struct Globals
{
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> *socket;
    queue<string> *que;
    boost::asio::io_context *io_context;
    mutex *m;
    std::ofstream* outputfile;
    json* j;
};

static Globals globals;

int main() {
    //Key pair protocol
    
    const std::string sslFolder = "SSL";
    const std::string privateKeyPath = sslFolder + "/private.key";
    const std::string publicKeyPath = sslFolder + "/public.key";

    if (!fs::exists(sslFolder))
    {
        fs::create_directory(sslFolder);
        std::cout << "SSL folder created.\n";
    }
    if (checkKeysExist(privateKeyPath, publicKeyPath))
    {
        std::cout << "Keys already exist in the SSL folder.\n";
        // Load keys and proceed with further operations if needed
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::RSA::PublicKey publicKey;
        loadKeyPair(privateKeyPath, publicKeyPath, privateKey, publicKey);


    }
    else
    {
        generateKeyPair(privateKeyPath, publicKeyPath);
        std::cout << "Key pair generated and saved in the SSL folder.\n";
    }
    // Load keys and proceed with further operations if needed
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
    loadKeyPair(privateKeyPath, publicKeyPath, privateKey, publicKey);

    //Message context loading protocol:
    //Checks if "Message_Context.json" exists within the current working directory, if not, generates a new one.
    //If it does exist, loads the file into a string and parses it into a json object.


    // Append data to the JSON object
    


  

    //SSL protocol

    boost::asio::io_context io_context;
    boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_client);
    
    globals.io_context = &io_context;

    std::array<char, 1024> read_buffer;
    std::array<char, 1024> write_buffer;

    // Load the self-signed certificate into the SSL context
    ssl_context.load_verify_file("SSL/server_certificate.crt");

    // Create an SSL socket and connect to the server
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket(io_context, ssl_context);
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address("127.0.0.1"), 8443);
    globals.socket = &socket;
    socket.lowest_layer().connect(endpoint);
    

    // Perform the SSL handshake
    socket.handshake(boost::asio::ssl::stream_base::handshake_type::client);

    std::cout << "SSL handshake completed successfully!" << std::endl;
    //std::cin;
    // Do other things with the SSL socket...
    
    //do_read(socket,read_buffer);
    
    //do_read(socket,read_buffer);
    queue<string> consoleQueue;
    mutex m;
    globals.m = &m;
    globals.que = &consoleQueue;

    std::array<char, 1024> myArray2;
    Clear_Queue(socket, consoleQueue, io_context, m);
    do_read(socket,myArray2);


    // Write the JSON object to the file
    const std::string jsonFileName = "Message_Context.json";
    
    
    json jsonData;
    globals.j = &jsonData;

    bool jsonExists = fs::exists(jsonFileName);


    // Check if the file exists
    if (jsonExists) {
        cout << "JSON file exists" << endl;
        // File exists, load it into the JSON object
        std::ifstream file(jsonFileName);
        std::stringstream buffer;
        buffer << file.rdbuf(); // Read the contents of the file into a stringstream

        std::string fileContents = buffer.str();

        try {
            jsonData = json::parse(fileContents);
        }
        catch (const std::exception& e) {
            std::cerr << "Error parsing JSON: " << e.what() << std::endl;
            return 1;
        }

        file.close();
        // jsonData = json::parse(file);
    }
    else {
        cout << "JSON file does not exist" << endl;
        // File doesn't exist, generate a new JSON object
        jsonData["token"] = nullptr;
        jsonData["groups"] = json::object();

        std::cout << jsonData.dump(4) << std::endl;

         std::ofstream outputFile(jsonFileName);
         globals.outputfile = &outputFile;
         outputFile << jsonData.dump(4);
         outputFile.flush();
         outputFile.close();

    }

    //Prints JsonData to console
    //std::cout << jsonData.dump(4) << std::endl;

    std::thread t2([&m, &consoleQueue]() {console_adaptor(consoleQueue, m); });
    
    //std::ofstream outputFile(jsonFileName);
    //globals.outputfile = &outputFile;


    io_context.run();
    
    return 0;
}


//On exit closes outputfile and saves json data to file.
//On exit closes socket and io_context.


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

