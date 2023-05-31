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
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
//GUI


namespace fs = boost::filesystem;
using namespace std;
using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

void generateKeyPair(const std::string& privateKeyPath, const std::string& publicKeyPath)
{
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

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
    else if (checkKeysExist(privateKeyPath, publicKeyPath))
    {
        std::cout << "Keys already exist in the SSL folder.\n";
        // Load keys and proceed with further operations if needed
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::RSA::PublicKey publicKey;
        loadKeyPair(privateKeyPath, publicKeyPath, privateKey, publicKey);


    }

    generateKeyPair(privateKeyPath, publicKeyPath);
    std::cout << "Key pair generated and saved in the SSL folder.\n";

    // Load keys and proceed with further operations if needed
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
    loadKeyPair(privateKeyPath, publicKeyPath, privateKey, publicKey);

    
    //SSL protocol

    boost::asio::io_context io_context;
    boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_client);

    std::array<char, 1024> read_buffer;
    std::array<char, 1024> write_buffer;

    // Load the self-signed certificate into the SSL context
    ssl_context.load_verify_file("SSL/server_certificate.crt");

    // Create an SSL socket and connect to the server
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket(io_context, ssl_context);
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address("127.0.0.1"), 8443);
    socket.lowest_layer().connect(endpoint);
    

    // Perform the SSL handshake
    socket.handshake(boost::asio::ssl::stream_base::handshake_type::client);

    std::cout << "SSL handshake completed successfully!" << std::endl;
    //std::cin;
    // Do other things with the SSL socket...
    
    //do_read(socket,read_buffer);
    
    io_context.run();
    while (1)
    {
        std::array<char, 1024> myArray;
        std::cout << "Enter a string: ";

        // Read input from console
        std::string input;
        std::getline(std::cin, input);

        // Copy input string to array
        std::strncpy(myArray.data(), input.c_str(), myArray.size());

        std::cout << input << endl;

        do_write(socket, myArray);
        io_context.run();
    }
    
    return 0;
}



// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

