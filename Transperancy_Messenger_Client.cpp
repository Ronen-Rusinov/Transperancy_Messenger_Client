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

std::string publicKeyToHex(const CryptoPP::RSA::PublicKey& publicKey)
{
    std::string encodedPublicKey;
    CryptoPP::StringSink* sink = new CryptoPP::StringSink(encodedPublicKey);

    // HexEncoder provides the hex encoding functionality
    CryptoPP::HexEncoder encoder(sink);
    publicKey.Save(encoder);

    // Finalize the encoding
    encoder.MessageEnd();

    // Clean up the sink
    delete sink;

    return encodedPublicKey;
}

std::string privateKeyToHex(const CryptoPP::RSA::PrivateKey& privateKey)
{
    std::string encodedPrivateKey;
    CryptoPP::StringSink* sink = new CryptoPP::StringSink(encodedPrivateKey);

    // HexEncoder provides the hex encoding functionality
    CryptoPP::HexEncoder encoder(sink);
    privateKey.Save(encoder);

    // Finalize the encoding
    encoder.MessageEnd();

    // Clean up the sink
    delete sink;

    return encodedPrivateKey;
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

void atexit_handler()
{
    *(globals.outputfile) << globals.j->dump(4);
    globals.outputfile->flush();
	globals.outputfile->close();
    delete globals.j;
    std::cout << "File saved.\n";
}

const int a = atexit(atexit_handler);

void tokenize(vector<string>& vec, string& s, string del)
{
    int start, end = -1 * del.size();
    do {
        start = end + del.size();
        end = s.find(del, start);
        vec.emplace_back(s.substr(start, end - start));
    } while (end != -1);
}

void tokenize(vector<string>& vec, const string& s, string del)
{
    int start, end = -1 * del.size();
    do {
        start = end + del.size();
        end = s.find(del, start);
        vec.emplace_back(s.substr(start, end - start));
    } while (end != -1);
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


    //SSL protocol

    boost::asio::io_context io_context;
    boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_client);
    
    globals.io_context = &io_context;

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

    queue<string> consoleQueue;
    mutex m;
    globals.m = &m;
    globals.que = &consoleQueue;

    std::array<char, 1024> myArray2;
    Clear_Queue(socket, consoleQueue, io_context, m);
    do_read(socket,myArray2);


    // Write the JSON object to the file
    const std::string jsonFileName = "Message_Context.json";
    
    
    globals.j = new json();
    json& jsonData = *globals.j;

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

        jsonData["uid"] = nullptr;
        jsonData["token"] = nullptr;
        jsonData["groups"] = json::array();

        std::cout << jsonData.dump(4) << std::endl;

         std::ofstream outputFile(jsonFileName);
         globals.outputfile = &outputFile;
         outputFile << jsonData.dump(4);
         outputFile.flush();
         outputFile.close();

    }

    if (!jsonExists)
    {
        //Initiate signup

        //initialise a string with hex encoded public key
        std::string hexPublicKey = publicKeyToHex(publicKey);
        cout << hexPublicKey << endl;

        //Initialise a SIGNUP request string with the hex encoded public key
        std::string signupRequest = "SIGNUP " + hexPublicKey + "]";

        //Send the SIGNUP request to the server
        boost::asio::write(socket, boost::asio::buffer(signupRequest));

        //Read the response from the server
        std::array<char, 1024> myArray;
        boost::asio::read(socket, boost::asio::buffer(myArray));
        std::string response = myArray.data();
        std::cout << response << std::endl;

        //REFERENCE:
        //"CODE=200\nSIGNUP SUCCESS\nUID=" + rows[0][0] + " TOKEN=" + std::to_string(token)

        //Parse the response
        std::vector<std::string> tokens;
        tokenize(tokens, response, "\n");
        std::vector<std::string> tokens2;
        tokenize(tokens2, tokens[2], " ");
        
        //Extracts rows[0][0] from UID=rows[0][0]
        std::string uid = tokens2[0].substr(4, tokens2[0].length() - 4);

        //Extracts token from TOKEN=token
        std::string token = tokens2[1].substr(6, tokens2[1].length() - 6);

        //Update the JSON object
        jsonData["token"] = stoi(token);
        jsonData["uid"] = stoi(uid);

        //Write the JSON object to the file
        *globals.outputfile << jsonData.dump(4);
        globals.outputfile->flush();

    }
    else 
    {
        //REFERENCE: "^SIGNIN UID=\\d{1,10} TOKEN=\\d+\\]"
        //Prepares SIGNIN request
        std::string signinRequest = "SIGNIN UID=" + std::to_string(jsonData["uid"].get<int>()) + " TOKEN=" + std::to_string(jsonData["token"].get<int>()) + "]";

        //Send the SIGNIN request to the server
        boost::asio::write(socket, boost::asio::buffer(signinRequest));

        //REFERENCE "CODE=200\nSIGNIN SUCCESS"
        // "CODE=401\nSIGNIN FAILURE"
        // "CODE=500\nSIGNIN FAILURE"
        //Read the response from the server
        std::array<char, 1024> myArray;
        boost::asio::read(socket, boost::asio::buffer(myArray));

        //Checks the response code
        std::string response = myArray.data();
        std::cout << response << std::endl;
        std::vector<string> tokens;
        tokenize(tokens, response, "\n");
        if (tokens[0] != "CODE=200")
        {
			std::cout << "Signin failed" << std::endl;
			return 1;
		}


        //REFERENCE FOR GETCONTEXT:
        //"^CONTEXT CURRENT=\\[(?:\\d+,\\d+)(?:&\\d+,\\d+)*\\]"
        
        //iterates over all groups and finds their last mesid, while constructing a request string
        stringstream ss;
        ss << "GETCONTEXT CURRENT=[";

        //checks that there are groups in the json file
        //if not, gets context for group 0 from mesid 0
        if (jsonData["groups"].size() == 0)
        {
            ss << "0,0\]";
        }

        for (const auto& value : jsonData["groups"])
        {
			std::string groupid = value["groupid"].get<std::string>();
			std::string lastmesid = value["lastmesid"].get<std::string>();

			std::string groupidlastmesid = groupid + "," + lastmesid;

			ss << "&" + groupidlastmesid;
		
		}
        ss << "\]";

        //Send the GETCONTEXT request to the server
        boost::asio::write(socket, boost::asio::buffer(ss.str()));
        
        //Read the response from the server
        std::array<char, 1024> myArray2;
        boost::asio::read(socket, boost::asio::buffer(myArray2));
        std::string response2 = myArray2.data();
        std::cout << response2 << std::endl;
        //REFERENCE: CODE=200\n<gid>,<mes>,<mes>\n<gid>,<mes>,<mes>&<keyid>,<key_body>\n<keyid>,<key_body>
        //REFERENCE: CODE=401\nGETCONTEXT FAILURE

        //Tokenises the repsponse by '&' and then by linebreaks
        std::vector<string> tokens2;
        tokenize(tokens2, response2, "&");
        std::vector<string> tokens3;
        tokenize(tokens3, tokens2[0], "\n");
        std::vector<string> tokens4;
        if (tokens2.size() > 1)
        {
			tokenize(tokens4, tokens2[1], "\n");
		}

        //Checks the response code
        if (tokens3[0] != "CODE=200")
        {
            cout << "Getcontext failed" << endl;
        }
        else
        {
            //For each ine in the response, tokenise by commas, and check if a group fitting it exists.
            //If not, create a new group and add it to the json file, then append the messages to the group.
            //Otherwise, append the messages to the group.
            
            std::vector<string> tokens6;

            for (auto& group : tokens3)
            {
                tokens6.clear();
				tokenize(tokens6, group, ",");
				bool groupExists = false;
                for (auto& value : jsonData["groups"])
                {
                    if (value["groupid"] == tokens6[0])
                    {
						groupExists = true;
						break;
					}
				}
                if (!groupExists)
                {
					json newGroup;
					newGroup["groupid"] = tokens6[0];
					newGroup["lastmesid"] = tokens6[1];
					newGroup["messages"] = json::array();
					jsonData["groups"].push_back(newGroup);
				}
                for (auto& value : jsonData["groups"])
                {
                    if (value["groupid"] == tokens6[0])
                    {
						value["lastmesid"] = value["lastmesid"]+ tokens6.size()-1 ;
                        for (int i = 1; i < tokens6.size(); i++)
                        {
							value["messages"].push_back(tokens6[i]);
						}
						break;
					}
				}
			}

            //Adds the keys to their respective groups
            if (tokens2.size() > 1)
            {
                for (auto& key : tokens4)
                {
					tokens6.clear();
					tokenize(tokens6, key, ",");
                    for (auto& value : jsonData["groups"])
                    {
                        if (value["groupid"] == tokens6[0])
                        {
							value["keyid"] = tokens6[1];
							value["key_body"] = tokens6[2];
							break;
						}
					}
				}
            }

            //Writes the json data to the file
            *globals.outputfile << jsonData.dump(4);
            globals.outputfile->flush();

            //Prints the json data to the console
            cout << jsonData.dump(4) << endl;
        }
    }


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

