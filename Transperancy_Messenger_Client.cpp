// Transperancy_Messenger_Client.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <queue>



using namespace std;
using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

int main() {
    boost::asio::io_context io_context;
    boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_client);

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
     
    while (1)
    {
        std::string command;
        std::cin >> command;
        boost::asio::write(socket,boost::asio::buffer(command));
    }
    
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
