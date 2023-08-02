/*
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
  simple socket handling class for systems with BSD socket API
 */

#include <AP_HAL/AP_HAL.h>
#if HAL_OS_SOCKETS

#include "Socket.h"
#define CERT_FILE "/home/ravena/ssl-tutorial-2.3/finished_src/certs/ca-cert.pem"

/*
  constructor
 */
SocketAPM::SocketAPM(bool _datagram) : SocketAPM(_datagram, socket(AF_INET, _datagram ? SOCK_DGRAM : SOCK_STREAM, 0))
{
}

SocketAPM::SocketAPM(bool _datagram, int _fd) : datagram(_datagram), fd(_fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (!datagram)
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

}

SocketAPM::~SocketAPM()
{
    if (fd != -1)
    {
        ::close(fd);
        fd = -1;
    }
    
}

void SocketAPM::make_sockaddr(const char *address, uint16_t port, struct sockaddr_in &sockaddr)
{
    memset(&sockaddr, 0, sizeof(sockaddr));

#ifdef HAVE_SOCK_SIN_LEN
    sockaddr.sin_len = sizeof(sockaddr);
#endif
    
    sockaddr.sin_port = htons(port);
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr(address);
}

/*
  connect the socket
 */
bool SocketAPM::connect(const char *address, uint16_t port)
{
    int ret_log = 0;
    ret_log = wolfSSL_Debugging_ON();
    if (ret_log != 0) {
        // failed to set logging callback
        fprintf(stderr, "failed to turn debug on.\n");
        exit(EXIT_FAILURE);
    }

    // Inicialização da WolfSSL
    wolfSSL_Init(); /* Inicializa o WolfSSL */

    // Criação do WOLFSSL_CTX
    WOLFSSL_CTX *ctx;
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
    {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }

    // Carrega os certificados CA no WOLFSSL_CTX
    if (wolfSSL_CTX_load_verify_locations(ctx, "/home/ravena/ssl-tutorial-2.3/finished_src/certs/ca-cert.pem", 0) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading ../certs/ca-cert.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, "/home/ravena/ssl-tutorial-2.3/finished_src/certs/server-cert.pem", 0) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading ../certs/ca-cert.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    // Criação da estrutura sockaddr_in para o endereço e porta
    struct sockaddr_in sockaddr;

    address = "127.0.0.1"; // Endereço IP do servidor
    port = 12345;
    make_sockaddr(address, port, sockaddr);
   
    // Criação do socket TCP para a conexão
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "Error creating socket.\n");
        return false;
    }
    

    // Conexão usando TLS
    if (::connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0)
    {
        fprintf(stderr, "Error connecting to the server.\n");
        return false;
    }

    // Configuração do contexto TLS no socket
    if ( (ssl = wolfSSL_new(ctx)) == NULL)
    {
        fprintf(stderr, "wolfSSL_new error.\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Creating SSL object.\n");
    }

    // Configuração do contexto TLS no objeto SSL
    wolfSSL_set_fd(ssl, sockfd);

    if (wolfSSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to set SSL/TLS file descriptor.\n");
        exit(EXIT_FAILURE);
    } else {
        printf("Wolfssl_set_fd sucess");
    }

    // Inicia o handshake do TLS
    // wolfSSL_connect() inicia o handshake SSL/TLS com o servidor e é chamado durante wolfSSL_read() se não tiver sido chamado anteriormente. No nosso caso, não chamamos explicitamente wolfSSL_connect(), pois deixamos que nosso primeiro wolfSSL_read() faça isso por nós.

    printf("\nChegou antes do wolfssl_connect.\n");

    int ret = 0;
    int err = 0;
    char buffer[100];

    ret = wolfSSL_connect(ssl);

    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf("error no connect = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
    }


    // Handshake do TLS foi concluído com sucesso
    printf("TLS connection established.\n");

    // // Suponha que você queira enviar uma mensagem de texto como dados
    char msg[1024];
    int sendSz;
    strncpy(msg, "Ola Servidor", 13);
    sendSz = (int)strlen(msg);
    
   
    // Chame a função send do objeto ssl
    ssize_t bytesSent = send(msg, sendSz);
 
    // Verifique se o envio foi bem-sucedido
    if (bytesSent == -1) {
        printf("O envio da mensagem falhou.\n");
        return -1;
    } else {
        printf("Mensagem enviada com sucesso.\n");
    }


    wolfSSL_free(ssl);     // Liberar o objeto SSL em caso de falha na conexão
    wolfSSL_CTX_free(ctx); // Liberar o contexto SSL em caso de falha na conexão
    wolfSSL_Cleanup();     // Limpar recursos do wolfSSL em caso de falha na conexão

    return true;
}

/*
  bind the socket
 */
bool SocketAPM::bind(const char *address, uint16_t port)
{
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);


    if (::bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0)
    {
        return false;
    }
    return true;
}

/*
  set SO_REUSEADDR
 */
bool SocketAPM::reuseaddress(void) const
{
    int one = 1;
    return (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != -1);
}

/*
  set blocking state
 */
bool SocketAPM::set_blocking(bool blocking) const
{
    int fcntl_ret;
    if (blocking)
    {
        fcntl_ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    }
    else
    {
        fcntl_ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    }
    return fcntl_ret != -1;
}

/*
  set cloexec state
 */
bool SocketAPM::set_cloexec() const
{
    return (fcntl(fd, F_SETFD, FD_CLOEXEC) != -1);
}

/*
  send some data
 */


ssize_t SocketAPM::send(const void *buf, size_t size) const
{
    char bufferSend[100];
    int sslWriteResult = wolfSSL_write(ssl, buf, static_cast<int>(size));
    if (sslWriteResult < 0) {
        int error = wolfSSL_get_error(ssl, sslWriteResult);
        printf("error no send = %d, %s\n", error, wolfSSL_ERR_error_string(error, bufferSend));
        return -1;
    } else if (sslWriteResult == 0) {
        printf("Erro: Conexão fechada durante a operação de escrita.\n");
        return -1;
    } else {
        return static_cast<ssize_t>(sslWriteResult);
    }


}

/*
  send some data
 */
ssize_t SocketAPM::sendto(const void *buf, size_t size, const char *address, uint16_t port)
{
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);
    return ::sendto(fd, buf, size, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
}

/*
  receive some data
 */
ssize_t SocketAPM::recv(void *buf, size_t size, uint32_t timeout_ms)
{
    if (!pollin(timeout_ms)) {
        return -1;
    }
    
    int bytes_read = wolfSSL_read(ssl, buf, size);
    
    if (bytes_read <= 0) {

        int wolfssl_error = wolfSSL_get_error(ssl, bytes_read);

        if (wolfssl_error == SSL_ERROR_WANT_READ || wolfssl_error == SSL_ERROR_WANT_WRITE) {

            return 0; 

        } else if (wolfssl_error == SSL_ERROR_ZERO_RETURN) {
        
            return 0;
        } else {
            
            return -1;
        }
    }

    return bytes_read;
}

/*
  return the IP address and port of the last received packet
 */
void SocketAPM::last_recv_address(const char *&ip_addr, uint16_t &port) const
{
    ip_addr = inet_ntoa(in_addr.sin_addr);
    port = ntohs(in_addr.sin_port);
}

void SocketAPM::set_broadcast(void) const
{
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));
}

/*
  return true if there is pending data for input
 */
bool SocketAPM::pollin(uint32_t timeout_ms)
{
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000UL;

    if (select(fd + 1, &fds, nullptr, nullptr, &tv) != 1)
    {
        return false;
    }
    return true;
}

/*
  return true if there is room for output data
 */
bool SocketAPM::pollout(uint32_t timeout_ms)
{
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000UL;

    if (select(fd + 1, nullptr, &fds, nullptr, &tv) != 1)
    {
        return false;
    }
    return true;
}



/*
   start listening for new tcp connections
 */
bool SocketAPM::listen(uint16_t backlog) const
{
    return ::listen(fd, (int)backlog) == 0;
}

/*
  accept a new connection. Only valid for TCP connections after
  listen has been used. A new socket is returned
*/
SocketAPM *SocketAPM::accept(uint32_t timeout_ms)
{
    if (!pollin(timeout_ms))
    {
        return nullptr;
    }

    int newfd = ::accept(fd, nullptr, nullptr);
    if (newfd == -1)
    {
        return nullptr;
    }
    // turn off nagle for lower latency
    int one = 1;
    setsockopt(newfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return new SocketAPM(false, newfd);
}

#endif // HAL_OS_SOCKETS