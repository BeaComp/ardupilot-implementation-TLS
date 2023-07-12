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

/*
  constructor
 */
SocketAPM::SocketAPM(bool _datagram) :
    SocketAPM(_datagram, 
              socket(AF_INET, _datagram?SOCK_DGRAM:SOCK_STREAM, 0))
{}

SocketAPM::SocketAPM(bool _datagram, int _fd) :
    datagram(_datagram),
    fd(_fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (!datagram) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
}

SocketAPM::~SocketAPM()
{
    if (fd != -1) {
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
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);

    if (::connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
        return false;
    }
    return true;
}

/*
  bind the socket
 */
bool SocketAPM::bind(const char *address, uint16_t port)
{
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
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certificados/certs.pem", 0) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading ./certificados/certs.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    // Criação da estrutura sockaddr_in para o endereço e porta
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);

    // Conexão usando TLS
    if (::connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0)
    {
        return false;
    }

    // Configuração do contexto TLS no socket
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
    {
        fprintf(stderr, "Error creating SSL object.\n");
        exit(EXIT_FAILURE);
    }
    wolfSSL_set_fd(ssl, fd);

    // Inicia o handshake do TLS
    if (wolfSSL_connect(ssl) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error establishing TLS connection.\n");
        exit(EXIT_FAILURE);
    }

    // A partir daqui, a conexão está estabelecida e segura
    // Você pode usar o objeto 'ssl' para enviar e receber dados com segurança

    wolfSSL_free(ssl);     // Liberar o objeto SSL em caso de falha na conexão
    wolfSSL_CTX_free(ctx); // Liberar o contexto SSL em caso de falha na conexão
    wolfSSL_Cleanup();     // Limpar recursos do wolfSSL em caso de falha na conexão

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
    if (blocking) {
        fcntl_ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    } else {
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
    return wolfSSL_write(ssl, buf, size);
}

/*
  send some data
 */
ssize_t SocketAPM::sendto(const void *buf, size_t size, const char *address, uint16_t port)
{
    struct sockaddr_in sockaddr;
    make_sockaddr(address, port, sockaddr);

    // Obtenha os dados criptografados usando wolfSSL_write()
    int encryptedSize = wolfSSL_write(ssl, buf, size);
    if (static_cast<size_t>(encryptedSize) != size)
    {
        // err_sys("wolfSSL_write failed");
        return -1;
    }

    // Envie os dados criptografados usando ::sendto()
    return ::sendto(fd, buf, encryptedSize, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
}

/*
  receive some data
 */
ssize_t SocketAPM::recv(void *buf, size_t size, uint32_t timeout_ms)
{
    if (!pollin(timeout_ms))
    {
        return -1;
    }

    // Variáveis para receber os dados criptografados
    char encryptedBuffer[size];
    int encryptedSize = wolfSSL_read(ssl, encryptedBuffer, size);
    if (encryptedSize <= 0)
    {
        // err_quit("wolfSSL_read error");
        return -1;
    }

    socklen_t len = sizeof(in_addr);
    return ::recvfrom(fd, buf, size, MSG_DONTWAIT, (sockaddr *)&in_addr, &len);
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
    setsockopt(fd,SOL_SOCKET,SO_BROADCAST,(char *)&one,sizeof(one));
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

    if (select(fd+1, &fds, nullptr, nullptr, &tv) != 1) {
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

    if (select(fd+1, nullptr, &fds, nullptr, &tv) != 1) {
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
    if (!pollin(timeout_ms)) {
        return nullptr;
    }

    int newfd = ::accept(fd, nullptr, nullptr);
    if (newfd == -1) {
        return nullptr;
    }
    // turn off nagle for lower latency
    int one = 1;
    setsockopt(newfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return new SocketAPM(false, newfd);
}

#endif // HAL_OS_SOCKETS
