#ifndef __PROXY_SERVICE_HPP
#define __PROXY_SERVICE_HPP
#include "httpserver/httpserver.h"

class Receiver: public HttpServer
{
    virtual void handle_recv_request(boost::shared_ptr<http::server4::request> http_req, 
            boost::shared_ptr<HttpSession> session)
    {   
        Request request(http_req, session);
        HandleTask::Instance()->enqueue(request);
    }   
};

#endif
