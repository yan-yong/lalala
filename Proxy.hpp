#ifndef __PROXY_HPP
#define __PROXY_HPP

#include "utility/murmur_hash.h"
#include "jsoncpp/include/json/json.h"

struct Proxy
{
    static const unsigned PROXY_SIZE = 50; 
    enum State
    {
        SCAN_IDLE,
        SCAN_HTTP,
        SCAN_CONNECT,
        SCAN_HTTPS,
        SCAN_JUDGE
    } state_;
    char ip_[16];
    uint16_t port_;
    unsigned err_num_;
    unsigned request_cnt_;
    time_t request_time_;
    unsigned char http_enable_ :1;
    unsigned char https_enable_:1;
    unsigned char is_foreign   :1;
    //代理类型
    enum Type
    {
        TYPE_UNKNOWN,
        TRANSPORT,
        ANONYMOUS,
        HIGH_ANONYMOUS
    } type_;

    char fill_buf_[PROXY_SIZE - sizeof(state_) - sizeof(type_) -
        sizeof(ip_) - sizeof(port_) - sizeof(err_num_) - 
        sizeof(request_cnt_) - sizeof(request_time_) - 1];

    Proxy()
    {
        memset(this, 0, sizeof(Proxy));
    }

    Proxy(std::string ip, uint16_t port)
    {
        memset(this, 0, sizeof(Proxy));
        strcpy(ip_, ip.c_str());
        port_ = port;
    }
    ~Proxy()
    {
    }
    std::string ToString() const
    {
        char buf[100];
        snprintf(buf, 100, "%s:%hu", ip_, port_);
        return buf;
    }
    Json::Value ToJson() const
    {
        Json::Value json_val;
        json_val["addr"] = ToString();
        if(https_enable_)
            json_val["https"] = "1";
        if(type_)
            json_val["type"]  = type_;
        char available_cnt_str[10];
        snprintf(available_cnt_str, 10, "%u", 
            request_cnt_ - err_num_);
        json_val["avail"] = available_cnt_str;
        return json_val;
    }
    bool operator < (const Proxy& other) const
    {
        int ret = strncmp(ip_, other.ip_, 16);
        return ret < 0 || (ret == 0 && port_ < other.port_);
    }
    struct sockaddr * AcquireSockAddr() const
    {
        return get_sockaddr_in(ip_, port_);
    }
} __attribute__((packed));

struct HashFunctor
{
    uint64_t operator () (const Proxy& proxy)
    {
        uint64_t val = 0;
        std::string proxy_str = proxy.ToString();
        MurmurHash_x64_64(proxy_str.c_str(), proxy_str.size(), &val);
        return val; 
    }
};

#endif
