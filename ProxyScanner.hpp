#ifndef __PROXY_SCANNER_HPP
#define __PROXY_SCANNER_HPP
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <list>
#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>
#include <httpparser/TUtility.hpp>
#include <boost/unordered_set.hpp>
#include "lock/lock.hpp"
#include "utility/net_utility.h"
#include "fetcher/Fetcher.hpp"
#include "shm/ShareHashSet.hpp" 
#include "utility/murmur_hash.h"
#include "jsoncpp/include/json/json.h"
 
struct Proxy
{
    static const unsigned PROXY_SIZE = 50; 
    enum State
    {
        SCAN_IDLE,
        SCAN_HTTP,
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

typedef ShareHashSet<Proxy, HashFunctor> ProxySet; 

class ProxyScanner: protected IMessageEvents
{
    static const unsigned DEFAULT_SCAN_INTERVAL_SEC    = 0;
    static const unsigned DEFAULT_VALIDATE_INTERVAL_SEC= 600;
    static const unsigned DEFAULT_REQ_CHECK_INTERVAL   = 100;

    void __load_offset_file();
    void __save_offset_file();     

protected:
    virtual struct RequestData* CreateRequestData(void *);
    virtual void FreeRequestData(struct RequestData *);
    virtual IFetchMessage* CreateFetchResponse(const FetchAddress&, void *);
    virtual void FreeFetchMessage(IFetchMessage *);

    virtual void GetScanProxyRequest(int, std::vector<RawFetcherRequest>&);
    virtual void FinishProxy(Proxy* proxy);
    virtual void ProcessResult(const RawFetcherResult&);
    RawFetcherRequest CreateFetcherRequest(Proxy* proxy);
 
public:
    ProxyScanner(ProxySet * proxy_set,
        Fetcher::Params fetch_params,
        const char* eth_name = NULL);
    ~ProxyScanner();
    void SetHttpTryUrl(std::string try_url, size_t page_size);
    void SetHttpsTryUrl(std::string try_url, size_t page_size);
    void SetScanPort(const std::vector<uint16_t>& scan_port);
    void SetScanRange(unsigned low_range[4], unsigned high_range[4]); 
    void SetScanOffset(unsigned offset[4]);
    void GetScanOffset(unsigned offset[4]) const;
    void SetValidateIntervalSeconds(time_t validate_interval_sec);
    void SetScanIntervalSeconds(time_t scan_interval_sec);
    void SetErrorRetryNum(unsigned proxy_error_num);
    void SetProxyJudyUrl(std::string url);
    void SetMaxTxSpeed(size_t max_tx_speed);
    void SetSynRetryTimes(unsigned retry_times);
    void Stop();
    void RequestGenerator(int fetcher_quota, std::vector<RawFetcherRequest>& req_vec);
    void Start();

protected:
    Fetcher::Params params_;
    time_t offset_save_interval_;
    time_t offset_save_time_;
    Fetcher::Params fetcher_params_;
    URI*    try_http_uri_;
    size_t  try_http_size_;
    URI*    try_https_uri_;
    size_t  try_https_size_;
    URI*    proxy_judy_uri_;
    boost::shared_ptr<ThreadingFetcher> fetcher_;
    std::vector<uint16_t> scan_port_;
    unsigned offset_[4];
    unsigned port_idx_;
    unsigned low_range_[4];
    unsigned high_range_[4];
    sockaddr* local_addr_;
    time_t validate_time_;
    time_t validate_interval_;
    time_t scan_time_;
    time_t scan_interval_; 
    ProxySet *proxy_set_;
    bool stopped_;
    std::queue<RawFetcherRequest> req_queue_;
    unsigned error_retry_num_;
    ProxySet::HashKey validate_idx_;
    unsigned each_validate_max_;
    //单位是Byte
    size_t max_tx_con_quota_;
    std::map<time_t, unsigned> conn_traffic_stats_; 
    unsigned conn_timeout_interval_;
    unsigned req_interval_;
    time_t   last_req_time_;
};

inline time_t current_time_ms()
{
    timeval tv; 
    gettimeofday(&tv, NULL);
    return (tv.tv_sec*1000000 + tv.tv_usec) / 1000;
}

#endif 
