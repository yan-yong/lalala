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

class Proxy;

class ProxyScanner: protected IMessageEvents
{
    static const unsigned DEFAULT_SCAN_INTERVAL_SEC  = 0;
    static const unsigned DEFAULT_VALIDATE_INTERVAL_SEC= 600;

    inline time_t __remain_time(time_t last_time, time_t cur_time, time_t interval); 
    void __load_offset_file();
    void __save_offset_file();     

protected:
    virtual struct RequestData* CreateRequestData(void *);
    virtual void FreeRequestData(struct RequestData *);
    virtual IFetchMessage* CreateFetchResponse(const FetchAddress&, void *);
    virtual void FreeFetchMessage(IFetchMessage *);

    virtual void GetScanProxyRequest(int, std::vector<RawFetcherRequest>&);
    //virtual bool GetValidateProxyRequest(Connection* &, void* &);
    virtual void HandleProxyDelete(Proxy * proxy);
    virtual void HandleProxyUpdate(Proxy* proxy);
    virtual void ProcessResult(const RawFetcherResult&);
    RawFetcherRequest CreateFetcherRequest(Proxy* proxy);
 
public:
    ProxyScanner(Fetcher::Params fetch_params,
        const char* offset_file = NULL,
        time_t offset_save_sec  = 60, 
        const char* eth_name = NULL);
    virtual ~ProxyScanner(){}
    void SetHttpTryUrl(std::string try_url, size_t page_size);
    void SetHttpsTryUrl(std::string try_url, size_t page_size);
    void SetScanPort(const std::vector<uint16_t>& scan_port);
    void SetScanRange(unsigned low_range[4], unsigned high_range[4]); 
    void SetValidateIntervalSeconds(time_t validate_interval_sec);
    void SetScanIntervalSeconds(time_t scan_interval_sec);
    void Stop();
    void RequestGenerator(int n, std::vector<RawFetcherRequest>& req_vec);
    void Start();

protected:
    Fetcher::Params params_;
    const char* offset_file_;
    time_t offset_save_interval_;
    time_t offset_save_time_;
    Fetcher::Params fetcher_params_;
    URI*    try_http_uri_;
    size_t  try_http_size_;
    URI*    try_https_uri_;
    size_t  try_https_size_;
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
    boost::unordered_set<Proxy*> proxy_set_;
    boost::unordered_set<Proxy*>::iterator update_itr_;
    bool stopped_;
    std::queue<RawFetcherRequest> req_queue_;
};

#endif 
