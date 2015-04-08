#include "ProxyScanner.hpp"
#include "fetcher/Fetcher.hpp"
#include "utility/net_utility.h"
#include "boost/bind.hpp"
#include "httpparser/TUtility.hpp"
#include "httpparser/URI.hpp"
#include "httpparser/HttpFetchProtocal.hpp"
#include "log/log.h"

const double   THRESHOLD_PERCENT = 0.9;
//tcp第一个握手包大小
const unsigned TCP_FIRST_PACKET_SIZE = 66;

ProxyScanner::ProxyScanner(ProxySet * proxy_set,
    Fetcher::Params fetch_params, 
    const char* eth_name):
    offset_save_time_(0), 
    try_http_uri_(NULL), try_http_size_(0),
    try_https_uri_(NULL),try_https_size_(0),
    proxy_judy_uri_(NULL), port_idx_(0), 
    local_addr_(NULL), validate_time_(0),
    validate_interval_(DEFAULT_VALIDATE_INTERVAL_SEC*1000),
    scan_time_(0), 
    scan_interval_(DEFAULT_SCAN_INTERVAL_SEC*1000),
    proxy_set_(proxy_set), stopped_(false),
    error_retry_num_(0), validate_idx_(0),
    each_validate_max_(100), max_tx_con_quota_(0),
    req_interval_(0), last_req_time_(0) 
{
    low_range_[0] = low_range_[1] = 0;
    low_range_[2] = low_range_[3] = 0;
    high_range_[0] = high_range_[1] = 255;
    high_range_[2] = high_range_[3] = 255;

    memset(offset_, 0, sizeof(offset_));
    uint16_t scan_ports[] = {80, 8080, 3128, 8118, 808};
    scan_port_.assign(scan_ports, scan_ports + sizeof(scan_ports)/sizeof(*scan_ports));
    memcpy(&params_, &fetch_params, sizeof(fetch_params));
    SetHttpTryUrl("http://www.baidu.com/img/baidu_jgylogo3.gif", 705);
    SetHttpsTryUrl("https://www.baidu.com/img/baidu_jgylogo3.gif", 705);
    proxy_judy_uri_ = NULL;        

    fetcher_.reset(new ThreadingFetcher(this));
    fetcher_->SetResultCallback(boost::bind(&ProxyScanner::ProcessResult, this, _1));
    ThreadingFetcher::RequestGenerator req_generator =
        boost::bind(&ProxyScanner::RequestGenerator, this, _1, _2);
    fetcher_->SetRequestGenerator(req_generator);
    if(eth_name)
    {
        local_addr_ = (struct sockaddr*)malloc(sizeof(struct sockaddr));
        memset(local_addr_, 0, sizeof(struct sockaddr)); 
        struct in_addr * p_addr = &((struct sockaddr_in*)local_addr_)->sin_addr;
        assert(getifaddr(AF_INET, 0, eth_name, p_addr) == 0);
        ((struct sockaddr_in*)local_addr_)->sin_family = AF_INET; 
    }
    conn_timeout_interval_ = fetch_params.conn_timeout.tv_sec * 1000 +
        fetch_params.conn_timeout.tv_usec / 1000;
    assert(conn_timeout_interval_ > 0);
}

ProxyScanner::~ProxyScanner()
{
    if(try_http_uri_)
        delete try_http_uri_;
    if(try_https_uri_)
        delete try_https_uri_;
}

void ProxyScanner::SetHttpTryUrl(std::string try_url, size_t page_size)
{
    if(try_http_uri_)
    {
        delete try_http_uri_;
        try_http_uri_ = NULL;
    }
    try_http_uri_ = new URI();
    if(!UriParse(try_url.c_str(), try_url.size(), *try_http_uri_)
        || !HttpUriNormalize(*try_http_uri_))
    {
        assert(false);
    }
    try_http_size_ = page_size;
}

void ProxyScanner::SetHttpsTryUrl(std::string try_url, size_t page_size)
{
    if(try_https_uri_)
    {
        delete try_https_uri_;
        try_https_uri_ = NULL;
    }
    try_https_uri_ = new URI();
    if(!UriParse(try_url.c_str(), try_url.size(), *try_https_uri_)
        || !HttpUriNormalize(*try_https_uri_))
    {
        assert(false);
    }
    try_https_size_ = page_size;
}

void ProxyScanner::SetProxyJudyUrl(std::string judy_url)
{
    proxy_judy_uri_ = new URI();
    if(!UriParse(judy_url.c_str(), judy_url.size(), *proxy_judy_uri_)
        || !HttpUriNormalize(*proxy_judy_uri_))
    {
        assert(false);
    }
}

void ProxyScanner::SetMaxTxSpeed(size_t max_tx_speed)
{
    max_tx_con_quota_ = max_tx_speed / TCP_FIRST_PACKET_SIZE;
}

void ProxyScanner::SetScanPort(const std::vector<uint16_t>& scan_port)
{
    scan_port_ = scan_port;
}

void ProxyScanner::SetScanOffset(unsigned offset[4])
{
    memcpy(offset_, offset, sizeof(offset_));
}

RawFetcherRequest ProxyScanner::CreateFetcherRequest(Proxy* proxy)
{
    assert(proxy->state_ != Proxy::SCAN_IDLE);
    proxy->request_time_ = current_time_ms();
    URI * uri = NULL;
    switch(proxy->state_)
    {
        case(Proxy::SCAN_HTTPS):
        {
            uri = try_https_uri_;
            break;
        }
        case(Proxy::SCAN_HTTP):
        {
            uri = try_http_uri_;
            ++(proxy->request_cnt_);
            break;
        }
        case(Proxy::SCAN_JUDGE):
        {
            uri = proxy_judy_uri_; 
            break;
        }
        default:
        {
            LOG_ERROR("invalid proxy state: %d.\n", proxy->state_);
            assert(false);
        }
    }
    FetchAddress fetch_address;
    fetch_address.remote_addr = proxy->AcquireSockAddr();
    fetch_address.remote_addrlen = sizeof(sockaddr);
    fetch_address.local_addr  = local_addr_;
    fetch_address.local_addrlen = local_addr_ ?sizeof(sockaddr):0;
    RawFetcherRequest request;
    request.conn = fetcher_->CreateConnection(
		str2protocal(uri->Scheme()), AF_INET,
		SOCK_STREAM, 0, fetch_address);
    free(fetch_address.remote_addr);
    //char tmp_buf[100] = {0};
    //uint16_t port = 0;
    //assert(get_addr_string(fetch_address.remote_addr, tmp_buf, 100, port)); 
    //LOG_INFO("request %s %hu %p\n", tmp_buf, port, fetch_address.remote_addr);
    request.context = (void*)proxy;
    return request;
}

void ProxyScanner::GetScanProxyRequest(
    int n, std::vector<RawFetcherRequest>& req_vec)
{
    time_t cur_time = current_time_ms();
    if(offset_[0]  == low_range_[0] && 
        offset_[1] == low_range_[1] &&
        offset_[2] == low_range_[2] &&
        offset_[3] == low_range_[3] &&
        port_idx_ == 0)
    {
        if(scan_time_ + scan_interval_ > cur_time)
            return;
        LOG_INFO("####### Start scan from %d.%d.%d.%d (%d.%d.%d.%d - %d.%d.%d.%d) ########\n",
            offset_[0], offset_[1], offset_[2], offset_[3],
            low_range_[0], low_range_[1], low_range_[2], low_range_[3],
            high_range_[0], high_range_[1], high_range_[2], high_range_[3]);
        scan_time_ = cur_time;
    }

    for(int i = 0 ; i < n; i++)
    {
        //进位
        if(port_idx_ == scan_port_.size())
        {
            port_idx_ = 0;
            offset_[3]++;
        }
        for(int i = 3; i >= 1; --i)
        {
            if(offset_[i] > high_range_[i])
            {
                offset_[i] = low_range_[i];
                offset_[i-1]++;
            }
        }
        //跳过内网地址
        if(offset_[0] == 10)
        {
            offset_[0] = 11;
            offset_[1] = low_range_[1];
            offset_[2] = low_range_[2];
            offset_[3] = low_range_[3];
        }
        if(offset_[0] == 172 && offset_[1] >= 16 && offset_[1] <= 31)
        {
            offset_[1] = 32;
            offset_[2] = low_range_[2];
            offset_[3] = low_range_[3];
        }
        if(offset_[0] == 192 && offset_[1] == 168)
        {
            offset_[1] = 169;
            offset_[2] = low_range_[2];
            offset_[3] = low_range_[3];
        }
        //检查是否结束
        if(offset_[0] > high_range_[0])
        {
            LOG_INFO("####### End scan from %d.%d.%d.%d (%d.%d.%d.%d - %d.%d.%d.%d) ########\n",
                offset_[0], offset_[1], offset_[2], offset_[3],
                low_range_[0], low_range_[1], low_range_[2], low_range_[3],
                high_range_[0], high_range_[1], high_range_[2], high_range_[3]);
            memcpy(offset_, low_range_, sizeof(low_range_));
            port_idx_ = 0;
            return;
        }
        uint16_t port = scan_port_[port_idx_];
        char ip_str[200];
        snprintf(ip_str, 200, "%d.%d.%d.%d", offset_[0], 
                offset_[1], offset_[2], offset_[3]);
        Proxy * proxy = new Proxy(ip_str, port);
        proxy->state_ = Proxy::SCAN_HTTP;
        req_vec.push_back(CreateFetcherRequest(proxy));
        ++port_idx_;
    }
}

void ProxyScanner::FinishProxy(Proxy* proxy)
{
    if(proxy->err_num_ > error_retry_num_)
    {
        LOG_INFO("erase failed proxy: %s\n", proxy->ToString().c_str());
        proxy_set_->erase(*proxy);
        delete proxy;
        return;
    }
    proxy->state_ = Proxy::SCAN_IDLE;
    if(proxy->request_cnt_ == 1)
    {
        if(proxy_set_->find(*proxy))
        {
            delete proxy;
            return;
        }
        LOG_INFO("===== %s %u %u %u =====\n", proxy->ip_, 
            proxy->port_, proxy->http_enable_, proxy->https_enable_);
    }
    proxy_set_->update(*proxy);
    delete proxy;
}

void ProxyScanner::ProcessResult(const RawFetcherResult& fetch_result)
{
    HttpFetcherResponse *resp = (HttpFetcherResponse *)fetch_result.message;
    Proxy* proxy = (Proxy*)fetch_result.context;
    assert(proxy->state_ != Proxy::SCAN_IDLE);
    fetcher_->CloseConnection(fetch_result.conn);
    fetcher_->FreeConnection(fetch_result.conn);

    if(rand() % 2000 == 0)
    {
        LOG_INFO("errno: %s %s %hu\n", strerror(fetch_result.err_num), 
            proxy->ip_, proxy->port_);
    }

    //** http result **//
    switch(proxy->state_)
    {
        case(Proxy::SCAN_HTTP):
        {
            if(fetch_result.err_num == 0 && resp && resp->Body.size() == try_http_size_)
            {
                proxy->err_num_ = 0;
                proxy->state_ = Proxy::SCAN_HTTPS;
                proxy->http_enable_ = 1;
                req_queue_.push(CreateFetcherRequest(proxy));
                if(proxy->request_cnt_ > 1)
                    LOG_INFO("validate success: %s.\n", proxy->ToString().c_str());
                break;
            }
            //first error.
            if(proxy->request_cnt_ == 1)
            {
                delete proxy;
                break;
            }
            ++(proxy->err_num_);
            LOG_INFO("validate error: %s %u\n", proxy->ToString().c_str(), proxy->err_num_);
            FinishProxy(proxy);
            break;
        }
        case(Proxy::SCAN_HTTPS):
        {
            if(fetch_result.err_num == 0 && resp && resp->Body.size() == try_https_size_)
                proxy->https_enable_ = 1;
            // no need judy proxy --> end
            if(proxy->type_ != Proxy::TYPE_UNKNOWN || !proxy_judy_uri_)
            {
                FinishProxy(proxy);
                break; 
            }
            proxy->state_ = Proxy::SCAN_JUDGE;
            req_queue_.push(CreateFetcherRequest(proxy));
            break;
        }
        case(Proxy::SCAN_JUDGE):
        {
            // last --> end
            const char *pat_str = "HTTP_X_FORWARDED_FOR";
            if(fetch_result.err_num == 0 && resp)
            {
                resp->Body.push_back('\0');
                if(strstr(&(resp->Body[0]), pat_str))
                    proxy->type_ = Proxy::TRANSPORT;
                else
                    proxy->type_ = Proxy::HIGH_ANONYMOUS;
            }
            else
                LOG_ERROR("request proxy judy url error: %s\n", proxy->ToString().c_str());
            FinishProxy(proxy);
            break;
        }
        default:
        {
            LOG_ERROR("invalid proxy state: %d\n", proxy->state_);
            assert(false);
        }
    }
    if(resp)
        delete resp;
}

void ProxyScanner::SetScanRange(unsigned low_range[4], unsigned high_range[4])
{
    if(high_range_[0] > 255)
        high_range_[0] = 255;
    if(high_range_[1] > 255)
        high_range_[1] = 255;
    if(high_range_[2] > 255)
        high_range_[2] = 255;
    if(high_range_[3] > 255)
        high_range_[3] = 255;
    if(offset_[0] < low_range[0])
        offset_[0] = low_range[0];
    if(offset_[1] < low_range[1])
        offset_[1] = low_range[1];
    if(offset_[2] < low_range[2])
        offset_[2] = low_range[2];
    if(offset_[3] < low_range[3])
        offset_[3] = low_range[3];
    memcpy(low_range_,  low_range,  4*sizeof(low_range[0]));
    memcpy(high_range_, high_range, 4*sizeof(high_range[0]));
}

void ProxyScanner::SetScanIntervalSeconds(time_t scan_interval_sec)
{
    scan_interval_ = scan_interval_sec * 1000; 
}

void ProxyScanner::SetErrorRetryNum(unsigned error_retry_num)
{
    error_retry_num_ = error_retry_num;
}

void ProxyScanner::SetValidateIntervalSeconds(time_t validate_interval_sec)
{
    validate_interval_ = validate_interval_sec * 1000; 
}

void ProxyScanner::SetSynRetryTimes(unsigned retry_times)
{
    int interval = 1000;
    for(unsigned i = 1; i <= retry_times; ++i)
    {
        req_interval_ += interval;
        interval *= 2; 
    }
    //add 1 second 
    req_interval_ += 1000;
    if(conn_timeout_interval_ < req_interval_)
        req_interval_ = conn_timeout_interval_;
    LOG_INFO("request interval: %u\n", req_interval_);
}

void ProxyScanner::RequestGenerator(
    int fetcher_quota, std::vector<RawFetcherRequest>& req_vec)
{
    time_t cur_time = current_time_ms();
    if(cur_time < last_req_time_ + 1000)
        return;
    last_req_time_ = cur_time;
    //计算配额
    int n = max_tx_con_quota_* 1000 / req_interval_;
    if(n > fetcher_quota)
        n = fetcher_quota;

    while(!req_queue_.empty() && n > 0)
    {
        RawFetcherRequest req = req_queue_.front();
        req_queue_.pop();
        req_vec.push_back(req);
        --n;
    }

    if(validate_time_ + validate_interval_ <= cur_time && n > 0)
    {
        if(validate_idx_ == 0)
            LOG_INFO("validate begin.\n");
        for(unsigned i = 0; i < each_validate_max_ && n > 0; i++)
        {
            Proxy * proxy = new Proxy();
            // 验证结束
            if(!proxy_set_->get_next(validate_idx_, *proxy))
            {
                delete proxy;
                validate_time_ = cur_time;
                validate_idx_  = 0;
                LOG_INFO("validate end.\n");
                break;
            }
            --n;
            proxy->state_ = Proxy::SCAN_HTTP;
            req_vec.push_back(CreateFetcherRequest(proxy));
            LOG_INFO("put validate request: %s\n", proxy->ToString().c_str());
        }
    }

    if(n > 0)
        GetScanProxyRequest(n, req_vec);

    LOG_INFO("put request: %zd\n", req_vec.size());
}

void ProxyScanner::Start()
{
    fetcher_->Begin(params_);
}

void ProxyScanner::GetScanOffset(unsigned offset[4]) const
{
    memcpy(offset, offset_, sizeof(offset_));
}

struct RequestData* ProxyScanner::CreateRequestData(void * contex)
{
    Proxy* proxy = (Proxy*)contex;
    HttpFetcherRequest* req = new HttpFetcherRequest();
    req->Clear();
    URI * uri = NULL;
    if(proxy->state_ == Proxy::SCAN_HTTP)
    {
        req->Uri    = try_http_uri_->ToString();
        uri  = try_http_uri_;
    }
    else
    {
        req->Uri    = try_https_uri_->ToString();
        uri  = try_https_uri_;
    }
    req->Method = "GET";
    req->Version= "HTTP/1.1";
    req->Headers.Add("Host", uri->Host());
    req->Headers.Add("Accept", "*/*");
    req->Headers.Add("Accept-Language", "zh-cn");
    req->Headers.Add("Accept-Encoding", "*");
    req->Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1)");
    req->Close();
    //LOG_INFO("request %s %u.\n", proxy->ip_.c_str(), proxy->port_);
    return req;
}

void ProxyScanner::FreeRequestData(struct RequestData * request_data)
{
    delete (HttpFetcherRequest*)request_data;
}

IFetchMessage* ProxyScanner::CreateFetchResponse(const FetchAddress& address, void * contex)
{
    HttpFetcherResponse* resp = new HttpFetcherResponse(
        address.remote_addr, 
        address.remote_addrlen,
        address.local_addr,
        address.local_addrlen,
        UINT_MAX, UINT_MAX);
    return resp;
}

void ProxyScanner::FreeFetchMessage(IFetchMessage *message)
{
    delete message;
}

void ProxyScanner::Stop()
{
    stopped_ = true;
    fetcher_->End();
}
