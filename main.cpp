#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "log/log.h"
#include "ProxyScanner.hpp"
#include <sys/types.h>
#include <sys/wait.h>
#include "Config.hpp"
#include "httpserver/httpserver.h"
#include "lock/lock.hpp"

static const int MAX_PROCESS_CNT = 256;
static bool g_stop = false;
static unsigned g_proc_num = 0;
static Config*  g_cfg = NULL;
static SpinLock g_spin_lock;
struct ProcessInfo
{
    int pid_;
    unsigned low_range_[4];
    unsigned high_range_[4];

    ProcessInfo()
    {
        pid_ = 0;
        memset(low_range_, 0, sizeof(low_range_));
        memset(high_range_, 0, sizeof(high_range_));
    }
} g_proc_info[MAX_PROCESS_CNT];

static void SetupSignalHandler(bool is_worker);

static void WorkerRuntine(unsigned int low_range[4], unsigned int high_range[4])
{
    SetupSignalHandler(true);
    Fetcher::Params fetch_params;
    memset(&fetch_params, 0, sizeof(fetch_params));
    fetch_params.conn_timeout.tv_sec = g_cfg->connect_timeout_sec_;
    fetch_params.max_connecting_cnt  = g_cfg->max_connect_count_;
    fetch_params.socket_rcvbuf_size  = 8096;
    fetch_params.socket_sndbuf_size  = 8096;
    ProxyScanner proxy_scanner(fetch_params, "offset.dat");
    proxy_scanner.SetScanRange(low_range, high_range);
    proxy_scanner.SetScanIntervalSeconds(1000);
    proxy_scanner.Start();

    LOG_INFO("Worker process %d (%d.%d.%d.%d - %d.%d.%d.%d) start.\n", getpid(), 
        low_range[0], low_range[1], low_range[2], low_range[3],
        high_range[0], high_range[1], high_range[2], high_range[3]);
    while(!g_stop)
        sleep(1);
    LOG_INFO("Worker process %d (%d.%d.%d.%d - %d.%d.%d.%d) stopping ...\n", getpid(), 
        low_range[0], low_range[1], low_range[2], low_range[3],
        high_range[0], high_range[1], high_range[2], high_range[3]);
    proxy_scanner.Stop();
    LOG_INFO("Worker process %d end.\n", getpid());
    exit(0);
}

static void SpawnWorkerProcess()
{
    unsigned worker_process_count = g_cfg->worker_process_count_;
    unsigned* low_range = g_cfg->scan_low_range_;
    unsigned* high_range= g_cfg->scan_high_range_;
    assert(worker_process_count < MAX_PROCESS_CNT);
    int range_interval = (high_range[0] - low_range[0]) / worker_process_count;
    if(range_interval == 0)
        range_interval = 1;
    //check process num 
    for(unsigned i = 0; g_proc_num < worker_process_count && i < worker_process_count; i++)
    {
        if(g_proc_info[i].pid_)
            continue;
        if(g_proc_info[i].low_range_[0] == 0)
        {
            g_proc_info[i].low_range_[0]  = low_range[0] + i * range_interval;
            if(i != 0)
                g_proc_info[i].low_range_[0] += 1;
            g_proc_info[i].high_range_[0] = low_range[0] + (i+1)*range_interval;
            if(g_proc_info[i].low_range_[0] > 255)
                g_proc_info[i].low_range_[0] = 255;
            if(g_proc_info[i].high_range_[0] > 255)
                g_proc_info[i].high_range_[0] = 255;
            if(g_proc_info[i].low_range_[0] > g_proc_info[i].high_range_[0] ||
                    low_range[1] + low_range[2] + low_range[3] >=
                    high_range[1]+ high_range[2]+ high_range[3] )
            {
                g_proc_info[i].low_range_[0] = 0;
                g_proc_info[i].high_range_[0]= 0;
                break;
            }
            memcpy(g_proc_info[i].low_range_ + 1, low_range + 1, 3*sizeof(*low_range));
            memcpy(g_proc_info[i].high_range_+ 1, high_range+ 1, 3*sizeof(*high_range));
        }
        pid_t child_pid = fork();
        if(child_pid == 0)
        {
            WorkerRuntine(g_proc_info[i].low_range_, g_proc_info[i].high_range_);
        }
        g_proc_info[i].pid_ = child_pid;
        ++g_proc_num;
    }
}

static void SigChildHandler(int sig)
{
    while(1) 
    {
        SpinGuard guard(g_spin_lock);
        pid_t pid = 0;
        /* seems to be the bug of glibc */
        errno = 0;
        if((pid = waitpid(-1, NULL, WNOHANG)) <= 0) 
        {
            if(errno == EINTR)
                continue;
            return;
        }
        LOG_INFO("Found process %d quited.\n", pid);
        for(unsigned i = 0; i < g_proc_num && g_proc_info[i].pid_; i++) 
        {
            if(pid == g_proc_info[i].pid_) 
            {
                g_proc_info[i].pid_ = 0;
                std::swap(g_proc_info[i], g_proc_info[g_proc_num - 1]);
                --g_proc_num;
            }
        }
        if(!g_stop)
            SpawnWorkerProcess();
        return;
    }
}

static void SigQuitHandler(int sig)
{
    g_stop = true;
}

static void SetupSignalHandler(bool is_worker)
{
    signal(SIGPIPE, SIG_IGN);
    // worker
    if(is_worker)
    {
        struct sigaction quit_act, oact;
        sigemptyset(&quit_act.sa_mask);
        quit_act.sa_flags = 0;
        quit_act.sa_handler = SigQuitHandler;
        //sigaddset(&quit_act.sa_mask, SIGINT);
        //sigaddset(&quit_act.sa_mask, SIGTERM);
        sigaddset(&quit_act.sa_mask, SIGUSR1);
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        if(sigaction(SIGUSR1, &quit_act, &oact) < 0)
        {
            LOG_ERROR("child sigaction SIGUSR1 error.\n");
            return;
        }
    }

    struct sigaction worker_quit_act, oact;
    worker_quit_act.sa_handler = SigChildHandler;
    sigemptyset(&worker_quit_act.sa_mask);
    worker_quit_act.sa_flags = 0;
    //sigaddset(&worker_quit_act.sa_mask, SIGCHLD);
    if(sigaction(SIGCHLD, &worker_quit_act, &oact) < 0)
    {
        LOG_ERROR("parent sigaction SIGCHLD error.\n");
        return;
    }
}

int main(int argc, char* argv[])
{
    std::string config_file = "config.xml";
    if(argc == 1)
        LOG_INFO("Use default config file %s\n", config_file.c_str());
    else
        config_file = argv[1];
    g_cfg = new Config(config_file.c_str());
    g_cfg->ReadConfig();

    LOG_INFO("Master process starting ...\n");
    SpawnWorkerProcess();
    SetupSignalHandler(false);
    //set up httpserver
    boost::shared_ptr<HttpServer> httpserver(new HttpServer());
    httpserver->initialize(g_cfg->bind_ip_, g_cfg->listen_port_);
    httpserver->run();

    LOG_INFO("Master process stopping ...\n");
    g_stop = true;
    //kill child process
    for(int i = 0; i < MAX_PROCESS_CNT; ++i)
    {
        if(g_proc_info[i].pid_ == 0)
            continue;
        if(kill(g_proc_info[i].pid_, SIGUSR1) < 0)
            LOG_ERROR("kill %d error: %s\n", g_proc_info[i].pid_, strerror(errno));
        LOG_INFO("Master process killing worker process %d ...\n", g_proc_info[i].pid_);
    }
    
    for(unsigned i = 0; i < g_proc_num; i++)
    {
        if(g_proc_info[i].pid_)
        {
            int status = 0;
            waitpid(g_proc_info[i].pid_, &status, 0);
        }
    }

    return 0;
}
