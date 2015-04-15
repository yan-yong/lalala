#encoding: utf-8
import sys, urllib2, time, thread, re

save_ip_file = "ip.dat"

class IpSection:
    '''电信'''
    TELECOM = 1
    '''联通'''
    UNICOM  = 2
    '''移动'''
    CMCC    = 3
    '''铁通'''
    CRTC    = 4
    '''教育网'''
    CERNET  = 5
    '''其他'''
    OTHER   = 6 
    def __init__(self, ip_base, ip_mask_len, ip_type):
        self.ip_base_ = []
        for item in ip_base.split('.'):
            self.ip_base_.append(int(item))
        assert(len(self.ip_base_) == 4)
        self.ip_mask_len_ = ip_mask_len
        self.ip_type_ = ip_type
        self.low_  = []
        self.high_ = []
        intergen_len  = ip_mask_len / 8
        tail_len      = ip_mask_len % 8
        for i in range(4):
            self.low_.append(self.ip_base_[i])
            if i < intergen_len:
                self.high_.append(self.ip_base_[i])
            elif i == intergen_len:
                mask = (1 << (8 - tail_len)) - 1
                self.low_[i] = self.ip_base_[i] & (~mask)
                self.high_.append(self.low_[i] + mask)
            else:
                self.high_.append(255)
    def __cmp__(self, other):
        for i in range(4):
            if(self.ip_base_[i] > other.ip_base_[i]):
                return 1;
            elif(self.ip_base_[i] < other.ip_base_[i]):
                return -1;
        return 0;
    def __str__(self):
        return "%d.%d.%d.%d %d.%d.%d.%d %d" % (self.low_[0], self.low_[1], self.low_[2], self.low_[3], \
            self.high_[0], self.high_[1], self.high_[2], self.high_[3], self.ip_type_)

def log_error(str):
    time_str = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    sys.stderr.write('[%s] [%x] [error] %s\n' % (time_str, thread.get_ident(), str))
    sys.stderr.flush()
    #sys.stderr.flush()

def log_info(str):
    time_str = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    sys.stdout.write('[%s] [%x] [info] %s\n' % (time_str, thread.get_ident(), str))
    #sys.stdout.flush()

def get_resource_url(ip_type):
    if ip_type == IpSection.TELECOM:
        return 'http://ispip.clangcn.com/chinatelecom.html'
    elif ip_type == IpSection.UNICOM:
        return 'http://ispip.clangcn.com/unicom_cnc.html'
    elif ip_type == IpSection.CMCC:
        return 'http://ispip.clangcn.com/cmcc.html'
    elif ip_type == IpSection.CRTC:
        return 'http://ispip.clangcn.com/crtc.html'
    elif ip_type == IpSection.CERNET:
        return 'http://ispip.clangcn.com/cernet.html'
    elif ip_type == IpSection.OTHER:
        return 'http://ispip.clangcn.com/othernet.html'
    else:
        return ''

def main():
    reload(sys)
    sys.setdefaultencoding('utf-8');
    ip_type = 0
    if len(sys.argv) == 1:
        ip_type = 0
        log_info("acquire all ip type.\n")
    else:
        ip_type = int(sys.argv[1]);

    ip_sec_lst = []
    for type in range(1, IpSection.OTHER + 1):
        if ip_type > 0 and ip_type != type:
            continue
        url = get_resource_url(type)
        if len(url) == 0:
            assert(False) 
        try:
            content = urllib2.urlopen(url).read()
            log_info("download %s success\n" % url);
        except Excetpion, err:
            log_error("download %s error: %s\n" % (url, err))
        ret_lst = re.findall(r'(\d+?\.\d+?\.\d+?\.\d+?)/(\d+)', content)
        for ip_base, ip_mask_len in ret_lst:
            ip_sec_lst.append(IpSection(ip_base, int(ip_mask_len), type))

    MIN_IP_SECTION = 1000
    if len(ip_sec_lst) < MIN_IP_SECTION:
        log_error("FAILTURE: ip section num %d < %d" % (len(ip_sec_lst), MIN_IP_SECTION));
        sys.exit(1)
    ip_sec_lst.sort();
    save_file = open(save_ip_file, 'w')
    for ip_sec in ip_sec_lst:
        save_file.write("%s\n" % str(ip_sec));
    log_info("SUCCESS: write %d ip sections.\n" % len(ip_sec_lst))

if __name__ == "__main__":
    reload(sys)
    sys.setdefaultencoding("utf-8")
    main()
