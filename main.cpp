#define IPTYPE_TCP              0x06

#include "netfilter.h"

char * restricted_domain;
int nf_value;

#include "Trie.h"
#include <string>
#include <regex>

// Map {'first_letter', Trie*}
unordered_map<char, Trie*> triesMap;

// Domain name extraction
vector<string> readAddFile(const string fileurl) {
    vector<string> d_names;
    ifstream f(fileurl);

    if (!f.is_open()) {
	printf("Error : Unable to open the file");
	return d_names;
    }

    string line;
    while (getline(f, line)) {
	istringstream iss(line);
	string field;
	// Skip first column
	getline(iss, field, ',');
	// Read second column (address name)
	getline(iss, field, ',');
	d_names.push_back(field);
    }
    f.close();
    return d_names;

}

void usage() {
    printf("syntax : 1m-block <site list file>");
    printf("sample : 1m-block top-1m.txt");

}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void initTrie(vector<string> dNames) {
    // Generate Multiple Trie (first_letter)
    for (const std::string& str : dNames) {
        char firstLetter = str[0];
        if (firstLetter >= '0' && firstLetter <= '9') {
            //if first_letter is num
            if (triesMap.find('_') == triesMap.end()) {
                triesMap['_'] = new Trie();
            }
            triesMap['_']->insert(str);
        }
        else {
            // if first_letter is alphabet
            if (triesMap.find(firstLetter) == triesMap.end()) {
                triesMap[firstLetter] = new Trie();
            }
            triesMap[firstLetter]->insert(str);
        }
    }
    printf("Generate Limited Domain Trie\n");
}

bool searchString(string str) {
    // Search for strings in the tries
    char firstLetter = str[0];
    if (firstLetter >= '0' && firstLetter <= '9') firstLetter = '_';

    if (triesMap.find(firstLetter) != triesMap.end()) {
        bool found = triesMap[firstLetter]->search(str);
        return found;
    }
    else {
        // There is no trie
        return false;
    }
    
}


void inspect(unsigned char* buf, int size)
{
    struct ipv4_hdr *ip_hdr = (ipv4_hdr *)buf;
    //IP Header//
    if(ip_hdr->ip_p != IPTYPE_TCP) return;
    u_int8_t ip_hdr_len = (ip_hdr->VerIHL & 0x0F) * 4;
    u_int16_t total_len = (ntohs(ip_hdr->ip_len));

    //TCP Header//
    struct tcp_hdr *tcp_header = (tcp_hdr *)(buf+ ip_hdr_len);
    u_int8_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;

    u_int8_t payload_len = total_len - ip_hdr_len - tcp_hdr_len;
    if(payload_len <= 0) return;

    //TCP Payload//
    unsigned char *pl = buf + ip_hdr_len+ tcp_hdr_len;
    int n = payload_len;

    char payloads[n + 1];
    memcpy(payloads, pl, n);
    payloads[n] = '\0';
    /*
    char *pattern = "Host: ([a-zA-Z0-9\.]+)";

    regex_t reg;
    int reti;

    reti = regcomp(&reg, pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Failed to compile regex pattern\n");
        exit(1);
    }

    regmatch_t matches[2];
    reti = regexec(&reg, payloads, 2, matches, 0);
    if (!reti) {
        size_t host_len = matches[1].rm_eo - matches[1].rm_so;
        char host[host_len + 1];
        memcpy(host, payloads + matches[1].rm_so, host_len);
        host[host_len] = '\0';
        printf("Accessing Host: %s\n", host);
        if(!strcmp(host, restricted_domain)){
            nf_value = NF_DROP;
        }

    }
    // Free the compiled regex structure
    regfree(&reg);
    */
    string host_name;
    string c_to_str = string(payloads);
    regex pattern("Host: ([a-zA-Z0-9\.]+)");

    smatch matches;

    // Extract domain names from the packets
    if (std::regex_search(c_to_str, matches, pattern)) {
        if (matches.size() > 1) {
            cout << "Domain Name: " << matches[1] << endl;
            host_name = matches[1];
        }
    }
    
    if(searchString(host_name)){
    	nf_value = NF_DROP;
    }

}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        printf("payload_len=%d\n", ret);
        inspect(data, ret);
    }

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    nf_value = NF_ACCEPT;
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    return nfq_set_verdict(qh, id, nf_value, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        usage();
        return false;
    }

    string url_file_path = argv[1];
    vector<string> dNames;
    dNames = readAddFile(url_file_path);
    
    initTrie(dNames);

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
    
    for (auto& pair : triesMap) {
        delete pair.second;
    }

    exit(0);
}

