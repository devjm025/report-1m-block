struct tcp_hdr
{
#define TH_FIN    0x01      /* finished send data */
#define TH_SYN    0x02      /* synchronize sequence numbers */
#define TH_RST    0x04      /* reset the connection */
#define TH_PUSH   0x08      /* push data to the app layer */
#define TH_ACK    0x10      /* acknowledge */
#define TH_URG    0x20      /* urgent! */
#define TH_ECE    0x40
#define TH_CWR    0x80

    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t data_offset;       /*data offset */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};
