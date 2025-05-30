#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct toaData {
    u8 opcode;
    u8 opsize;
    u16 port;
    u32 ip;
};


const volatile u8 opcode = 0;
const volatile u16 port = 0;
const volatile u32 ip = 0;

SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *skops){


    u32 op = skops->op;

    s32 rv = -1;

    switch (op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            //bpf_printk("enter connect cb\n");
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            break;
        }

        case BPF_SOCK_OPS_HDR_OPT_LEN_CB: {
            //bpf_printk("enter opt len cb\n");
            // rv = sizeof(struct toaData);
	    rv = 40;
            bpf_reserve_hdr_opt(skops, rv, 0);
            break;
        }
        case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: {
            //bpf_printk("enter write hdr opt\n");
            //bpf_printk("ip:%d",bpf_htons(ip));
            struct toaData fakeToa1 = {
                    .opcode = opcode,
                    .opsize = 0x08,
                    .port = bpf_htons(port),
                    .ip = bpf_htonl(ip)
            };
	    struct toaData fakeToa2 = {
                    .opcode = 253,
                    .opsize = 0x08,
                    .port = bpf_htons(port),
                    .ip = bpf_htonl(ip)
            };
	    struct toaData fakeToa3 = {
                    .opcode = 200, // tencent
                    .opsize = 0x08,
                    .port = bpf_htons(port),
                    .ip = bpf_htonl(ip)
            };
	    struct toaData fakeToa4 = {
                    .opcode = 238,
                    .opsize = 0x08,
                    .port = bpf_htons(port),
                    .ip = bpf_htonl(ip)
            };
	    struct toaData fakeToa5 = {
                    .opcode = 201,
                    .opsize = 0x08,
                    .port = bpf_htons(port),
                    .ip = bpf_htonl(ip)
            };
            int ret = bpf_store_hdr_opt(skops, &fakeToa1, sizeof(fakeToa1), 0);
            ret = bpf_store_hdr_opt(skops, &fakeToa2, sizeof(fakeToa2), 0);
            ret = bpf_store_hdr_opt(skops, &fakeToa3, sizeof(fakeToa3), 0);
            ret = bpf_store_hdr_opt(skops, &fakeToa4, sizeof(fakeToa4), 0);
            ret = bpf_store_hdr_opt(skops, &fakeToa5, sizeof(fakeToa5), 0);
            if (ret!=0){
                bpf_printk("write options error!");
            }
        }


        default:
            rv = -1;
    }
    skops->reply = rv;
    return 1;

}
