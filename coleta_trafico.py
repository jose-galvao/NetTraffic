#!/usr/bin/env python3

import socket
import struct
from bcc import BPF
import ctypes as ct


bpf_program = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// Estrutura para obter as portas de transporte (TCP/UDP)
struct transport_header_simple {
    u16 source;
    u16 dest;
};

//Estrutura para usar como chave do mapa. Define um fluxo.
struct fluxo_chave_ts {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
};

// Estrutura do evento, agora com o campo para o IAT.
struct ip_event {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    s64 inter_arrival_time_ns; // s64 para aceitar valor negativo inicial
    u32 tam_packet;
    u8 protocol;
};

// Mapa para enviar eventos para o user space
BPF_PERF_OUTPUT(events);

// Mapa para guardar o último timestamp de cada fluxo
BPF_HASH(last_timestamps, struct fluxo_chave_ts, u64, 10240);

int monitor_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    //Tamanh do pacote
    u32 tam_packet = (u32) (data_end - data);

    //timestamp atual
    u64 current_ktime_ns = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;


    // Preenche a chave do fluxo para usar no mapa
    struct fluxo_chave_ts flow_key = {};
    flow_key.src_ip = ip->saddr;
    flow_key.dst_ip = ip->daddr;
    flow_key.protocol = ip->protocol;

    u32 ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    void *transport_header_ptr = (void *)ip + ip_header_len;
    struct transport_header_simple *transport = (struct transport_header_simple *)transport_header_ptr;

    if ((void *)(transport + 1) > data_end) {
        return XDP_PASS;
    }

    // Completa a chave do fluxo com as portas
    flow_key.src_port = transport->source;
    flow_key.dst_port = transport->dest;

    // Preenche o evento
    struct ip_event event = {};
    event.src_ip = ip->saddr;
    event.dst_ip = ip->daddr;
    event.src_port = transport->source;
    event.dst_port = transport->dest;
    event.inter_arrival_time_ns = 0; // Valor padrão: N/A
    event.tam_packet = tam_packet;
    event.protocol = ip->protocol;

    u64 *prev_ts_ns_ptr = last_timestamps.lookup(&flow_key);
    if (prev_ts_ns_ptr != NULL) {
        // Se achou um timestamp anterior, calcula a diferença
        event.inter_arrival_time_ns = (s64)current_ktime_ns - (s64)(*prev_ts_ns_ptr);
    }
    // Atualiza o mapa com o timestamp do pacote atual para o próximo cálculo
    last_timestamps.update(&flow_key, &current_ktime_ns);

    events.perf_submit(ctx, &event, sizeof(event));

    return XDP_PASS;
}
"""

class IpEvent(ct.Structure):
    _fields_ = [
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("inter_arrival_time_ns", ct.c_int64),
        ("tam_packet", ct.c_uint32),
        ("protocol", ct.c_uint8),
    ]

def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

# Função de impressão modificada para exibir o IAT
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(IpEvent)).contents

    src_ip_str = ip_to_str(event.src_ip)
    dst_ip_str = ip_to_str(event.dst_ip)

    src_port_h = socket.ntohs(event.src_port)
    dst_port_h = socket.ntohs(event.dst_port)

    # Formata o IAT para exibição
    iat_str = "N/A"
    if event.inter_arrival_time_ns != 0:
        # Converte de nanossegundos para milissegundos
        iat_ms = event.inter_arrival_time_ns / 1000000.0
        iat_str = f"{iat_ms:.3f}"


    print(f"{iat_str};{src_ip_str};{src_port_h};{dst_ip_str};{dst_port_h};{event.tam_packet};{event.protocol}")


def main():
    interface_monitorada = "ens3"  #alterar paa interface q desejo monitorar

    bpf_instance = None
    try:
        bpf_instance = BPF(text=bpf_program)
        monitor_fn = bpf_instance.load_func("monitor_packets", BPF.XDP)

        try:
            bpf_instance.remove_xdp(interface_monitorada, 0)
        except Exception:
            pass
        bpf_instance.attach_xdp(interface_monitorada, monitor_fn, 0)

        bpf_instance["events"].open_perf_buffer(print_event)

        # Cabeçalho
        header = f"{'IAT_(ms)'};{'SRC_IP'};{'SRC_PORT'};{'DST_IP'};{'DST_PORT'};{'PACKET_SIZE_(B)'};N_PROTO"
        print(header)

        while True:
            try:
                bpf_instance.perf_buffer_poll(timeout=200)
            except KeyboardInterrupt:
                break

    finally:
        if bpf_instance:
            try:
                bpf_instance.remove_xdp(interface_monitorada, 0)
            except Exception:
                pass

if __name__ == "__main__":
    main()
