from scapy.all import *
import time
import json
from statistics import stdev, median


def packet_builder(ip_dst, ip_ttl):
    ip_header = IP(dst=ip_dst, ttl=ip_ttl)
    protocol_header = ICMP()
    return ip_header / protocol_header


def packet_sender(pkt):
    unreachable_hops_counter = 0
    packet_path = {}
    while True:
        try:
            send_time = time.time()
            pkt_response = sr1(pkt, timeout=1, verbose=0)
            end_time = (time.time() - send_time) * 1000
        except Exception as exception_packet_sender:
            print(f'Error while sending packet: {exception_packet_sender}')

        if pkt_response:
            packet_path[pkt_response.src] = {
                "ttl": pkt_response.ttl,
                "latency": f'{end_time:.2f}'
            }

            # ICMP Response Types
            # 0 = Echo Reply (Destination reached)
            # 3 = Destination Unreachable
            if pkt_response.type == 3 or pkt_response.type == 0:
                break
        else:
            if unreachable_hops_counter == 3:
                break
            unreachable_hops_counter += 1
            packet_path[f'Hop #{pkt.ttl} unreachable'] = {
                "ttl": None,
                "latency": f'{end_time:.2f}'
            }

        #packet_analyser(pkt_response, end_time)
        pkt.ttl += 1        



        # Stops if 3 hops are unreachable
        

        # Stops when reach the 10 hop
        if pkt.ttl == 31:
            break

    return packet_path


def are_paths_same(network_tests):
    is_same_path = True
    for network_test in network_tests[1:]:
        if not 'unreachable' in network_test.keys():
            if network_tests[0].keys() != network_test.keys():
                is_same_path = False
                break

    return is_same_path   


def loss_detection(network_tests):
    hop_counter = dict()
    detected_packet_loss = dict()

    for network_test in network_tests:
        for hop in network_test.keys():
            if 'unreachable' in hop:
                continue
            hop_counter[hop] = hop_counter.get(hop, 0) + 1
    
    for hop in hop_counter:
        if hop_counter[hop] < 5:
            detected_packet_loss[hop] = f'{(hop_counter[hop] / 5) * 100}%'
        
    if detected_packet_loss:
        return detected_packet_loss
    
    return 'No loss detected'


def high_latency_detection(network_tests):
    high_latency = dict()
    for trace in network_tests:
        for hop in trace:
            if float(trace[hop]['latency']) > 100:
                high_latency[hop] = trace[hop]['latency']
    if high_latency:
        return high_latency
    
    return 'No high latency detected'


if __name__ == '__main__':
    networks_tests = []
    for i in range(1, 6):
        pkt = packet_builder('1.1.1.1', 1)
        networks_tests.append(packet_sender(pkt))
        time.sleep(1)
    #print(json.dumps(networks_tests))
    print(f'Same paths: {are_paths_same(networks_tests)}')
    print(f'Packet loss: {loss_detection(networks_tests)}')
    print(f'High latency: {high_latency_detection(networks_tests)}')












# def packet_crafter(pkt_dst, pkt_ttl):
#     unreachable_hops_counter = 0
#     while True:
#         ip_header = IP(dst=pkt_dst, ttl=pkt_ttl)
#         protocol_header = ICMP()
#         pkt = ip_header / protocol_header

#         try:
#             send_time = time.time()
#             pkt_response = sr1(pkt, timeout=1, verbose=0)
#             receive_time = (time.time() - send_time) * 1000
#             if pkt_response is None:
#                 print(f"{pkt_ttl}\t???\t100.0")
#                 unreachable_hops_counter += 1
#                 pkt_ttl += 1
#             elif pkt_response.type == 0:
#                 print(f"{pkt_ttl}\t{pkt_response.src}\t{receive_time:.2f} ms")
#                 break
#             elif pkt_response.type == 3:
#                 print(f"{pkt_ttl}\t{pkt_response.src}\t{receive_time:.2f} ms")
#                 break
#             else:
#                 print(f"{pkt_ttl}\t{pkt_response.src}\t{receive_time:.2f} ms")
#         except Exception as e:
#             print(f'Error while trying to send packet {e}')
        
#         if unreachable_hops_counter == 3:
#             break
#         if pkt_ttl == 30:
#             break
#         pkt_ttl += 1



