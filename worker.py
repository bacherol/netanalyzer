from scapy.all import *
import time
import json

### Configuration
# IP for the test
ip_target = '1.1.1.1'

###


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
                return 'Destination unreachable'
            unreachable_hops_counter += 1
            packet_path[f'Hop #{pkt.ttl} unreachable'] = {
                "ttl": None,
                "latency": f'{end_time:.2f}'
            }

        # Increase TTL to go to next hop
        pkt.ttl += 1        
      
        # Stops when reach the 30 hop
        if pkt.ttl == 31:
            break

    return packet_path


def same_path_detection(network_tests):
    different_path = None
    for network_test in network_tests[1:]:
        if not 'unreachable' in str(network_test.keys()):
            if network_tests[0].keys() != network_test.keys():
                different_path = True
                break
    return different_path   


def packet_loss_detection(network_tests):
    detected_packet_loss = dict()
    hop_counter = dict()
    for traceroute in network_tests:
        for hop in traceroute.keys():
            if 'unreachable' in hop:
                continue
            hop_counter[hop] = hop_counter.get(hop, 0) + 1
    
    for hop in hop_counter:
        if hop_counter[hop] < 3:
            detected_packet_loss[hop] = f'{100 - ((hop_counter[hop] / 5) * 100)}%'
        
    if detected_packet_loss:
        return detected_packet_loss



def high_latency_detection(network_tests):
    high_latency = dict()
    high_latency_counter = dict()
    for trace in network_tests:
        for hop in trace:
            if not 'unreachable' in hop and float(trace[hop]['latency']) > 100:
                high_latency_counter[hop] = high_latency_counter.get(hop, 0) + 1
                if high_latency_counter[hop] > 3:
                    high_latency[hop] = trace[hop]['latency']
    if high_latency:
        return high_latency



if __name__ == '__main__':
    networks_tests = []
    for i in range(1, 6):
        pkt = packet_builder(ip_target, 1)
        trace_test = packet_sender(pkt)
        if 'unreachable' not in trace_test:
            networks_tests.append(trace_test)
        time.sleep(1)
    
    if networks_tests:
        try:
            result_test = dict()
            different_path = same_path_detection(networks_tests)
            packet_loss = packet_loss_detection(networks_tests)
            high_latency = high_latency_detection(networks_tests)
            if different_path:
                result_test["different_path"] = different_path
            if packet_loss:
                result_test["packet_loss"] = packet_loss
            if high_latency:
                result_test["high_latency"] = high_latency
            if result_test:
                print(result_test)
        except Exception as e:
            print(f'Error: {e}')
    
    ## ONLY FOR DEBUG PURPOSES
    # print(json.dumps(networks_tests))
    #else:
        #result_test = 'Destination Unreachable!'

