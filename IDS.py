import threading, time
from sniffer import Sniffer

def buffer_merge(buffer, t_buffer):
    for k,v in t_buffer.items():
        found = buffer.get(k)
        if not found:
            buffer[k] = [v[0], v[1], v[2]]
        else:
            buffer[k] = [found[0], v[1], v[1] - found[0]]
    return buffer

def buffer_trim(buffer, timerange):
    time_now = time.time()
    for k, v in buffer.items():
        if (time_now - v[1]) > timerange:
            del(buffer[k])
    return buffer

def get_sources(flows, source_set):
    for key in flows:
        source_set.add(key[0])
    return source_set

def varied_connections(flows, sip):
    count = 0
    for key in flows:
        if key[0] == sip:
            count += 1
    return count

def average_duration(flows, sip):
    port_count = 0
    total_duration = 0
    for key, val in flows.items():
        if key[0] == sip:
            total_duration += val[2]
            count += 1
    if count == 0:
        return 0
    else:
        return total_duration/count

def raise_alert(sip, severity):
    if severity == 'high':
        print "////////////////////////////////////////////////////////////////"
        print "     WARNING: LIKELY SCANNING ATTACK FROM SOURCE IP: " + sip
        print "////////////////////////////////////////////////////////////////"
    else:
        print "Possible Scanning Attack from Source IP: " + sip

def main(sniffer):
    main_buffer = {}
    source_set = set()
    while(True):
        flag = False
        temp_buffer = sniffer.run()
        main_buffer = buffer_merge(main_buffer, temp_buffer)

        for sip in source_set:
            if varied_connections(main_buffer, sip) > 3:
                if average_duration(main_buffer, sip) < 1:
                    raise_high_alert(sip, 'high')
                    flag = True
                else:
                    raise_low_alert(sip, 'low')
                    flag = True
        if not flag:
            print "No Suspicious Events Logged in Last Run Cycle."

        main_buffer = buffer_trim(main_buffer, 60)
        sniffer.flush_buffer()

if __name__ == "__main__":
    sniffer = Sniffer()

    main(sniffer)
