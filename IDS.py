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


def main(sniffer):
    main_buffer = {}
    while(True):
        temp_buffer = sniffer.run()
        print "Sniffer ran for 10 seconds. " + str(len(temp_buffer)) + " flows were created."
        ###
        ###ANALYZE
        ###
        main_buffer = buffer_merge(main_buffer, temp_buffer)
        print "Total Size of buffer: " + str(len(main_buffer))
        main_buffer = buffer_trim(main_buffer, 20)
        sniffer.flush_buffer()

if __name__ == "__main__":
    sniffer = Sniffer()

    main(sniffer)
