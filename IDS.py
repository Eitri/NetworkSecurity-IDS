from sniffer import Sniffer

def main():
    s = Sniffer()
    buffer = s.run()
    print "Sniffer ran for 10 seconds. " + str(len(buffer)) + " flows were created."

if __name__ == "__main__":
    main()
