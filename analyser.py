class Analyser:
	def varied_connections(self):
		port_set = set()
		source_set = set()
		print(self.flows.iteritems().next())
		for key in self.flows:
			port = key[3]
			source_ip = key[0]
			source_set.add(source_ip)
			port_set.add((source_ip, port))
		
		return len(port_set) - len(source_set)
			
	def average_duration(self):
		total_duration = 0
		for key, val in self.flows.iteritems():
			total_duration += val[2]
		
		return total_duration/len(self.flows)

	def __init__(self, flows):
		self.flows = flows
