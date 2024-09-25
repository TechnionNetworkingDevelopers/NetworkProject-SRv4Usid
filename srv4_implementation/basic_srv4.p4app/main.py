from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo, Topo

# Define a custom topology class
class CustomTopo(Topo):
    def __init__(self, **opts):
        # Initialize the parent class
        Topo.__init__(self, **opts)
        
        # Add hosts and switches to the topology
        host_1 = self.addHost("h1", ip="10.1.0.0")
        switch_0 = self.addSwitch("s0")
        self.addLink(host_1, switch_0, port2=1)
        
        switch_3 = self.addSwitch("s3")
        self.addLink(switch_0, switch_3, port1=2, port2=1)
        
        switch_5 = self.addSwitch("s5")
        self.addLink(switch_3, switch_5, port1=2, port2=1)
        
        switch_6 = self.addSwitch("s6")
        self.addLink(switch_3, switch_6, port1=3, port2=1)
        
        switch_4 = self.addSwitch("s4")
        self.addLink(switch_5, switch_4, port1=2, port2=1)
        self.addLink(switch_6, switch_4, port1=2, port2=2)
        
        host_2 = self.addHost("h2", ip="10.2.0.0")
        self.addLink(switch_4, host_2, port2=1)

# Instantiate the custom topology
topo = CustomTopo()

# Create a P4Mininet network with the custom topology and a P4 program
net = P4Mininet(program="basic.p4", topo=topo)
net.start()

# Insert table entries for each link in the network
for src, dst in [
    ["h1", "s0"],
    ["s0", "s3"],
    ["s3", "s5"],
    # ["s3", "s6"],
    # ["s6", "s4"],
    ["s5", "s4"],
    # ["s4", "h2"],
]:
    if src == "h1" and dst == "s0":
        sw = net.get("s0")
        # Insert table entries for switch s0
        sw.insertTableEntry(
            table_name="MyIngress.srv4_ingress",
            match_fields={"hdr.ipv4.dstAddr": ["10.2.0.0", 32]},
            action_name="MyIngress.srv4_push_c_sid",
            action_params={"s1": 5},
        )
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.5.2.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("s3").intfs[1].MAC(), "port": 2},
        )
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.1.0.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("h1").intfs[0].MAC(), "port": 1},
        )
    elif src == "s0" and dst == "s3":
        sw = net.get("s3")
        # Insert table entries for switch s3
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.5.2.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("s5").intfs[1].MAC(), "port": 2},
        )
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.1.0.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("s0").intfs[1].MAC(), "port": 1},
        )
    elif src == "s3" and dst == "s5":
        sw = net.get("s5")
        # Insert table entries for switch s5
        sw.insertTableEntry(
            table_name="MyIngress.srv4_my_sid",
            match_fields={"hdr.ipv4.dstAddr": ["10.5.2.0", 32]},
            action_name="MyIngress.srv4_next_c_sid",
        )
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.2.0.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("s4").intfs[1].MAC(), "port": 2},
        )
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.1.0.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("s3").intfs[1].MAC(), "port": 1},
        )
    elif src == "s5" and dst == "s4":
        sw = net.get("s4")
        # Insert table entries for switch s4
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.2.0.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("h2").intfs[1].MAC(), "port": 3},
        )
        sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": ["10.1.0.0", 32]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": net.get("s5").intfs[1].MAC(), "port": 1},
        )
    # Print the table entries for the current switch
    sw.printTableEntries()

# Ping all hosts to check connectivity
loss = net.pingAll()
assert loss == 0

print("OK")