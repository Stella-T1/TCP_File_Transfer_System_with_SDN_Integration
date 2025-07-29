"""
CAN201 CW Part II - Ryu Redirect
Copyright Group 8
Last Update: 30 Nov 2024
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto

clientIp = '10.0.1.5'
clientMac = '00:00:00:00:00:03'
server1Ip = '10.0.1.2'
server1Mac = '00:00:00:00:00:01'
server2Ip = '10.0.1.3'
server2Mac = '00:00:00:00:00:02'

class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}
        self.logger.info("[INFO]CAN201 CW Part II AY2024/25 - Group 8")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_idleTimeout(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, idle_timeout=5,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=5, match=match,
                                    instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        dst = eth_pkt.dst
        src = eth_pkt.src

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("[PACKET-IN], dpid:%s, src:%s, dst:%s, in_port:%s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            if eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                ip_src = ipv4_pkt.src
                ip_dst = ipv4_pkt.dst
                ip_protocol = ipv4_pkt.proto

                # ICMP Protocol
                if ip_protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=ip_src,
                                            ipv4_dst=ip_dst, ip_proto=ip_protocol)
                # TCP Protocol
                if ip_protocol == in_proto.IPPROTO_TCP:
                    #Capture the packet from Client to Server 1, and modify the dst eth & ipv4 address
                    if ip_src == clientIp and ip_dst == server1Ip:
                        if server2Mac in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][server2Mac]
                            self.logger.info("Successfully captured the data packet from [Client] to [Server 1] and modified the destination address to [Server 2]")
                        else:
                            out_port = ofproto.OFPP_FLOOD

                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)

                        actions = [parser.OFPActionSetField(eth_dst=server2Mac),
                                   parser.OFPActionSetField(ipv4_dst=server2Ip),
                                   parser.OFPActionOutput(port=out_port)]

                    #Capture the packet from Server 2 to Client, and modify the src eth & ipv4 address
                    elif ip_src == server2Ip and ip_dst == clientIp:
                        if clientMac in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][clientMac]
                            self.logger.info("Successfully captured the data packet from [Server 2] to [Client] and modified the source address to [Server 1]")
                        else:
                            out_port = ofproto.OFPP_FLOOD

                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)

                        actions = [parser.OFPActionSetField(eth_src=server1Mac),
                                   parser.OFPActionSetField(ipv4_src=server1Ip),
                                   parser.OFPActionOutput(port=out_port)]

                    else:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_dst=ip_dst,
                                                ip_proto=ip_protocol)

            #ARP Packet
            elif eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=in_port, eth_dst=dst,
                                        eth_src=src)

            #Update Flow Table
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow_idleTimeout(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow_idleTimeout(datapath, 1, match, actions)

            self.logger.info("[FLOW TABLE UPDATED] Match:%s, Actions:%s", match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        self.logger.info("[PACKET-OUT] dpid:%s, in_port:%s, actions:%s, buffer_id:%s", dpid, in_port, actions, msg.buffer_id)
        datapath.send_msg(out)
