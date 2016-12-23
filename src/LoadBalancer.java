package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;

import org.openflow.protocol.*;
import org.openflow.protocol.action.*;
import org.openflow.protocol.instruction.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.*;
import edu.wisc.cs.sdn.apps.l3routing.L3Routing;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
    public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
    private static final byte TCP_FLAG_SYN = 0x02;
	
    private static final short IDLE_TIMEOUT = 20;
	
    // Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
    @Override
    public void init(FloodlightModuleContext context)
	    throws FloodlightModuleException 
    {
	log.info(String.format("Initializing %s... ", MODULE_NAME));
		
	// Obtain table number from config
	Map<String,String> config = context.getConfigParams(this);
	this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
	    String[] configItems = instanceConfig.split(" ");
	    if (configItems.length != 3)
            { 
		log.error("Ignoring bad instance config: " + instanceConfig);
		continue;
	    }
	    LoadBalancerInstance instance = new LoadBalancerInstance(
		    configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
	this.floodlightProv = context.getServiceImpl(
	        IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
    }

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }

	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
	    IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
	    log.info("SWITCH "+switchId+" ADDED");
		
	    OFMatch rule;
	    OFActionOutput action;
	    List<OFAction> actions;
	    List<OFInstruction> instructions;
	    OFInstructionApplyActions instruct;

	    Iterator itr = instances.entrySet().iterator();
	    while(itr.hasNext()) {
		LoadBalancerInstance instance = (LoadBalancerInstance)((Map.Entry)itr.next()).getValue();
		rule = new OFMatch();
		rule.setDataLayerType((short)0x800);
		rule.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, instance.getVirtualIP());
		action = new OFActionOutput(OFPort.OFPP_CONTROLLER);
		actions = new ArrayList<OFAction>();
		instructions = new ArrayList<OFInstruction>();
		actions.add(action);	
		instruct = new OFInstructionApplyActions(actions);
		instructions.add(instruct);
		SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, rule, instructions);
	    }
	    rule = new OFMatch();
	    rule.setDataLayerType(OFMatch.ETH_TYPE_ARP);
	    action = new OFActionOutput(OFPort.OFPP_CONTROLLER);
	    actions = new ArrayList<OFAction>();
	    instructions = new ArrayList<OFInstruction>();
	    actions.add(action);	
	    instruct = new OFInstructionApplyActions(actions);
	    instructions.add(instruct);
	    SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, rule, instructions);
	    rule = new OFMatch();
	    rule.setDataLayerType((short)0x800);
	    OFInstructionGotoTable instruction = new OFInstructionGotoTable(L3Routing.table);
	    instructions = new ArrayList<OFInstruction>();
	    instructions.add(instruction);
	    SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, rule, instructions);
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
	    // We're only interested in packet-in messages
	    if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
	    OFPacketIn pktIn = (OFPacketIn)msg;
	    
	    // Handle the packet
	    Ethernet ethPkt = new Ethernet();
	    ethPkt.deserialize(pktIn.getPacketData(), 0,
			       pktIn.getPacketData().length);
	    
	    /* Send an ARP replay for ARP requests for virtual IPs; for TCP SYNS
	       sent to a virtual IP, select a host and install connection-specific
	       rules to rewrite IP and MAC address; ignore all other packets. */
	    
	    if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
		ARP arp = (ARP)ethPkt.getPayload();
		if (arp.getOpCode() != ARP.OP_REQUEST 
		    || arp.getProtocolType() != ARP.PROTO_TYPE_IP) {
		    return Command.CONTINUE;
		}
		int targetIP = IPv4.toIPv4Address(arp.getTargetProtocolAddress());
		log.info(String.format("Received ARP request for %s from %s",
				       IPv4.fromIPv4Address(targetIP),
				       MACAddress.valueOf(arp.getSenderHardwareAddress()).toString()));
		LoadBalancerInstance instance = instances.get(new Integer(targetIP));
		log.info("Constructing reply....");
		byte[] deviceMac = instance.getVirtualMAC();
		arp.setOpCode(ARP.OP_REPLY);
		arp.setTargetHardwareAddress(arp.getSenderHardwareAddress());
		arp.setTargetProtocolAddress(arp.getSenderProtocolAddress());
		arp.setSenderHardwareAddress(deviceMac);
		arp.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(targetIP));
		ethPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
		ethPkt.setSourceMACAddress(deviceMac);
		SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethPkt);
	    } else if(ethPkt.getEtherType() == Ethernet.TYPE_IPv4){
		IPv4 ip = (IPv4)ethPkt.getPayload();
		if (ip.getProtocol() != IPv4.PROTOCOL_TCP) {
		    return Command.CONTINUE;
		}
		TCP tcp = (TCP)ip.getPayload();
		if (tcp.getFlags() != TCP_FLAG_SYN) {
		    return Command.CONTINUE;
		}
		OFMatch rule = new OFMatch();
		rule.setDataLayerType((short)0x800);
		rule.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		rule.setTransportSource(tcp.getSourcePort());
		rule.setTransportDestination(tcp.getDestinationPort());
		rule.setNetworkSource(OFMatch.ETH_TYPE_IPV4, ip.getSourceAddress());
		rule.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, ip.getDestinationAddress());
		LoadBalancerInstance instance = instances.get(ip.getDestinationAddress());
		int thisIP = instance.getNextHostIP();
		OFActionSetField macAction = new OFActionSetField(OFOXMFieldType.ETH_DST, getHostMACAddress(thisIP));
		OFActionSetField ipAction = new OFActionSetField(OFOXMFieldType.IPV4_DST, thisIP);
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(macAction);
		actions.add(ipAction);
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		OFInstructionApplyActions instruct = new OFInstructionApplyActions(actions);
		OFInstructionGotoTable instruction = new OFInstructionGotoTable(L3Routing.table);
		instructions.add(instruct);
		instructions.add(instruction);
		SwitchCommands.installRule(sw, table, SwitchCommands.MAX_PRIORITY, rule, instructions, (short)20, (short)20);
		OFMatch incoming = new OFMatch();
		incoming.setDataLayerType((short)0x800);
		incoming.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		incoming.setTransportSource(tcp.getDestinationPort());
		incoming.setTransportDestination(tcp.getSourcePort());
		incoming.setNetworkSource(OFMatch.ETH_TYPE_IPV4, thisIP);
		incoming.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, ip.getSourceAddress());
		log.info("IP of destination: " + ip.getDestinationAddress() + "Match on: " + thisIP + " and " + instance.getVirtualMAC() + " that IP " + instance.getVirtualIP());	
		OFActionSetField macSet = new OFActionSetField(OFOXMFieldType.ETH_SRC, instance.getVirtualMAC());
		OFActionSetField ipSet = new OFActionSetField(OFOXMFieldType.IPV4_SRC, instance.getVirtualIP());
		List<OFAction> actions2 = new ArrayList<OFAction>();
		actions2.add(macSet);
		actions2.add(ipSet);
		List<OFInstruction> instructions2 = new ArrayList<OFInstruction>();
		instruction = new OFInstructionGotoTable(L3Routing.table);
		OFInstructionApplyActions instruct2 = new OFInstructionApplyActions(actions2);
		instructions2.add(instruct2);
		instructions2.add(instruction);
		SwitchCommands.installRule(sw, table, SwitchCommands.MAX_PRIORITY, incoming, instructions2, (short)20, (short)20);
		log.info("Set the rules");		
	    }
		
	    // We don't care about other packets
	    return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
