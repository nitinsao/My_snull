#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>

#include "snull.h"

#include <linux/in6.h>
#include <asm/checksum.h>

MODULE_AUTHOR("Nitin Sao");
MODULE_LICENSE("Dual BSD/GPL");			// BSD for IFF_RUNNING <- interface flag, but Most network drivers need not worry about IFF_RUNNING.

/*
 * Transmitter lockup simulation, normally disabled.
 */
static int lockup = 0;
// module_param(lockup, int, 0);

static int timeout = SNULL_TIMEOUT;			// In snull.h, SNULL_TIMEOUT = 5 (in jiffies)

/*
 * The devices
 */
struct net_device *snull_devs[2];
/*
 * Do we run in NAPI mode? we are not using it.
 */
// static int use_napi = 0;
// module_param(use_napi, int, 0);

int pool_size = 8;						// pool size for packets per dev
module_param(pool_size, int, 0);

// ---------------------------Last change-------------------------
// static void (*snull_interrupt)(int, void *, struct pt_regs *);
// ---------------------------------------------------------------

/*
 * A structure representing an in-flight packet.
 */
struct snull_packet {
	struct snull_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];			// ETH_DATA_LEN = 1500 octets (MTU)
};

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
struct snull_priv {
	struct net_device *dev;				// Was not in ldd3
	struct napi_struct napi;			// Was not in ldd3
	struct net_device_stats stats;		// the standard place to hold interface statistics
	/* We can see some data of stats in ifconfig */
	int status;
	// Below two lists are used to create (give a feel of) a ring buffer
	struct snull_packet *ppool;			// Packet pool, List of outgoing packets
	struct snull_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;					// Receive interrupt enable
	int tx_packetlen;					// Length of packet to be transmitted
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
};

/*
 * Enable and disable receive interrupts.
 */
static void snull_rx_ints(struct net_device *dev, int enable)
{
	int dev_num = 1;
	if(dev == snull_devs[0])
		dev_num = 0;
	printk(KERN_ALERT "%s called by sn%d, enable = %d", __FUNCTION__, dev_num, enable);
	struct snull_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}

/*
 * Set up a device's packet pool.
 */
void snull_setup_pool(struct net_device *dev)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	struct snull_priv *priv = netdev_priv(dev);
	int i;
	struct snull_packet *pkt;

	priv->ppool = NULL;					// Initializing packet pool
	for (i = 0; i < pool_size; i++) {		// Creating pool_size (8) packets and adding it to head of the ppool
		pkt = kmalloc (sizeof (struct snull_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}
}

/*
 * Open and close
 */
int snull_open(struct net_device *dev)		// is called whenever ifconfig activates it.
{
	/* registers any system resource, request_region(), request_irq(), ....  (like fops->open) */

	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	/* 
	 * Assign the hardware address of the board: use "\0SNULx", where
	 * x is 0 or 1. The first byte is '\0' to avoid being a multicast
	 * address (the first byte of multicast addrs is odd).
	 */
	// ETH_ALEN = 6
	memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);		// dev_addr : Interface address info used in eth_type_trans()
	// Above will do : snull_devs[0]->dev_addr = \0SNUL0
	// and snull_devs[1]->dev_addr = \0SNUL0, below instruction will change the last char of it
	if (dev == snull_devs[1])
		dev->dev_addr[ETH_ALEN-1]++; /* \0SNUL1 */
	netif_start_queue(dev);			// Allow upper layers to call the device hard_start_xmit routine.
	return 0;
}

int snull_release(struct net_device *dev)		// should reverse operations performed at open time.
{
    /* release ports, irq and such -- like fops->close */
	
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	netif_stop_queue(dev); /* can't transmit any more */
	/* Stop upper layers calling the device hard_start_xmit routine.
 	 * Used for flow control when transmit resources are unavailable.
	 */
	return 0;
}


/*
 * Buffer/pool management.
 */
struct snull_packet *snull_get_tx_buffer(struct net_device *dev)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	struct snull_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct snull_packet *pkt;
    
	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;						// outgoing pkt
	priv->ppool = pkt->next;				// can also be written as : priv->ppool = priv->ppool->next
	if (priv->ppool == NULL) {				// No more packets in queue.
		printk (KERN_INFO "Pool empty\n");
		netif_stop_queue(dev);				// stop transmitted packets, Used for flow control when transmit resources are unavailable.
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;					// Return netdev_priv(dev)->ppool (indirectly..)
}

void snull_enqueue_buf(struct net_device *dev, struct snull_packet *pkt)
	// Inserts packet in front of priv->rx_queue
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	unsigned long flags;
	struct snull_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	// Insert packet in front of priv->rx_queue
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}


/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
void snull_rx(struct net_device *dev, struct snull_packet *pkt)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	struct sk_buff *skb;
	struct snull_priv *priv = netdev_priv(dev);

	/*
	 * The packet has been retrieved from the transmission
	 * medium. Build an skb around it, so upper layers can handle it
	 */
	skb = dev_alloc_skb(pkt->datalen + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb, 2); /* align IP on 16B boundary */
	/* skb_reserve : Increase the headroom of an empty &sk_buff by reducing the tail
 	 * room. This is only allowed for an empty buffer.
 	 * skb->data += len;
	 * skb->tail += len;
 	 */  
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
	/* For skb_put(), see /net/core/skbuff.c => void *skb_put(struct sk_buff *skb, unsigned int len) */
	// It extends the used data area of the buffer by len, and returns the pointer of next to the used data area.

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;									// Its new skb, so initializing it
	// skb->protocol: Packet protocol from driver
	skb->protocol = eth_type_trans(skb, dev);		// determine the packet's protocol ID (/net/ethernet/eth.c)
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
	priv->stats.rx_packets++;					// Maintain the stats
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);								// post (skb) buffer to the network code (/net/core/dev.c)
	/* It receives a packet from a device driver and queues it for the upper (protocol) levels to process.*/
  out:
	return;
}

void snull_release_buffer(struct snull_packet *pkt)
// Adds pkt in the front of the priv->ppool, so it would be considered in next loop
{
	int dev_num = 0;
	if(pkt->dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	unsigned long flags;
	struct snull_priv *priv = netdev_priv(pkt->dev);
	
	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;				// Add pkt in the front of the priv->ppool, so it would be considered in next loop
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	/* netif_queue_stopped() : Test if transmit queue on device is currently unable to send.*/
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		/* netif_wake_queue - restart transmit, It allow upper layers to call the device hard_start_xmit routine.
			Used for flow control when transmit resources are available.*/
		netif_wake_queue(pkt->dev);
}

/*
 * The typical interrupt entry point
 * <priv->status is odd> maintains the stats, when transmission is done
 * <priv->status is even> receive the packet using snull_rx() 
 */
// static void snull_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)		// irq: 0, regs: NULL
static void snull_interrupt(int irq, void *dev_id, struct pt_regs *regs)		// irq: 0, regs: NULL
{
	int statusword;
	struct snull_priv *priv;
	struct snull_packet *pkt = NULL;
	/*
	 * As usual, check the "device" pointer to be sure it is
	 * really interrupting.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	/* ... and check with hw if it's really ours */

	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	/* paranoid */
	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & SNULL_RX_INTR) {			// See snull.h, SNULL_RX_INTR = 0x0001, ie. if statusword is odd
		/* send it to snull_rx for handling */
		pkt = priv->rx_queue;
		if (pkt) {
			priv->rx_queue = pkt->next;		// Most of the time pkt->next will be NULL, as generally we are transmitting single packet and receiving single pkt
			snull_rx(dev, pkt);				// Recieve pkt at dev (generally dest), not upto the socket, but pkt will be wrapped by sk_buff sent towards upper layers.
			printk(KERN_ALERT "Pkt received");
		}
	}
	if (statusword & SNULL_TX_INTR) {			// See snull.h, SNULL_TX_INTR = 0x0002, ie. if statusword is even
		/* a transmission is over: free the skb */
		priv->stats.tx_packets++;				// Maintain the stats
		priv->stats.tx_bytes += priv->tx_packetlen;
		printk(KERN_ALERT "Pkt transmitted, stats updated");
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	if (pkt) snull_release_buffer(pkt); /* Do this outside the lock! */
	// Received packet will be moved to ppool, so that it would be reconsidered for transmission
	return;
}



/*
 * Transmit a packet (low level interface)
 */
static void snull_hw_tx(char *buf, int len, struct net_device *dev)
{
	/*
	 * This function deals with hw details. This interface loops
	 * back the packet to the other snull interface (if any).
	 * In other words, this function implements the snull behaviour,
	 * while all other procedures are rather device-independent
	 */

	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d, buf : %s, len : %i", __FUNCTION__, dev_num, buf, len);

	struct iphdr *ih;				// IP header
	struct net_device *dest;
	struct snull_priv *priv;
	u32 *saddr, *daddr;				// IP addresses
	struct snull_packet *tx_buffer;
    
	/* I am paranoid. Ain't I? */
	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {			// Its less probable
		printk("snull: Hmm... packet too short (%i octets)\n",
				len);
		return;
	}

	if (0) { /* enable this conditional to look at the data */
		int i;
		PDEBUG("len is %i\n" KERN_DEBUG "data:",len);
		for (i=14 ; i<len; i++)							// Read below comment, printed data would include IP header
			printk(" %02x",buf[i]&0xff);
		printk("\n");
	}
	/*
	 * Ethhdr is 14 bytes, but the kernel arranges for iphdr
	 * to be aligned (i.e., ethhdr is unaligned)
	 */
	ih = (struct iphdr *)(buf+sizeof(struct ethhdr)); 		// Getting IP header from buf, after ethhdr
	saddr = &ih->saddr;				// Source IP
	daddr = &ih->daddr;				// Dest IP

	printk(KERN_ALERT "Changing N/w ID of src & dest\n");
	((u8 *)saddr)[2] ^= 1; /* change the third octet (class C) of Source Addr*/
	((u8 *)daddr)[2] ^= 1; /* change the third octet (class C) of Dest Addr*/

	ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	// Calculating checksum
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);		// Compute the IPv4 header checksum efficiently. <__sum16 ip_fast_csum(const void *iph, unsigned int ihl)>


	// For PDEBUGG, see snull.h -> It does nothing ;)
	if (dev == snull_devs[0])
		PDEBUGG("SN0 %08x:%05i --> %08x:%05i\n",
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source),		// ntohl: converts the unsigned integer 'netlong' from network byte order to host byte order.
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest));		// ntohs: converts the unsigned short integer 'netshort' from network byte order to host byte order.
	else
		PDEBUGG("SN1 %08x:%05i <-- %08x:%05i\n",
				ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest),
				ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source));

	/*
	 * Ok, now the packet is ready for transmission: first simulate a
	 * receive interrupt on the twin device, then  a
	 * transmission-done on the transmitting device
	 */
	dest = snull_devs[dev == snull_devs[0] ? 1 : 0];	// If dev(src) is sn0, then dest will be sn1
	priv = netdev_priv(dest);							// Get private data of dest
	tx_buffer = snull_get_tx_buffer(dev);				// Get the packet (ppool) pointer(to be sent) from private data using dev
	tx_buffer->datalen = len;							// feed the packet of dev (ie. src)
	memcpy(tx_buffer->data, buf, len);					// feed the packet with actual data (buf)
	snull_enqueue_buf(dest, tx_buffer);					// enqueue tx_buffer in the front of list of incoming pkt of dest. 
	/*
	tx_buffer->next = priv->rx_queue;
	priv->rx_queue = tx_buffer;
	*/
	if (priv->rx_int_enabled) {
		printk(KERN_ALERT "Receive Interrupt Enabled in function %s by dest :sn%d", __FUNCTION__, 1-dev_num);
		priv->status |= SNULL_RX_INTR;				// See snull.h, SNULL_RX_INTR = 0x0001
		snull_interrupt(0, dest, NULL);			// snull_regular_interrupt() will be called, as we are not using napi.
		// snull_interrupt either Recieve pending packets or maintains stats if pkt transmitted.
	}

	priv = netdev_priv(dev);						// Get private data of src, now work with src
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= SNULL_TX_INTR;					// SNULL_TX_INTR = 0x0002
	if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {		//lockup simulation, normally disabled (lockup = 0)
        	/* Simulate a dropped transmit interrupt */
		netif_stop_queue(dev);
		PDEBUG("Simulate lockup at %ld, txp %ld\n", jiffies,
				(unsigned long) priv->stats.tx_packets);
	}
	else
		snull_interrupt(0, dev, NULL);			// snull_regular_interrupt() will be called, as we are not using napi.
}

/*
 * Transmit a packet (called by the kernel)
 */
int snull_tx(struct sk_buff *skb, struct net_device *dev)		// initiates the transmission of a packet
/* Full packet (protocol headers and all) is contained in a socket buffer ( sk_buff ) structure*/
{
	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct snull_priv *priv = netdev_priv(dev);
	
	data = skb->data;		// Data head pointer (unsigned char *data;)
	len = skb->len;			// Length of actual data (unsigned int len;)

	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d, data : %s, len : %i < %i", __FUNCTION__, dev_num, data, len, ETH_ZLEN);
	// ETH_ZLEN: 60

	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}

	/* Remember the skb, so we can free it at interrupt time */
	priv->skb = skb;

	/* actual deliver of data is device-specific, and not shown here */
	snull_hw_tx(data, len, dev);		// data: Actual data to be sent, len : Max length of data, dev : net_device as passed to it.


	return 0; /* Our simple device can not fail */
}

/*
 * Deal with a transmit timeout.
 */
void snull_tx_timeout (struct net_device *dev)
// It is called on the assumption that an interrupt has been missed or the interface has locked up.
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	struct snull_priv *priv = netdev_priv(dev);

	PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - netdev_get_tx_queue(dev, 0)->trans_start);
        /* Simulate a transmission interrupt to get things moving */
	priv->status = SNULL_TX_INTR;		// status changed to 0x0002
	snull_interrupt(0, dev, NULL);		// snull_regular_interrupt() will be called, as we are not using napi.
	// snull_interrupt either Recieve pending packets or maintains stats if pkt transmitted.
	priv->stats.tx_errors++;			// make an entry in stats (statistics)
	netif_wake_queue(dev);
	return;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *snull_stats(struct net_device *dev)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	struct snull_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
int snull_config(struct net_device *dev, struct ifmap *map)			// ifmap: Device mapping structure.
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "snull: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
        	/* request_irq() is delayed to open-time */
	}

	/* ignore other fields */
	return 0;
}

/*
 * Ioctl commands 
 */
// If you dont want net_device being up without your permission (ie. without ifconfig up), use this function
int snull_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	PDEBUG("ioctl\n");
	return 0;
}


/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
/*
int snull_change_mtu(struct net_device *dev, int new_mtu)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	unsigned long flags;
	struct snull_priv *priv = netdev_priv(dev);
	spinlock_t *lock = &priv->lock;
    
	 // check ranges 
	if ((new_mtu < 68) || (new_mtu > 1500))			// MTU must be between 68 and 1500
		return -EINVAL;
	
	 // * Do anything you need, and the accept the value
	 
	spin_lock_irqsave(lock, flags);
	dev->mtu = new_mtu;
	spin_unlock_irqrestore(lock, flags);
	return 0;  //success 
}
*/

static const struct net_device_ops snull_netdev_ops = {
	// open & stop called when IFF_UP changed
	.ndo_open		= snull_open,
	// ndo_open called when a network device transitions to the up state.
	.ndo_stop		= snull_release,
	// ndo_stop called when a network device transitions to the down state.

	.ndo_start_xmit		= snull_tx,					// initiates the transmission of a packet.
	// ndo_start_xmit called when a packet needs to be transmitted.
	.ndo_tx_timeout		= snull_tx_timeout,			// called by the networking code when a packet transmission fails to complete within a reasonable period
	// ndo_tx_timeout called when the transmitter has not made any progress for dev->watchdog ticks.
	.ndo_get_stats		= snull_stats,				// update a net_device_stats structure (dev->stats) and return a pointer to it. We are doing just a shortcut.
	// ndo_get_stats called when a user wants to get the network device usage statistics.
	.ndo_set_config		= snull_config,				// entry point for configuring the driver. Drivers for modern "hardware" normally do not need to implement this method.
	// ndo_set_config used to set network devices bus interface parameters.
	// Only dev->irq is set with map->irq

	// Below two are optional methods. (According to LDD3)
	.ndo_do_ioctl		= snull_ioctl,				// Performs interface-specific ioctl commands.
	// ndo_do_ioctl called when a user requests an ioctl which can't be handled by the generic interface code.
	// But the function (ndo_do_ioctl) is doing nothing.
	
	// .ndo_change_mtu		= snull_change_mtu,			// takes action if there is a change in the MTU for the interface.
	// ndo_change_mtu called when a user wants to change the Maximum Transfer Unit of a device.
	// MTU can be changed using `ifconfig sn0 mtu 1400`, which we are not going to do, so not needed.
};

/*
 * Builds the hardware header from the source and destination hardware addresses
 * eth_header is the default function for Ethernet-like interfaces, and ether_setup assigns this field accordingly.
 */
int snull_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	// void *skb_push(struct sk_buff *skb, unsigned int len) : add data to the start of a buffer
		// extends the used data area of the buffer at the buffer start.
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);	// creating space for ether_header

	eth->h_proto = htons(type);				// converts the unsigned short integer 'hostshort' from host byte order to network byte order.
	// Setting up the Hardware address of source and dest
	// If saddr or daddr is known, then use it otherwise use dev->dev_addr (Hw address of device)
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */		// Change the last bit of dest addr
	return (dev->hard_header_len);		// Return Maximum hardware header length.
}


static const struct header_ops snull_header_ops = {			// To control snull_header (not exactly..)
	.create 	= snull_header,			// called before ndo_start_xmit in snull_netdev_ops
	.cache 		= NULL,
};

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void snull_init(struct net_device *dev)
{
	int dev_num = 1;
	if(dev == snull_devs[0])
		dev_num = 0;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	struct snull_priv *priv;

	/*
	 * Then, initialize the priv field. This encloses the statistics
	 * and a few private fields.
	 */		
	// to get access to the private data pointer, it should use the netdev_priv inline function.
	// priv pointer is allocated along with the net_device structure.
	
	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct snull_priv));
	spin_lock_init(&priv->lock);		// Initialize the lock
	priv->dev = dev;				// Set the dev field, so we would be able to get dev through priv

   	/* 
	 * Then, assign other fields in dev, using ether_setup() and some
	 * hand assignments
	 */

	ether_setup(dev); /* assign some of the fields */
	/*
	void ether_setup(struct net_device *dev)
	{
		dev->header_ops			= &eth_header_ops;
		dev->type				= ARPHRD_ETHER;
		dev->hard_header_len 	= ETH_HLEN;
		dev->min_header_len		= ETH_HLEN;
		dev->mtu				= ETH_DATA_LEN;
		dev->min_mtu			= ETH_MIN_MTU;
		dev->max_mtu			= ETH_DATA_LEN;
		dev->addr_len			= ETH_ALEN;
		dev->tx_queue_len		= DEFAULT_TX_QUEUE_LEN;
		dev->flags				= IFF_BROADCAST|IFF_MULTICAST;
		dev->priv_flags			|= IFF_TX_SKB_SHARING;

		eth_broadcast_addr(dev->broadcast);
	}
	*/
	
	dev->watchdog_timeo = timeout;
	/* watchdog_timeo : The minimum time (in jiffies) that should pass before the networking layer
		decides that a transmission timeout has occurred and calls the driver’s tx_timeout function.
	*/

	//-----------------------------------Important Note---------------------------------------
	/*
	if (use_napi) {								// We are not using napi, use_napi = 0
		netif_napi_add(dev, &priv->napi, snull_poll, 2);
	}
	*/
	// Above call is not required, so snull_poll() is not copied here, so snull_dequeue_buf() is also not here.
	//----------------------------------------------------------------------------------------


	// Below commented are now in <struct net_device_ops snull_netdev_ops>
	/*		
	dev->open 				= snull_open;
	dev->stop 				= snull_release;
	dev->set_config 		= snull_config;
	dev->hard_start_xmit 	= snull_tx;
	dev->do_ioctl 			= snull_ioctl;
	dev->get_stats 			= snull_stats;
	dev->rebuild_header 	= snull_rebuild_header;		// This is not being used now.
	dev->hard_header 		= snull_header;				// Now it is controlled by dev->header_ops, defined below
	*/
	/*Below two : related to the handling of transmission timeouts*/
	/*
	dev->tx_timeout 		= snull_tx_timeout;
	dev->watchdog_timeo 	= timeout;					// This member watchdog_timeo not changed its place. Its defined above.
	*/

	/* keep the default flags, just add NOARP */
	dev->flags 				|= IFF_NOARP;		//IFF_NOARP : specifies that the interface cannot use the ARP.
	// Because the “remote” systems simulated by snull do not really exist, there is nobody available to answer ARP requests for them.
	// ~~Now NETIF_F_NO_CSUM is not there in /include/linux/netdev_features.h
	// dev->features 			|= NETIF_F_NO_CSUM;	// no checksums are ever required for this interface
	
	dev->features        	|= NETIF_F_HW_CSUM;	// hardware does checksumming itself
	// ~~Now hard_header_cache is not member of net_device
	// dev->hard_header_cache 	= NULL; 		// Disable caching it disables the caching of the (nonexistent) ARP replies on this interface
	dev->netdev_ops = &snull_netdev_ops;		// Now above function initializations are done through this
	dev->header_ops = &snull_header_ops;		// Includes snull_header creation

	snull_rx_ints(dev, 1);		/* enable receive interrupts */
	snull_setup_pool(dev);		// Creating pool_size (8) packets for packet pool of dev
}

void mysnull_cleanup(void);



int mysnull_init_module(void)
{

	printk(KERN_ALERT "%s called###", __FUNCTION__);

	int result, i, ret = -ENOMEM;

	// We are not using napi
	// snull_interrupt = use_napi ? snull_napi_interrupt : snull_regular_interrupt;
	// snull_interrupt = snull_regular_interrupt;

	/* Allocate the devices */
	// mynet_devs[0] = alloc_netdev(int sizeof_priv, const char *name, void (*setup)(struct net_device *));
	// sizeof_priv : size of the driver’s “private data” area
	// name : name of this interface, use of %d will get the next available number
	// setup : pointer to an initialization function to set up the rest of the net_device structure
	// alloc_netdev had 3 args, but now its 4 args
	snull_devs[0] = alloc_netdev(sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_init);
	snull_devs[1] = alloc_netdev(sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_init);
	if (snull_devs[0] == NULL || snull_devs[1] == NULL)
		goto out;
	// We want to make ethernet device interface, so we could use built-in function for allocation of the same
	// struct net_device *alloc_etherdev(int sizeof_priv);
	// uses eth%d for the name argument

	ret = -ENODEV;
	for (i = 0; i < 2; i++)
		if ((result = register_netdev(snull_devs[i])))
			// you should not register the device until everything (eg. driver) has been completely initialized.
			printk("snull: error %i registering device \"%s\"\n", result, snull_devs[i]->name);
		else
			ret = 0;
	printk(KERN_ALERT "register_netdev() Done.");
   out:
	if (ret) 
		mysnull_cleanup();
	return 0;
	// struct net_device is always put together at runtime. The initialization must be complete before calling register_netdev.
}

void snull_teardown_pool(struct net_device *dev)
{
	int dev_num = 0;
	if(dev == snull_devs[1])
		dev_num = 1;
	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);

	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;
    
	while ((pkt = priv->ppool)) {		// Free all the packets from ppool (packet pool) of dev
		priv->ppool = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
}    

void mysnull_cleanup(void)
{
	printk(KERN_ALERT "%s called###", __FUNCTION__);

	int i;
	for (i = 0; i < 2; i++) {
		if (snull_devs[i]) {
			unregister_netdev(snull_devs[i]);		// removes the interface from the system
			snull_teardown_pool(snull_devs[i]);		// internal cleanup is done, which cannot happen until the device has been unregistered
			free_netdev(snull_devs[i]);				// returns the net_device structure to the kernel
			/*
			If a reference to that structure exists somewhere, it may continue to exist, 
			but your driver need not care about that. Once you have unregistered the interface, 
			the kernel no longer calls its methods. ie. after free_netdev we cannot make any further
			references to the device or our private area.
			*/
		}
	}
	return;
}

module_init(mysnull_init_module);
module_exit(mysnull_cleanup);
