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

// #include <linux/in6.h>
#include <asm/checksum.h>

MODULE_AUTHOR("Nitin Sao");
MODULE_LICENSE("Dual BSD/GPL");	

static int timeout = SNULL_TIMEOUT;			// In snull.h, SNULL_TIMEOUT = 5 (in jiffies)

/*
 * The devices
 */
// struct net_device *snull_devs[2];
struct net_device *snull_devs[1];

int pool_size = 8;						// pool size for packets per dev
module_param(pool_size, int, 0);

static void (*snull_interrupt)(int, void *, struct pt_regs *);

struct snull_packet {
	struct snull_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];			// ETH_DATA_LEN = 1500 octets (MTU)
};

struct snull_priv {
	struct net_device *dev;				// Was not in ldd3
	struct napi_struct napi;			// Was not in ldd3
	struct net_device_stats stats;		// the standard place to hold interface statistics
	int status;
	struct snull_packet *ppool;			// Packet pool, List of outgoing packets
	struct snull_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
};

static void snull_rx_ints(struct net_device *dev, int enable)
{
	struct snull_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
	printk(KERN_ALERT "%s called", __FUNCTION__);
}

void snull_setup_pool(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	int i;
	struct snull_packet *pkt;

	printk(KERN_ALERT "%s called", __FUNCTION__);


	// char msg_on_pkt[] = "Hello I am here!\n";

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
		// memcpy(pkt->dev, msg_on_pkt, sizeof(msg_on_pkt));
	}
	printk (KERN_ALERT "packet pool memory allocation done\n");
}

int snull_open(struct net_device *dev)		// is called whenever ifconfig activates it.
{
	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);		// dev_addr : Interface address info used in eth_type_trans()

	netif_start_queue(dev);			// Allow upper layers to call the device hard_start_xmit routine.
	return 0;
}

int snull_release(struct net_device *dev)		// should reverse operations performed at open time.
{
	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	netif_stop_queue(dev); /* can't transmit any more */
	return 0;
}

struct snull_packet *snull_get_tx_buffer(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct snull_packet *pkt;
    
	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

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
{
	unsigned long flags;
	struct snull_priv *priv = netdev_priv(dev);

	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}

void snull_rx(struct net_device *dev, struct snull_packet *pkt)
{
	struct sk_buff *skb;
	struct snull_priv *priv = netdev_priv(dev);

	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	skb = dev_alloc_skb(pkt->datalen + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb, 2); /* align IP on 16B boundary */  
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
	
	{
		// Printing pkt->data
		
		char *my_data = pkt -> data;
		int jump = sizeof(struct tcphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr);
		if(jump < pkt->datalen)
		{
			printk(KERN_ALERT "Actual: ");
			my_data = (char *)(pkt->data + jump);
		}
		
		printk(KERN_ALERT "%s: Rx data : %s, len: %d, jump: %d", __FUNCTION__, my_data, pkt->datalen, jump);
	}

	skb->dev = dev;									// Its new skb, so initializing it

	skb->protocol = eth_type_trans(skb, dev);		// determine the packet's protocol ID (/net/ethernet/eth.c)
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
	priv->stats.rx_packets++;					// Maintain the stats
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);								// post (skb) buffer to the network code (/net/core/dev.c)

  out:
	return;
}

void snull_release_buffer(struct snull_packet *pkt)
{
	unsigned long flags;
	struct snull_priv *priv = netdev_priv(pkt->dev);
	
	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;				// Add pkt in the front of the priv->ppool, so it would be considered in next loop
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);

	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}

static void snull_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)		// irq: 0, regs: NULL
{
	int statusword;
	struct snull_priv *priv;
	struct snull_packet *pkt = NULL;

	struct net_device *dev = (struct net_device *)dev_id;

	int dev_num = 0;

	printk(KERN_ALERT "%s called by sn%d", __FUNCTION__, dev_num);


	if (!dev)
		return;


	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	statusword = priv->status;
	priv->status = 0;
	if (statusword & SNULL_RX_INTR) {			// See snull.h, SNULL_RX_INTR = 0x0001, ie. if statusword is odd
		pkt = priv->rx_queue;
		if (pkt) {
			priv->rx_queue = pkt->next;
			snull_rx(dev, pkt);				// Recieve pkt at dev (generally dest), not upto the socket, but pkt will be wrapped by sk_buff sent towards upper layers.
			printk(KERN_ALERT "Pkt received");
		}
	}
	if (statusword & SNULL_TX_INTR) {			// See snull.h, SNULL_TX_INTR = 0x0002, ie. if statusword is even
		priv->stats.tx_packets++;				// Maintain the stats
		priv->stats.tx_bytes += priv->tx_packetlen;
		printk(KERN_ALERT "Pkt transmitted, stats updated");
		dev_kfree_skb(priv->skb);
	}

	spin_unlock(&priv->lock);
	if (pkt) snull_release_buffer(pkt); /* Do this outside the lock! */
	return;
}


static void snull_hw_tx(char *buf, int len, struct net_device *dev)
{
	struct iphdr *ih;				// IP header
	struct net_device *dest;
	struct snull_priv *priv;
	u32 *saddr, *daddr;				// IP addresses
	__be32	temp_addr;
	struct snull_packet *tx_buffer;
    
	printk(KERN_ALERT "%s called by sn0, buf : , len : %i", __FUNCTION__, len);

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

	printk(KERN_ALERT "Changing IPs of src & dest\n");
	printk(KERN_ALERT "src : %d.%d.%d.%d", ((u8 *)saddr)[0], ((u8 *)saddr)[1], ((u8 *)saddr)[2], ((u8 *)saddr)[3]);
	printk(KERN_ALERT "dest : %d.%d.%d.%d", ((u8 *)daddr)[0], ((u8 *)daddr)[1], ((u8 *)daddr)[2], ((u8 *)daddr)[3]);
	// ((u8 *)saddr)[2] ^= 1; /* change the third octet (class C) of Source Addr*/
	// ((u8 *)daddr)[2] ^= 1; /* change the third octet (class C) of Dest Addr*/
	// Swapping src & dest
	temp_addr = ih->saddr;
	ih->saddr = ih->daddr;
	ih->daddr = temp_addr;
	printk(KERN_ALERT "new src : %d.%d.%d.%d", ((u8 *)saddr)[0], ((u8 *)saddr)[1], ((u8 *)saddr)[2], ((u8 *)saddr)[3]);
	printk(KERN_ALERT "new dest : %d.%d.%d.%d", ((u8 *)daddr)[0], ((u8 *)daddr)[1], ((u8 *)daddr)[2], ((u8 *)daddr)[3]);
	

	ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);		// Compute the IPv4 header checksum efficiently. <__sum16 ip_fast_csum(const void *iph, unsigned int ihl)>


	// dest = snull_devs[dev == snull_devs[0] ? 1 : 0];	// If dev(src) is sn0, then dest will be sn1
// ====================
	dest = dev;										// We want packets to be received at same interface
	priv = netdev_priv(dest);							// Get private data of dest
	tx_buffer = snull_get_tx_buffer(dev);				// Get the packet (ppool) pointer(to be sent) from private data using dev
	tx_buffer->datalen = len;							// feed the packet of dev (ie. src)
	memcpy(tx_buffer->data, buf, len);					// feed the packet with actual data (buf)
	snull_enqueue_buf(dest, tx_buffer);					// enqueue tx_buffer in the front of list of incoming pkt of dest. 

	if (priv->rx_int_enabled) {
		// printk(KERN_ALERT "Receive Interrupt Enabled in function %s by dest :sn0", __FUNCTION__);
		priv->status |= SNULL_RX_INTR;				// See snull.h, SNULL_RX_INTR = 0x0001
		snull_interrupt(0, dest, NULL);			// snull_regular_interrupt() will be called, as we are not using napi.
	}

	priv = netdev_priv(dev);						// Get private data of src, now work with src
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= SNULL_TX_INTR;					// SNULL_TX_INTR = 0x0002
	snull_interrupt(0, dev, NULL);			// snull_regular_interrupt() will be called, as we are not using napi.
}

int snull_tx(struct sk_buff *skb, struct net_device *dev)		// initiates the transmission of a packet
{
	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct snull_priv *priv = netdev_priv(dev);
	
	data = skb->data;		// Data head pointer (unsigned char *data;)
	len = skb->len;			// Length of actual data (unsigned int len;)
	
	/*
	{
		char *my_data = data;
		int jump = sizeof(struct tcphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr);
		if(jump < len)
		{
			my_data = (char *)(data + jump);
			memcpy(my_data, "Hello World\n", len - jump);
		}
		
		printk(KERN_ALERT "%s: Tx data : %s, len: %d, jump: %d", __FUNCTION__, my_data, len, jump);
	}
	*/
	printk(KERN_ALERT "%s called", __FUNCTION__);

	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}

	priv->skb = skb;

	snull_hw_tx(data, len, dev);		// data: Actual data to be sent, len : Max length of data, dev : net_device as passed to it.


	return 0; /* Our simple device can not fail */
}

void snull_tx_timeout (struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);

	printk(KERN_ALERT "%s called", __FUNCTION__);

	priv->status = SNULL_TX_INTR;		// status changed to 0x0002
	snull_interrupt(0, dev, NULL);		// snull_regular_interrupt() will be called, as we are not using napi.
	priv->stats.tx_errors++;			// make an entry in stats (statistics)
	netif_wake_queue(dev);
	return;
}

struct net_device_stats *snull_stats(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

int snull_config(struct net_device *dev, struct ifmap *map)			// ifmap: Device mapping structure.
{
	printk(KERN_ALERT "%s called", __FUNCTION__);

	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "snull: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	if (map->irq != dev->irq) {
		dev->irq = map->irq;
	}

	return 0;
}

/*
 * Ioctl commands 
 */
int snull_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	PDEBUG("ioctl\n");
	return 0;
}


static const struct net_device_ops snull_netdev_ops = {
	.ndo_open		= snull_open,
	.ndo_stop		= snull_release,
	.ndo_start_xmit		= snull_tx,					// initiates the transmission of a packet.
	.ndo_tx_timeout		= snull_tx_timeout,			// called by the networking code when a packet transmission fails to complete within a reasonable period
	.ndo_get_stats		= snull_stats,				// update a net_device_stats structure (dev->stats) and return a pointer to it. We are doing just a shortcut.
	.ndo_set_config		= snull_config,				// entry point for configuring the driver. Drivers for modern "hardware" normally do not need to implement this method.

	.ndo_do_ioctl		= snull_ioctl,
};

int snull_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);	// creating space for ether_header

	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	eth->h_proto = htons(type);				// converts the unsigned short integer 'hostshort' from host byte order to network byte order.
	
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */		// Change the last bit of dest addr

	return (dev->hard_header_len);		// Return Maximum hardware header length.
}


static const struct header_ops snull_header_ops = {			// To control snull_header (not exactly..)
	.create 	= snull_header,			// called before ndo_start_xmit in snull_netdev_ops
	.cache 		= NULL,
};

void snull_init(struct net_device *dev)
{
	struct snull_priv *priv;

	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct snull_priv));
	spin_lock_init(&priv->lock);
	priv->dev = dev;				// Set the dev field, so we would be able to get dev through priv
	// snull_rx_ints(dev, 1);  	/* enable receive interrupts */		// from ldd3

	ether_setup(dev); /* assign some of the fields */

	dev->watchdog_timeo = timeout;
	dev->flags 				|= IFF_NOARP;		//IFF_NOARP : specifies that the interface cannot use the ARP.
	dev->features        	|= NETIF_F_HW_CSUM;	// hardware does checksumming itself
	dev->netdev_ops = &snull_netdev_ops;		// Now above function initializations are done through this
	dev->header_ops = &snull_header_ops;		// Includes snull_header creation

	snull_rx_ints(dev, 1);		/* enable receive interrupts */
	snull_setup_pool(dev);		// Creating pool_size (8) packets for packet pool of dev
}

void mysnull_cleanup(void);



int mysnull_init_module(void)
{
	int result, i = 0, ret = -ENOMEM;

	printk(KERN_ALERT "%s called###", __FUNCTION__);

	snull_interrupt = snull_regular_interrupt;

	snull_devs[0] = alloc_netdev(sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_init);
	// snull_devs[1] = alloc_netdev(sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_init);
	if (snull_devs[0] == NULL)// || snull_devs[1] == NULL)
		goto out;

	ret = -ENODEV;
	// for (i = 0; i < 2; i++)
		if ((result = register_netdev(snull_devs[i])))
			printk("snull: error %i registering device \"%s\"\n", result, snull_devs[i]->name);
		else
			ret = 0;
	printk(KERN_ALERT "register_netdev() Done.");
   out:
	if (ret) 
		mysnull_cleanup();
	return 0;
}

void snull_teardown_pool(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;
    
	printk(KERN_ALERT "%s called by sn0", __FUNCTION__);

	while ((pkt = priv->ppool)) {		// Free all the packets from ppool (packet pool) of dev
		priv->ppool = pkt->next;
		kfree (pkt);
	}
}    

void mysnull_cleanup(void)
{
	int i = 0;
	printk(KERN_ALERT "%s called###", __FUNCTION__);

	// for (i = 0; i < 2; i++) {
		if (snull_devs[i]) {
			unregister_netdev(snull_devs[i]);		// removes the interface from the system
			snull_teardown_pool(snull_devs[i]);		// internal cleanup is done, which cannot happen until the device has been unregistered
			free_netdev(snull_devs[i]);				// returns the net_device structure to the kernel
		}
	// }
	return;
}

module_init(mysnull_init_module);
module_exit(mysnull_cleanup);
