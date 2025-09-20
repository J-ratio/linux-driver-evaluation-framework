/*
 * Sample Network Device Driver
 * 
 * A simplified network device driver that demonstrates network interface
 * registration and basic packet handling in the Linux kernel.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#define DRIVER_NAME "sample_net"
#define DRIVER_VERSION "1.0"

static struct net_device *sample_netdev;

/**
 * sample_net_open - Open network interface
 * @dev: network device
 * 
 * Called when the network interface is brought up.
 * 
 * Return: 0 on success
 */
static int sample_net_open(struct net_device *dev)
{
    printk(KERN_INFO "%s: Network interface opened\n", dev->name);
    netif_start_queue(dev);
    return 0;
}

/**
 * sample_net_stop - Stop network interface
 * @dev: network device
 * 
 * Called when the network interface is brought down.
 * 
 * Return: 0 on success
 */
static int sample_net_stop(struct net_device *dev)
{
    printk(KERN_INFO "%s: Network interface stopped\n", dev->name);
    netif_stop_queue(dev);
    return 0;
}

/**
 * sample_net_start_xmit - Transmit network packet
 * @skb: socket buffer containing packet data
 * @dev: network device
 * 
 * Called when a packet needs to be transmitted.
 * 
 * Return: NETDEV_TX_OK on success
 */
static netdev_tx_t sample_net_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph;
    
    printk(KERN_INFO "%s: Transmitting packet of %d bytes\n", dev->name, skb->len);
    
    /* Simple packet inspection */
    if (skb->protocol == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        printk(KERN_INFO "%s: IP packet from %pI4 to %pI4\n", 
               dev->name, &iph->saddr, &iph->daddr);
    }
    
    /* Update statistics */
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    
    /* Free the socket buffer */
    dev_kfree_skb(skb);
    
    return NETDEV_TX_OK;
}

/**
 * sample_net_get_stats - Get network statistics
 * @dev: network device
 * 
 * Return: pointer to network statistics structure
 */
static struct net_device_stats *sample_net_get_stats(struct net_device *dev)
{
    return &dev->stats;
}

/* Network device operations */
static const struct net_device_ops sample_netdev_ops = {
    .ndo_open = sample_net_open,
    .ndo_stop = sample_net_stop,
    .ndo_start_xmit = sample_net_start_xmit,
    .ndo_get_stats = sample_net_get_stats,
};

/**
 * sample_net_init - Initialize the network driver
 * 
 * Return: 0 on success, negative error code on failure
 */
static int __init sample_net_init(void)
{
    int ret;
    
    printk(KERN_INFO "Sample Network Driver: Initializing\n");
    
    /* Allocate network device */
    sample_netdev = alloc_netdev(0, "sample%d", NET_NAME_UNKNOWN, ether_setup);
    if (!sample_netdev) {
        printk(KERN_ERR "Sample Network Driver: Failed to allocate network device\n");
        return -ENOMEM;
    }
    
    /* Set up device operations */
    sample_netdev->netdev_ops = &sample_netdev_ops;
    
    /* Generate random MAC address */
    eth_hw_addr_random(sample_netdev);
    
    /* Register network device */
    ret = register_netdev(sample_netdev);
    if (ret) {
        printk(KERN_ERR "Sample Network Driver: Failed to register network device\n");
        free_netdev(sample_netdev);
        return ret;
    }
    
    printk(KERN_INFO "Sample Network Driver: Registered device %s with MAC %pM\n",
           sample_netdev->name, sample_netdev->dev_addr);
    
    return 0;
}

/**
 * sample_net_exit - Cleanup the network driver
 */
static void __exit sample_net_exit(void)
{
    printk(KERN_INFO "Sample Network Driver: Cleaning up\n");
    
    if (sample_netdev) {
        unregister_netdev(sample_netdev);
        free_netdev(sample_netdev);
    }
    
    printk(KERN_INFO "Sample Network Driver: Cleanup complete\n");
}

module_init(sample_net_init);
module_exit(sample_net_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("Sample network device driver for demonstration");
MODULE_VERSION(DRIVER_VERSION);
MODULE_ALIAS("sample_network_driver");