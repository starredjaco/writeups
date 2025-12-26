#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/unistd.h>
#include <linux/slab.h>

#define sb_dev_NAME "switchboard"
#define CLASS_NAME "switchboard"
#define BUF_SIZE 32
#define RST 0x10
#define N_SET 0x20
#define OBJ_SELECT 0x30
#define OBJ_NEW 0x40
#define SETTINGS 0x50

MODULE_AUTHOR("elbee");
MODULE_DESCRIPTION("switchboard");
MODULE_LICENSE("mine");

static struct miscdevice sb_dev;

typedef struct devices {
    struct switch_device* device;
    struct devices* next, *prev;
} devices;

struct switch_device {
    char *buf;
    void *head, *tail, *seek;
    int len;
    uint8_t inuse;
    uint8_t freed;
    unsigned long t_settings;
};

static devices* head;
int selected;

static struct switch_device* get(int index){
    devices * node = head;
    int i;
    if(index < 0 || node == 0)
        return 0;
    i = 0;
    while(1){
        if(node->next == 0){
            break;
        }
        if(i == index){
            break;
        }
        node = node->next;
        i++;
    }
    if(i != index){
        return 0;
    }
    return node->device;
}

static ssize_t add(struct switch_device* dev){
    devices * node = head;
    devices * newdev = kzalloc(sizeof(devices), GFP_KERNEL_ACCOUNT);
    if(!newdev)
        return -ENOMEM;
    newdev->device = dev;
    newdev->next = 0;
    newdev->prev = 0;
    if(node == 0){
        head = newdev;
        return 0;
    }
    while(1){
        if(node->next == 0){
            node->next = newdev;
            node->next->prev = node;
            break;
        }
        node->next->prev = node;
        node = node->next;
    }
    return 0;
}

static unsigned long length(struct switch_device* dev){
    if((dev->len) > BUF_SIZE)
        return BUF_SIZE-1;
    return dev->len;
}

static ssize_t rx_handle(struct file *filp, const char __user *buffer, size_t len, loff_t *off){
    struct switch_device *dev = get(selected);
    unsigned long ret;
    if(!dev)
        return -1;
    if(dev->inuse == 0){
        printk(KERN_ALERT "[switchboard] freeing\n");
        if(dev->freed == 0)
            kfree(dev->buf);
        dev->buf = kzalloc(BUF_SIZE, GFP_KERNEL_ACCOUNT);
        dev->tail = dev->buf;
        dev->head = dev->buf;
        dev->seek = dev->buf;
        dev->len = BUF_SIZE-1;
        dev->inuse = 1;
        dev->freed = 0;
    }
    ret = length(dev);
    if(len < ret)
        ret = len;
    if(copy_from_user(dev->head, buffer, ret) != 0)
        return -2;
    dev->tail = (dev->head)+BUF_SIZE-1;
    return ret;
}

static ssize_t tx_handle(struct file *filp, char __user *buffer, size_t len, loff_t *off) {
    struct switch_device *dev = get(selected);
    ssize_t i;
    if(!dev)
        return -1;
    if(dev->inuse == 0){
        printk(KERN_ALERT "[switchboard] freeing\n");
        if(dev->freed == 0)
            kfree(dev->buf);
        dev->buf = kzalloc(BUF_SIZE, GFP_KERNEL_ACCOUNT);
        dev->tail = dev->buf;
        dev->head = dev->buf;
        dev->seek = dev->buf;
        dev->len = BUF_SIZE-1;
        dev->inuse = 1;
        dev->freed = 0;
    }
    if(dev->head == dev->tail)
        return -3;
    i = 0;
    for(i = 0; i < len; i++){
        while(copy_to_user(buffer+i, dev->seek, 1) > 0){
            if(dev->t_settings & 0x1)
                break;
            printk(KERN_ALERT "[switchboard] retransmitting");
            cond_resched();
        }
        dev->seek++;
        if((dev->seek) >= (dev->tail))
            dev->seek = dev->head;
    }
    dev->seek = dev->head;
    return i;
}

static long buf_reset(unsigned long arg){
    struct switch_device *dev = get(selected);
    if(!dev)
        return -1;
    if(dev->inuse == 0){
        kfree(dev->buf);
        dev->freed = 1;
        return 1;
    }
    dev->seek = dev->head;
    dev->inuse = 0;
    return 0;
}

static long n_set(int arg){
    struct switch_device *dev = get(selected);
    if(!dev)
        return -1;
    dev->len = arg;
    return dev->len;
}

static long obj_select(unsigned long arg){
    struct switch_device *dev = get(arg);
    if(!dev)
        return -1;
    selected = arg;
    return 0;
}

static long obj_new(unsigned long arg){    
    struct switch_device *dev = kzalloc(sizeof(struct switch_device), GFP_KERNEL_ACCOUNT);
    if(!dev)
        return -ENOMEM;
    dev->buf = kzalloc(BUF_SIZE, GFP_KERNEL_ACCOUNT);
    if(!dev->buf){
        kfree(dev);
        return -ENOMEM;
    }
    dev->head = dev->buf;
    dev->tail = dev->buf;
    dev->seek = dev->buf;
    dev->len = 0;
    dev->inuse = 1;
    dev->freed = 0;
    dev->t_settings = 0;
    return (long)add(dev);
}

static long settings(unsigned long arg){
    struct switch_device *dev = get(selected);
    if(!dev)
        return -1;
    dev->t_settings = arg;
    return (long)dev->t_settings;
}

static long uart_manage(struct file *flip, unsigned int cmd, unsigned long arg){
    int result;
    switch(cmd){
        case RST:
            result = buf_reset(arg);
            break;
        case N_SET:
            result = n_set(arg);
            break;
        case OBJ_SELECT:
            result = obj_select(arg);
            break;
        case OBJ_NEW:
            result = obj_new(arg);
            break;
        case SETTINGS:
            result = settings(arg);
            break;
        default:
            result = -1;
    }
    return result;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = tx_handle, // kernel -> user
    .write = rx_handle, // user -> kernel
    .unlocked_ioctl = uart_manage, // ioctl
};

static int __init construct(void) {
    sb_dev.minor = MISC_DYNAMIC_MINOR;
    sb_dev.name = "switchboard";
    sb_dev.fops = &fops;
    if(misc_register(&sb_dev))
    {
        return -1;
    }
    printk(KERN_INFO "[switchboard] hello!\n");
    head = 0;
    selected = -1;
    return 0;
}

static void __exit destruct(void) {    
    devices * node = head;
    if(node != 0){
        while(1){
            devices * fd = node->next;
            if(node->device->buf != 0)
                kfree(node->device->buf);
            kfree(node->device);
            kfree(node);
            if(!fd)
                break;
            node = fd;
        }
    }
    misc_deregister(&sb_dev);
    printk(KERN_INFO "[switchboard] goodbye\n");
}

module_init(construct);
module_exit(destruct);
