#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa8c16cf3, "module_layout" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xf432dd3d, "__init_waitqueue_head" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0x6a517590, "device_create" },
	{ 0x8037428e, "__class_create" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0xc4556ebd, "cdev_add" },
	{ 0x1606bd6d, "cdev_init" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x940df3fb, "class_destroy" },
	{ 0x152aeb08, "device_destroy" },
	{ 0x1d26dbf2, "cdev_del" },
	{ 0xcf21d241, "__wake_up" },
	{ 0x4f6b400b, "_copy_from_user" },
	{ 0x69acdf38, "memcpy" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0x4f8b5ddb, "_copy_to_user" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xfb578fc5, "memset" },
	{ 0xfa66f77c, "finish_wait" },
	{ 0x5c8b5ce8, "prepare_to_wait" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x37a0cba, "kfree" },
	{ 0x783c7933, "kmem_cache_alloc_trace" },
	{ 0x352091e6, "kmalloc_caches" },
	{ 0x71e3cecb, "up" },
	{ 0xf22449ae, "down_interruptible" },
	{ 0x571ab46f, "current_task" },
	{ 0x27e1a049, "printk" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "6941609A9A8E28E59A206CA");
