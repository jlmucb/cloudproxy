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
	{ 0x8ca1999d, "module_layout" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xf432dd3d, "__init_waitqueue_head" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0x28f46d49, "device_create" },
	{ 0x491f0a43, "__class_create" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0x16e02f27, "cdev_add" },
	{ 0xbb36c49f, "cdev_init" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0xec35ed81, "class_destroy" },
	{ 0x1c044cbc, "device_destroy" },
	{ 0xb4f02b76, "cdev_del" },
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
	{ 0xa2e429a9, "kmem_cache_alloc_trace" },
	{ 0xd83ea029, "kmalloc_caches" },
	{ 0x71e3cecb, "up" },
	{ 0xf22449ae, "down_interruptible" },
	{ 0x5310fe6d, "current_task" },
	{ 0x27e1a049, "printk" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "6941609A9A8E28E59A206CA");
