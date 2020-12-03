/*
 * (C) Copyright 2016 Rockchip Electronics Co., Ltd
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <boot_rkimg.h>
#include <malloc.h>
#include <asm/io.h>
#include <asm/arch/boot_mode.h>

#include <asm/arch/vendor.h>
#include <optee_include/OpteeClientInterface.h>
#include <u-boot/sha256.h>
#define TOYBRICK_SN_LEN 64
#define TOYBRICK_MAC_LEN 6
#define TOYBRICK_AC_LEN 264
#define TOYBRICK_SN_ID         0x01
#define TOYBRICK_MAC_ID        0x03
#define TOYBRICK_ACT_ID        0xa0

DECLARE_GLOBAL_DATA_PTR;

enum {
	PH = 0,	/* P: Priority, H: high, M: middle, L: low*/
	PM,
	PL,
};

static int misc_require_recovery(u32 bcb_offset)
{
	struct bootloader_message *bmsg;
	struct blk_desc *dev_desc;
	disk_partition_t part;
	int cnt, recovery = 0;

	dev_desc = rockchip_get_bootdev();
	if (!dev_desc) {
		printf("dev_desc is NULL!\n");
		goto out;
	}

	if (part_get_info_by_name(dev_desc, PART_MISC, &part) < 0) {
		printf("No misc partition\n");
		goto out;
	}

	cnt = DIV_ROUND_UP(sizeof(struct bootloader_message), dev_desc->blksz);
	bmsg = memalign(ARCH_DMA_MINALIGN, cnt * dev_desc->blksz);
	if (blk_dread(dev_desc, part.start + bcb_offset, cnt, bmsg) != cnt)
		recovery = 0;
	else
		recovery = !strcmp(bmsg->command, "boot-recovery");

	free(bmsg);
out:
	return recovery;
}

/*
 * There are three ways to get reboot-mode:
 *
 * No1. Android BCB which is defined in misc.img (0KB or 16KB offset)
 * No2. CONFIG_ROCKCHIP_BOOT_MODE_REG that supports "reboot xxx" commands
 * No3. Env variable "reboot_mode" which is added by U-Boot
 *
 * Recovery mode from:
 *	- Android BCB in misc.img
 *	- "reboot recovery" command
 *	- recovery key pressed without usb attach
 */
int rockchip_get_boot_mode(void)
{
	static int boot_mode[] =		/* static */
		{ -EINVAL, -EINVAL, -EINVAL };
	static int bcb_offset = -EINVAL;	/* static */
	uint32_t reg_boot_mode;
	char *env_reboot_mode;
	int clear_boot_reg = 0;
#ifdef CONFIG_ANDROID_BOOT_IMAGE
	u32 offset = android_bcb_msg_sector_offset();
#else
	u32 offset = BCB_MESSAGE_BLK_OFFSET;
#endif

	/*
	 * Env variable "reboot_mode" which is added by U-Boot, reading ever time.
	 */
	env_reboot_mode = env_get("reboot_mode");
	if (env_reboot_mode) {
		if (!strcmp(env_reboot_mode, "recovery-key")) {
			printf("boot mode: recovery (key)\n");
			return BOOT_MODE_RECOVERY;
		} else if (!strcmp(env_reboot_mode, "recovery-usb")) {
			printf("boot mode: recovery (usb)\n");
			return BOOT_MODE_RECOVERY;
		} else if (!strcmp(env_reboot_mode, "recovery")) {
			printf("boot mode: recovery (env)\n");
			return BOOT_MODE_RECOVERY;
		} else if (!strcmp(env_reboot_mode, "fastboot")) {
			printf("boot mode: fastboot\n");
			return BOOT_MODE_BOOTLOADER;
		}
	}

	/*
	 * Android BCB special handle:
	 *    Once the Android BCB offset changed, reinitalize "boot_mode[PM]".
	 *
	 * Background:
	 *    1. there are two Android BCB at the 0KB(google) and 16KB(rk)
	 *       offset in misc.img
	 *    2. Android image: return 0KB offset if image version >= 10,
	 *	 otherwise 16KB
	 *    3. Not Android image: return 16KB offset, eg: FIT image.
	 *
	 * To handle the cases of 16KB and 0KB, we reinitial boot_mode[PM] once
	 * Android BCB is changed.
	 *
	 * PH and PL is from boot mode register and reading once.
	 * PM is from misc.img and should be updated if BCB offset is changed.
	 * Return the boot mode according to priority: PH > PM > PL.
	 */
	if (bcb_offset != offset) {
		boot_mode[PM] = -EINVAL;
		bcb_offset = offset;
	}

	/* directly return if there is already valid mode */
	if (boot_mode[PH] != -EINVAL)
		return boot_mode[PH];
	else if (boot_mode[PM] != -EINVAL)
		return boot_mode[PM];
	else if (boot_mode[PL] != -EINVAL)
		return boot_mode[PL];

	/*
	 * Boot mode priority
	 *
	 * Anyway, we should set download boot mode as the highest priority, so:
	 * reboot loader/bootloader/fastboot > misc partition "recovery" > reboot xxx.
	 */
	reg_boot_mode = readl((void *)CONFIG_ROCKCHIP_BOOT_MODE_REG);
	if (reg_boot_mode == BOOT_LOADER) {
		printf("boot mode: loader\n");
		boot_mode[PH] = BOOT_MODE_LOADER;
		clear_boot_reg = 1;
	} else if (reg_boot_mode == BOOT_FASTBOOT) {
		printf("boot mode: bootloader\n");
		boot_mode[PH] = BOOT_MODE_BOOTLOADER;
		clear_boot_reg = 1;
	} else if (misc_require_recovery(bcb_offset)) {
		printf("boot mode: recovery (misc)\n");
		boot_mode[PM] = BOOT_MODE_RECOVERY;
	} else {
		switch (reg_boot_mode) {
		case BOOT_NORMAL:
			printf("boot mode: normal\n");
			boot_mode[PL] = BOOT_MODE_NORMAL;
			clear_boot_reg = 1;
			break;
		case BOOT_RECOVERY:
			printf("boot mode: recovery (cmd)\n");
			boot_mode[PL] = BOOT_MODE_RECOVERY;
			clear_boot_reg = 1;
			break;
		case BOOT_UMS:
			printf("boot mode: ums\n");
			boot_mode[PL] = BOOT_MODE_UMS;
			clear_boot_reg = 1;
			break;
		case BOOT_CHARGING:
			printf("boot mode: charging\n");
			boot_mode[PL] = BOOT_MODE_CHARGING;
			clear_boot_reg = 1;
			break;
		case BOOT_PANIC:
			printf("boot mode: panic\n");
			boot_mode[PL] = BOOT_MODE_PANIC;
			break;
		case BOOT_WATCHDOG:
			printf("boot mode: watchdog\n");
			boot_mode[PL] = BOOT_MODE_WATCHDOG;
			break;
		default:
			printf("boot mode: None\n");
			boot_mode[PL] = BOOT_MODE_UNDEFINE;
		}
	}

	/*
	 * We don't clear boot mode reg when its value stands for the reboot
	 * reason or others(in the future), the kernel will need and clear it.
	 */
	if (clear_boot_reg)
		writel(BOOT_NORMAL, (void *)CONFIG_ROCKCHIP_BOOT_MODE_REG);

	if (boot_mode[PH] != -EINVAL)
		return boot_mode[PH];
	else if (boot_mode[PM] != -EINVAL)
		return boot_mode[PM];
	else
		return boot_mode[PL];
}

int toybrick_SnMacAc_check(void) {

	char vendor_sn[TOYBRICK_SN_LEN + 1]={0};
	char vendor_mac[TOYBRICK_MAC_LEN + 1]={0};
	char vendor_ac[TOYBRICK_AC_LEN + 1]={0};
	uint8_t sn_mac_ac[TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN+1]={0};
	uint8_t sn_mac_ac_sha256[TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN+SHA256_SUM_LEN+1]={0};
	uint8_t digest[SHA256_SUM_LEN+1] = {0};
	uint8_t hash_pre[SHA256_SUM_LEN+1] = {0};
	int ret_mac=-1,ret_sn=-1,ret_ac=-1,ret_sn_mac_ac=-1,ret=0;
	sha256_context ctx;
	ret_sn = vendor_storage_read(TOYBRICK_SN_ID,(void *)vendor_sn,TOYBRICK_SN_LEN);
	if (ret_sn <= 0) {
		printf("%s read sn id fail\n",__FUNCTION__);
	}

	ret_mac = vendor_storage_read(TOYBRICK_MAC_ID,//MAC
								(void *)vendor_mac,
								TOYBRICK_MAC_LEN);
	if (ret_mac !=TOYBRICK_MAC_LEN) {
		printf("%s read mac id fail\n",__FUNCTION__);
	}

	ret_ac = vendor_storage_read(TOYBRICK_ACT_ID,//AC
								(void *)vendor_ac,
								TOYBRICK_AC_LEN);
	if (ret_ac!=TOYBRICK_AC_LEN) {
		printf("%s read ac id fail\n",__FUNCTION__);
	}

	ret_sn_mac_ac=trusty_read_toybrick_SnMacAc(sn_mac_ac_sha256,
											 TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN+SHA256_SUM_LEN);
	if (ret_sn_mac_ac!=0) {
		printf("%s read sn_mac_ac fail\n",__FUNCTION__);
	}

	if (ret_sn > 0 && ret_mac==TOYBRICK_MAC_LEN && ret_sn_mac_ac!=0) {
		printf("Toybrick: backup SN to rpmb partition\n");
		memset(sn_mac_ac,0,TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN+1);
		memset(sn_mac_ac_sha256,0,TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN+SHA256_SUM_LEN+1);
		memcpy(sn_mac_ac,vendor_sn,TOYBRICK_SN_LEN);
		memcpy(sn_mac_ac+TOYBRICK_SN_LEN,vendor_mac,TOYBRICK_MAC_LEN);
		memcpy(sn_mac_ac+TOYBRICK_SN_LEN+TOYBRICK_MAC_LEN,vendor_ac,TOYBRICK_AC_LEN);

		sha256_starts(&ctx);
		sha256_update(&ctx,(const uint8_t *)sn_mac_ac,TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN);
		sha256_finish(&ctx, digest);
		memcpy(sn_mac_ac_sha256,digest,SHA256_SUM_LEN);
		memcpy(sn_mac_ac_sha256+SHA256_SUM_LEN,sn_mac_ac,TOYBRICK_SN_LEN+TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN);
		ret=trusty_write_toybrick_SnMacAc(sn_mac_ac_sha256,TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN+SHA256_SUM_LEN);
		if (ret!=0) {
			printf("%s trusty_write_toybrick_SnMacAc wrong!\n",__FUNCTION__);
			goto error;
		}
	} else if ((ret_sn <=0 || ret_mac!=TOYBRICK_MAC_LEN) && ret_sn_mac_ac==0) {
		printf("Toybrick: load sn from rpm partition to vendor partition\n");
		memcpy(hash_pre,sn_mac_ac_sha256,SHA256_SUM_LEN);
		sha256_starts(&ctx);
		sha256_update(&ctx,(const uint8_t *)sn_mac_ac_sha256+SHA256_SUM_LEN,TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN);
		sha256_finish(&ctx, digest);
		if (memcmp(digest, hash_pre, SHA256_SUM_LEN) != 0) {
			printf("%s get sn_mac_ac wrong!hash error!\n",__FUNCTION__);
			goto error;
		}

		memcpy(vendor_sn,sn_mac_ac_sha256+SHA256_SUM_LEN,TOYBRICK_SN_LEN);
		ret_sn=vendor_storage_write(TOYBRICK_ACT_ID, vendor_sn, TOYBRICK_SN_LEN);
		if (ret_sn <=0) {
			printf("%s write sn fail\n",__FUNCTION__);
			goto error;
		}

		memcpy(vendor_mac,sn_mac_ac_sha256+SHA256_SUM_LEN+TOYBRICK_SN_LEN,TOYBRICK_MAC_LEN);
		ret_mac=vendor_storage_write(TOYBRICK_MAC_ID, vendor_mac, TOYBRICK_MAC_LEN);
		if (ret_mac <0) {
			printf("%s write mac fail\n",__FUNCTION__);
			goto error;
		}

		memcpy(vendor_ac,sn_mac_ac_sha256+SHA256_SUM_LEN+TOYBRICK_SN_LEN+TOYBRICK_MAC_LEN,TOYBRICK_AC_LEN);
		ret_ac=vendor_storage_write(TOYBRICK_ACT_ID, vendor_ac, TOYBRICK_AC_LEN);
		if (ret_ac <0) {
			printf("%s write ac fail\n",__FUNCTION__);
			goto error;
		}
	} else  if ((ret_sn <=0 || ret_mac!=TOYBRICK_MAC_LEN ) && ret_sn_mac_ac!=0) {
		printf("Toybrick: warn: SN is null or it is NOT toybrick board,  goto loader!\n");
		run_command_list("rockusb 0 ${devtype} ${devnum}", -1, 0);
		//set_back_to_bootrom_dnl_flag();
		do_reset(NULL, 0, 0, NULL);
	} else {
		printf("Toybrick: SN(%s) check OK!\n", vendor_sn);
	}
	return 0;
error:
	printf("Toybrick: error: SN is null or it is NOT toybrick board,  goto loader!\n");
	run_command_list("rockusb 0 ${devtype} ${devnum}", -1, 0);
	//set_back_to_bootrom_dnl_flag();
	do_reset(NULL, 0, 0, NULL);
	return -1;
}

int setup_boot_mode(void)
{
	char env_preboot[256] = {0};
#ifndef CONFIG_ROCKCHIP_RK3288
	toybrick_SnMacAc_check();
#endif
	switch (rockchip_get_boot_mode()) {
	case BOOT_MODE_BOOTLOADER:
		printf("enter fastboot!\n");
#if defined(CONFIG_FASTBOOT_FLASH_MMC_DEV)
		snprintf(env_preboot, 256,
				"setenv preboot; mmc dev %x; fastboot usb 0; ",
				CONFIG_FASTBOOT_FLASH_MMC_DEV);
#elif defined(CONFIG_FASTBOOT_FLASH_NAND_DEV)
		snprintf(env_preboot, 256,
				"setenv preboot; fastboot usb 0; ");
#endif
		env_set("preboot", env_preboot);
		break;
	case BOOT_MODE_UMS:
		printf("enter UMS!\n");
		env_set("preboot", "setenv preboot; ums mmc 0");
		break;
	case BOOT_MODE_LOADER:
		printf("enter Rockusb!\n");
		env_set("preboot", "setenv preboot; rockusb 0 ${devtype} ${devnum}; rbrom");
		break;
	case BOOT_MODE_CHARGING:
		printf("enter charging!\n");
		env_set("preboot", "setenv preboot; charge");
		break;
	}

	return 0;
}
