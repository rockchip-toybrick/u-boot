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

#include <asm/arch/toybrick.h>
#include <optee_include/OpteeClientInterface.h>
#include <u-boot/sha256.h>

DECLARE_GLOBAL_DATA_PTR;

enum {
	PH = 0,	/* P: Priority, H: high, M: middle, L: low*/
	PM,
	PL,
};

static u32 bcb_recovery_msg;

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
	if (blk_dread(dev_desc, part.start + bcb_offset, cnt, bmsg) != cnt) {
		recovery = 0;
	} else {
		recovery = !strcmp(bmsg->command, "boot-recovery");
		if (!strcmp(bmsg->recovery, "recovery\n--rk_fwupdate\n"))
			bcb_recovery_msg = BCB_MSG_RECOVERY_RK_FWUPDATE;
		else if (!strcmp(bmsg->recovery, "recovery\n--factory_mode=whole") ||
			 !strcmp(bmsg->recovery, "recovery\n--factory_mode=small"))
			bcb_recovery_msg = BCB_MSG_RECOVERY_PCBA;
	}

	free(bmsg);
out:
	return recovery;
}

int get_bcb_recovery_msg(void)
{
	return bcb_recovery_msg;
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
	} else if (reg_boot_mode == BOOT_DFU) {
		printf("boot mode: dfu\n");
		boot_mode[PH] = BOOT_MODE_DFU;
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

static int load_SnMacAc_from_vendor(char *sn, char *mac, char *actcode)
{
	int ret;

	memset(sn, 0, TOYBRICK_SN_LEN + 1);
	memset(mac, 0, TOYBRICK_MAC_LEN + 1);
	memset(actcode, 0, TOYBRICK_ACTCODE_LEN + 1);

	ret = toybrick_get_sn(sn);
	if (ret <= 0) {
		printf("Load sn form vendor failed\n");
		return -EIO;
	}

	ret = toybrick_get_mac(mac);
	if (ret != TOYBRICK_MAC_LEN) {
		printf("Load mac form vendor failed\n");
		return -EIO;
	}

	ret = toybrick_get_actcode(actcode);
	if (ret != TOYBRICK_ACTCODE_LEN) {
		printf("Load actcode form vendor failed\n");
		return -EIO;
	}

	printf("Load SnMacAc from vendor: sn %s, mac %2.2x%2.2x%2.2x%2.2x%2.2x%2.2x\n",
			sn, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return 0;
}

static int save_SnMacAc_to_vendor(char *sn, char *mac, char *actcode)
{
	int ret;

	ret = toybrick_set_sn(sn);
	if (ret <= 0) {
		printf("Save sn to vendor failed\n");
		return -EIO;
	}

	ret = toybrick_set_mac(mac);
	if (ret != TOYBRICK_MAC_LEN) {
		printf("Save mac to vendor failed\n");
		return -EIO;
	}

	ret = toybrick_set_actcode(actcode);
	if (ret != TOYBRICK_ACTCODE_LEN) {
		printf("Save actcode to vendor failed\n");
		return -EIO;
	}

	return 0;
}

static int load_SnMacAc_from_rpmb(char *sn, char *mac, char *actcode)
{
	int ret;
	sha256_context ctx;
	uint8_t digest[SHA256_SUM_LEN + 1] = {0};
	uint8_t hash_pre[SHA256_SUM_LEN + 1] = {0};
	uint8_t data_sha256[TOYBRICK_SHA_LEN + 1]={0};

	memset(sn, 0, TOYBRICK_SN_LEN + 1);
	memset(mac, 0, TOYBRICK_MAC_LEN + 1);
	memset(actcode, 0, TOYBRICK_ACTCODE_LEN + 1);
	ret = trusty_read_toybrick_SnMacAc(data_sha256, TOYBRICK_SHA_LEN);
	if (ret != 0) {
		printf("Load SnMacAc from rpmb failed\n");
		return -EIO;
	}
	memcpy(hash_pre, data_sha256, SHA256_SUM_LEN);
	sha256_starts(&ctx);
	sha256_update(&ctx,(const uint8_t *)(data_sha256 + SHA256_SUM_LEN), TOYBRICK_DATA_LEN);
	sha256_finish(&ctx, digest);
	if (memcmp(digest, hash_pre, SHA256_SUM_LEN) != 0) {
		printf("SnMacAc from rpmb is invalid\n");
		return -EINVAL;
	}
	memcpy(sn, data_sha256 + SHA256_SUM_LEN, TOYBRICK_SN_LEN);
	memcpy(mac, data_sha256 + SHA256_SUM_LEN + TOYBRICK_SN_LEN, TOYBRICK_MAC_LEN);
	memcpy(actcode, data_sha256 + SHA256_SUM_LEN + TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN, TOYBRICK_ACTCODE_LEN);

	if (strlen(sn) == 0) {
		printf("SnMacAc from rpmb is empty\n");
		return -EINVAL;
	}

	printf("Load SnMacAc from rpmb: sn %s, mac %2.2x%2.2x%2.2x%2.2x%2.2x%2.2x\n",
			sn, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return 0;
}

static int save_SnMacAc_to_rpmb(char *sn, char *mac, char *actcode)
{
	int ret;
	sha256_context ctx;
	uint8_t digest[SHA256_SUM_LEN + 1] = {0};
	uint8_t data[TOYBRICK_DATA_LEN + 1]={0};
	uint8_t data_sha256[TOYBRICK_SHA_LEN + 1]={0};

	memset(&data, 0, sizeof(data));
	memset(&data_sha256, 0, sizeof(data_sha256));
	memcpy(data, sn, TOYBRICK_SN_LEN);
	memcpy(data + TOYBRICK_SN_LEN, mac, TOYBRICK_MAC_LEN);
	memcpy(data + TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN, actcode, TOYBRICK_ACTCODE_LEN);

	sha256_starts(&ctx);
	sha256_update(&ctx,(const uint8_t *)data, TOYBRICK_DATA_LEN);
	sha256_finish(&ctx, digest);
	memcpy(data_sha256, digest, SHA256_SUM_LEN);
	memcpy(data_sha256 + SHA256_SUM_LEN, data, TOYBRICK_DATA_LEN);
	
	ret = trusty_write_toybrick_SnMacAc(data_sha256, TOYBRICK_SHA_LEN);
	if (ret != 0) {
		printf("Save SnMacAc to rpmb failed\n");
		return -EIO;
	}

	return 0;
}

static int toybrick_check_SnMacAc(void)
{
	int ret = 0;
	int ret_vendor, ret_rpmb;
	char vendor_sn[TOYBRICK_SN_LEN + 1];
	char vendor_mac[TOYBRICK_MAC_LEN + 1];
	char vendor_actcode[TOYBRICK_ACTCODE_LEN + 1];
	char rpmb_sn[TOYBRICK_SN_LEN + 1];
	char rpmb_mac[TOYBRICK_MAC_LEN + 1];
	char rpmb_actcode[TOYBRICK_ACTCODE_LEN + 1];

	ret_vendor = load_SnMacAc_from_vendor(vendor_sn, vendor_mac, vendor_actcode);
	ret_rpmb = load_SnMacAc_from_rpmb(rpmb_sn, rpmb_mac, rpmb_actcode);

	if (ret_vendor < 0 && ret_rpmb < 0) {
		printf("No SnMacAc found in vendor and rpmb, goto loader ...\n");
		run_command_list("rockusb 0 ${devtype} ${devnum}", -1, 0);
		//set_back_to_bootrom_dnl_flag();
		do_reset(NULL, 0, 0, NULL);
	} else if (ret_vendor < 0) {
		printf("No SnMacAc found in vendor, load from rpmb and save to vendor\n");
		ret = save_SnMacAc_to_vendor(rpmb_sn, rpmb_mac, rpmb_actcode);
		do_reset(NULL, 0, 0, NULL);
	} else if (ret_rpmb < 0) {
		printf("No SnMacAc found in rpmb, load from vendor and save to rpmb\n");
		ret = save_SnMacAc_to_rpmb(vendor_sn, vendor_mac, vendor_actcode);
	} else if (memcmp(vendor_sn, rpmb_sn, TOYBRICK_SN_LEN) != 0){
		printf("Warn: SN(%s %s) form vendor and rpmb is different!\n",
				vendor_sn, rpmb_sn);
		ret = save_SnMacAc_to_vendor(rpmb_sn, rpmb_mac, rpmb_actcode);
		do_reset(NULL, 0, 0, NULL);
	} else if (memcmp(vendor_mac, rpmb_mac, TOYBRICK_MAC_LEN) != 0){
		printf("Warn: MAC form vendor and rpmb is different!\n");
		ret = save_SnMacAc_to_vendor(rpmb_sn, rpmb_mac, rpmb_actcode);
		do_reset(NULL, 0, 0, NULL);
	} else if (memcmp(vendor_actcode, rpmb_actcode, TOYBRICK_ACTCODE_LEN) != 0){
		printf("Warn: Actcode form vendor and rpmb is different!\n");
		ret = save_SnMacAc_to_vendor(rpmb_sn, rpmb_mac, rpmb_actcode);
		do_reset(NULL, 0, 0, NULL);
	} else {
		printf("Toybrick check SnMacAc OK, sn %s\n", vendor_sn);
		ret = 0;
	}

	return ret;
}

int setup_boot_mode(void)
{
	char env_preboot[256] = {0};
#ifndef CONFIG_ROCKCHIP_RK3288
	toybrick_check_SnMacAc();
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
#if defined(CONFIG_CMD_DFU)
	case BOOT_MODE_DFU:
		printf("enter DFU!\n");
		env_set("preboot", "setenv preboot; dfu 0 ${devtype} ${devnum}; rbrom");
		break;
#endif
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
