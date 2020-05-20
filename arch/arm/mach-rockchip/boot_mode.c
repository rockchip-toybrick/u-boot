/*
 * (C) Copyright 2016 Rockchip Electronics Co., Ltd
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <adc.h>
#include <asm/io.h>
#include <asm/arch/boot_mode.h>
#include <asm/arch/hotkey.h>
#include <asm/arch/param.h>
#include <cli.h>
#include <dm.h>
#include <fdtdec.h>
#include <boot_rkimg.h>
#include <stdlib.h>
#include <linux/usb/phy-rockchip-inno-usb2.h>
#include <key.h>
#ifdef CONFIG_DM_RAMDISK
#include <ramdisk.h>
#endif
#include <mmc.h>
#include <console.h>
#include <asm/arch/vendor.h>
#include <optee_include/OpteeClientInterface.h>
#include <u-boot/sha256.h>
#define TOYBRICK_SN_LEN 64
#define TOYBRICK_MAC_LEN 6
#define TOYBRICK_AC_LEN 264
#define TOYBRICK_SN_ID		0x01
#define TOYBRICK_MAC_ID	0x03
#define TOYBRICK_ACT_ID	0xa0
DECLARE_GLOBAL_DATA_PTR;

#if (CONFIG_ROCKCHIP_BOOT_MODE_REG == 0)

int setup_boot_mode(void)
{
	return 0;
}

#else

void set_back_to_bootrom_dnl_flag(void)
{
	writel(BOOT_BROM_DOWNLOAD, CONFIG_ROCKCHIP_BOOT_MODE_REG);
}

/*
 * detect download key status by adc, most rockchip
 * based boards use adc sample the download key status,
 * but there are also some use gpio. So it's better to
 * make this a weak function that can be override by
 * some special boards.
 */
#define KEY_DOWN_MIN_VAL	0
#define KEY_DOWN_MAX_VAL	30

__weak int rockchip_dnl_key_pressed(void)
{
	int keyval = false;

/*
 * This is a generic interface to read key
 */
#if defined(CONFIG_DM_KEY)
	keyval = key_read(KEY_VOLUMEUP);

	return key_is_pressed(keyval);

#elif defined(CONFIG_ADC)
	const void *blob = gd->fdt_blob;
	unsigned int val;
	int channel = 1;
	int node;
	int ret;
	u32 chns[2];

	node = fdt_node_offset_by_compatible(blob, 0, "adc-keys");
	if (node >= 0) {
	       if (!fdtdec_get_int_array(blob, node, "io-channels", chns, 2))
		       channel = chns[1];
	}

	ret = adc_channel_single_shot("saradc", channel, &val);
	if (ret) {
		printf("%s adc_channel_single_shot fail! ret=%d\n", __func__, ret);
		return false;
	}

	if ((val >= KEY_DOWN_MIN_VAL) && (val <= KEY_DOWN_MAX_VAL))
		return true;
	else
		return false;
#endif

	return keyval;
}

void boot_devtype_init(void)
{
	const char *devtype_num_set = "run rkimg_bootdev";
	char *devtype = NULL, *devnum = NULL;
	static int done = 0;
	int atags_en = 0;
	int ret;

	if (done)
		return;

	ret = param_parse_bootdev(&devtype, &devnum);
	if (!ret) {
		atags_en = 1;
		env_set("devtype", devtype);
		env_set("devnum", devnum);

#ifdef CONFIG_DM_MMC
		if (!strcmp("mmc", devtype))
			mmc_initialize(gd->bd);
#endif
		/*
		 * For example, the pre-loader do not have mtd device,
		 * and pass devtype is nand. Then U-Boot can not get
		 * dev_desc when use mtd driver to read firmware. So
		 * test the block dev is exist or not here.
		 *
		 * And the devtype & devnum maybe wrong sometimes, it
		 * is better to test first.
		 */
		if (blk_get_devnum_by_typename(devtype, atoi(devnum)))
			goto finish;
	}

	/* If not find valid bootdev by atags, scan all possible */
#ifdef CONFIG_DM_MMC
	mmc_initialize(gd->bd);
#endif
	ret = run_command_list(devtype_num_set, -1, 0);
	if (ret) {
		/* Set default dev type/num if command not valid */
		devtype = "mmc";
		devnum = "0";
		env_set("devtype", devtype);
		env_set("devnum", devnum);
	}

finish:
	done = 1;
	printf("Bootdev%s: %s %s\n", atags_en ? "(atags)" : "",
	       env_get("devtype"), env_get("devnum"));
}

void rockchip_dnl_mode_check(void)
{
	/* recovery key or "ctrl+d" */
	if (rockchip_dnl_key_pressed() ||
	    is_hotkey(HK_ROCKUSB_DNL)) {
		printf("download key pressed... ");
		if (rockchip_u2phy_vbus_detect() > 0) {
			printf("entering download mode...\n");
			/* If failed, we fall back to bootrom download mode */
			run_command_list("rockusb 0 ${devtype} ${devnum}", -1, 0);
			set_back_to_bootrom_dnl_flag();
			do_reset(NULL, 0, 0, NULL);
		} else {
#ifndef CONFIG_DUAL_SYSTEM
			printf("entering recovery mode!\n");
			env_set("reboot_mode", "recovery");
#endif
		}
	} else if (is_hotkey(HK_FASTBOOT)) {
		env_set("reboot_mode", "fastboot");
	}
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
		printf("%s write rpmb\n",__FUNCTION__);
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
		printf("%s write vendor\n",__FUNCTION__);
		memcpy(hash_pre,sn_mac_ac_sha256,SHA256_SUM_LEN);
		sha256_starts(&ctx);
		sha256_update(&ctx,(const uint8_t *)sn_mac_ac_sha256+SHA256_SUM_LEN,TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN+TOYBRICK_AC_LEN);
		sha256_finish(&ctx, digest);
		if (memcmp(digest, hash_pre, SHA256_SUM_LEN) != 0) {
			printf("%s get sn_mac_ac wrong!hash error!\n",__FUNCTION__);
			goto error;
		}

		memcpy(vendor_sn,sn_mac_ac_sha256+SHA256_SUM_LEN,TOYBRICK_SN_LEN);
		ret_sn=vendor_storage_write(TOYBRICK_SN_ID, vendor_sn, TOYBRICK_SN_LEN);
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
		printf("%s goto loader\n",__FUNCTION__);
		run_command_list("rockusb 0 ${devtype} ${devnum}", -1, 0);
		set_back_to_bootrom_dnl_flag();
		do_reset(NULL, 0, 0, NULL);
	} else {
		printf("%s other type\n",__FUNCTION__);
	}
	return 0;
error:
	run_command_list("rockusb 0 ${devtype} ${devnum}", -1, 0);
	set_back_to_bootrom_dnl_flag();
	do_reset(NULL, 0, 0, NULL);
	return -1;
}

int setup_boot_mode(void)
{
	int boot_mode = BOOT_MODE_NORMAL;
	char env_preboot[256] = {0};

	boot_devtype_init();
	rockchip_dnl_mode_check();
#ifndef CONFIG_ROCKCHIP_RK3288
	toybrick_SnMacAc_check();
#endif
#ifdef CONFIG_RKIMG_BOOTLOADER
	boot_mode = rockchip_get_boot_mode();
#endif
	switch (boot_mode) {
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
		env_set("preboot", "setenv preboot; rockusb 0 ${devtype} ${devnum}");
		break;
	case BOOT_MODE_CHARGING:
		printf("enter charging!\n");
		env_set("preboot", "setenv preboot; charge");
		break;
	}

	return 0;
}

#endif
