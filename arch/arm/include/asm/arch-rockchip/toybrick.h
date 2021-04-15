/*
 * (C) Copyright 2021-2022 Fuzhou Rockchip Electronics Co., Ltd
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef __TOYBRICK_BOARD__
#define __TOYBRICK_BOARD__

#include <linux/string.h>
#include <asm/arch/vendor.h>
#include <i2c.h>
#include <u-boot/sha256.h>

#define TOYBRICK_SN_ID		VENDOR_SN_ID
#define TOYBRICK_MAC_ID		VENDOR_LAN_MAC_ID
#define TOYBRICK_ACTCODE_ID	0xa0

#define TOYBRICK_SN_LEN		64
#define TOYBRICK_MAC_LEN	6
#define TOYBRICK_ACTCODE_LEN	264

#define TOYBRICK_DATA_LEN	(TOYBRICK_SN_LEN + TOYBRICK_MAC_LEN + TOYBRICK_ACTCODE_LEN)
#define TOYBRICK_SHA_LEN	(TOYBRICK_DATA_LEN + SHA256_SUM_LEN)

#define TOYBRICK_FLAG_LEN	7

static inline int toybrick_get_sn(char *sn)
{
	return vendor_storage_read(TOYBRICK_SN_ID, sn, TOYBRICK_SN_LEN);
}

static inline int toybrick_set_sn(char *sn)
{
	return vendor_storage_write(TOYBRICK_SN_ID, sn, TOYBRICK_SN_LEN);
}

static inline int toybrick_get_mac(char *mac)
{
	return vendor_storage_read(TOYBRICK_MAC_ID, mac, TOYBRICK_MAC_LEN);
}

static inline int toybrick_set_mac(char *mac)
{
	return vendor_storage_write(TOYBRICK_MAC_ID, mac, TOYBRICK_MAC_LEN);
}

static inline int toybrick_get_actcode(char *actcode)
{
	return vendor_storage_read(TOYBRICK_ACTCODE_ID, actcode, TOYBRICK_ACTCODE_LEN);
}

static inline int toybrick_set_actcode(char *actcode)
{
	return vendor_storage_write(TOYBRICK_ACTCODE_ID, actcode, TOYBRICK_ACTCODE_LEN);
}

static inline int toybrick_get_flag(char *flag, int *index)
{
	struct udevice *dev;
	u8 buf[8];
	char sn[TOYBRICK_SN_LEN + 1];
	int ret = toybrick_get_sn(sn);

	if (ret != TOYBRICK_SN_LEN)
		return -EINVAL;
	
	*index = -1;

	if ((strncmp(sn, "TX03310", TOYBRICK_FLAG_LEN) == 0) ||
			(strncmp(sn, "TXs3310", TOYBRICK_FLAG_LEN) == 0)) {
		if ((i2c_get_chip_for_busnum(1, 0x1c, 1, &dev) == 0) &&
				(dm_i2c_read(dev, 0, buf, 1) == 0))
			*index = 1;
		else
			*index = 0;
	}

	if ((strncmp(sn, "TX03568", TOYBRICK_FLAG_LEN) == 0) ||
			(strncmp(sn, "TXs3568", TOYBRICK_FLAG_LEN) == 0)) {
		*index = 0;
	}

	strncpy(flag, sn, TOYBRICK_FLAG_LEN);
	return 0;
}

#endif /* _TOYBRICK_BOARD_ */
