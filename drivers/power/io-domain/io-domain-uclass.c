/*
 * (C) Copyright 2008-2018 Rockchip Electronics
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <dm.h>

DECLARE_GLOBAL_DATA_PTR;

UCLASS_DRIVER(io_domain) = {
	.id		= UCLASS_IO_DOMAIN,
	.name		= "io_domain",
};
