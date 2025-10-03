/*
 * Copyright (c) 2025 Mark Johnston <markj@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

/* Needed to get the __GNUC_PREREQ__ macro. */
#if __has_include_next(<features.h>)
#include <features.h>
#endif

#include_next <stdckdint.h>
