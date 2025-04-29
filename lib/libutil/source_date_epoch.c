/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Klara, Inc.
 */

#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <libutil.h>
#include <limits.h>
#include <stdlib.h>

int
source_date_epoch(time_t *tp)
{
	intmax_t val;
	char *end, *env;

	env = getenv("SOURCE_DATE_EPOCH");
	if (env == NULL)
		return (1);

	errno = 0;
	val = strtoimax(env, &end, 10);
	if (errno != 0)
		return (-1);
	if (end == env || *end != '\0') {
		errno = EINVAL;
		return (-1);
	}

	/* Check for truncation.  Unfortunately there is no TIME_T_MAX. */
	_Static_assert(sizeof(time_t) == sizeof(int32_t) ||
	    sizeof(time_t) == sizeof(int64_t),
	    "time_t must be 32 or 64 bits");
	if (val < 0 || (sizeof(time_t) == sizeof(int32_t) && val > INT32_MAX) ||
	    (sizeof(time_t) == sizeof(int64_t) && val > INT64_MAX)) {
		errno = ERANGE;
		return (-1);
	}

	*tp = (time_t)val;
	return (0);
}
