/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/nv.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <regex.h>
#include <time.h>

#include <libcasper.h>
#include <libcasper_service.h>
#include <libutil.h>

#define SYSLOG_NAMES
#include <sys/syslog.h>

#include "config.h"

static int	readconfigfile(FILE *f, bool allow_includes);

static const char include_str[] = "include";
static const size_t include_str_len = sizeof(include_str) - 1;
static const char include_ext[] = ".conf";

static int
configfiles(const struct dirent *dp)
{
	const char *p;
	size_t ext_len;

	if (dp->d_name[0] == '.')
		return (0);
	ext_len = sizeof(include_ext) - 1;
	if (dp->d_namlen <= ext_len)
		return (0);
	/* XXXMJ maybe be more careful and do not trust namelen? */
	p = &dp->d_name[dp->d_namlen - ext_len];
	if (strcmp(p, include_ext) != 0)
		return (0);

	return (1);
}

static int
readconfigdir(const char *path)
{
	char cfile[PATH_MAX];
	struct dirent **ent;
	FILE *cf;
	int i, n, nents;

	nents = scandir(path, &ent, configfiles, alphasort);
	if (nents == -1)
		return (-1);
	for (i = 0; i < nents; i++) {
		n = snprintf(cfile, sizeof(cfile), "%s/%s", path,
		    ent[i]->d_name);
		free(ent[i]);
		if (n >= (int)sizeof(cfile))
			continue;
		cf = fopen(cfile, "re");
		if (cf == NULL)
			continue;
		/* XXXMJ error handling? */
		(void)readconfigfile(cf, false);
	}
	free(ent);
	return (0);
}

/*
 *  Decode a symbolic name to a numeric value
 */
static int
decode(const char *name, const CODE *codetab)
{
	const CODE *c;
	char *p, buf[40];

	if (isdigit(*name))
		return (atoi(name));

	for (p = buf; *name && p < &buf[sizeof(buf) - 1]; p++, name++) {
		if (isupper(*name))
			*p = tolower(*name);
		else
			*p = *name;
	}
	*p = '\0';
	for (c = codetab; c->c_name; c++)
		if (!strcmp(buf, c->c_name))
			return (c->c_val);

	return (-1);
}

static int
readconfigline(const char *cfline, const char *prog, const char *host,
    const char *pfilter)
{
	const char *service;
	char buf[LINE_MAX];
	char *bufp, *p, *q;
	size_t i;
	int pri_cmp, pri_done, pri_invert;
	bool syncfile;

	/* scan through the list of selectors */
	for (p = line; *p != '\0' && !isspace(*p);) {
		/* find the end of this facility name list */
		for (q = p; *q != '\0' && !isspace(*q) && *q != '.'; q++)
			continue;

		/* get the priority comparison */
		pri_cmp = 0;
		pri_done = 0;
		pri_invert = 0;
		if (*q == '!') {
			pri_invert = 1;
			q++;
		}
		for (; !pri_done; q++) {
			switch (*q) {
			case '<':
				pri_cmp |= PRI_LT;
				break;
			case '=':
				pri_cmp |= PRI_EQ;
				break;
			case '>':
				pri_cmp |= PRI_GT;
				break;
			default:
				pri_done++;
				break;
			}
		}

		/* collect priority name */
		for (bufp = buf; *q != '\0' && !strchr("\t,; ", *q); )
			*bufp++ = *q++;
		*bufp = '\0';

		/* skip cruft */
		while (strchr(",;", *q))
			q++;

		/* decode priority name */
		if (*buf == '*') {
			pri = LOG_PRIMASK;
			pri_cmp = PRI_LT | PRI_EQ | PRI_GT;
		} else {
			/* Ignore trailing spaces. */
			for (i = strlen(buf) - 1; i >= 0 && isspace(buf[i]);
			    i--)
				buf[i] = '\0';

			pri = decode(buf, prioritynames);
			if (pri < 0) {
				/* XXXMJ */
#if 0
				errno = 0;
				(void)snprintf(ebuf, sizeof ebuf,
				    "unknown priority name \"%s\"", buf);
				logerror(ebuf);
				free(f);
#endif
				return;
			}
		}
		if (!pri_cmp)
			pri_cmp = UniquePriority ? PRI_EQ : (PRI_EQ | PRI_GT);
		if (pri_invert)
			pri_cmp ^= PRI_LT | PRI_EQ | PRI_GT;

		/* scan facilities */
		while (*p != '\0' && !strchr("\t.; ", *p)) {
			for (bufp = buf; *p != '\0' && !strchr("\t,;. ", *p);)
				*bufp++ = *p++;
			*bufp = '\0';

			if (*buf == '*') {
				for (i = 0; i < LOG_NFACILITIES; i++) {
					f->f_pmask[i] = pri;
					f->f_pcmp[i] = pri_cmp;
				}
			} else {
				i = decode(buf, facilitynames);
				if (i < 0) {
					errno = 0;
					(void)snprintf(ebuf, sizeof ebuf,
					    "unknown facility name \"%s\"",
					    buf);
					logerror(ebuf);
					free(f);
					return;
				}
				f->f_pmask[i >> 3] = pri;
				f->f_pcmp[i >> 3] = pri_cmp;
			}
			while (*p == ',' || *p == ' ')
				p++;
		}

		p = q;
	}

	/* skip to action part */
	for (; isspace(*p); p++)
		;

	if (*p == '-') {
		syncfile = 0;
		p++;
	} else {
		syncfile = 1;
	}

	switch (*p) {
	case '@':
		p++;
		{
			char endkey = ':', *tp;

			/*
			 * scan forward to see if there is a port defined.
			 */
			i = sizeof(f->fu_forw_hname);
			tp = f->fu_forw_hname;

			/*
			 * an ipv6 address should start with a '[' in that case
			 * we should scan for a ']'
			 */
			if (*p == '[') {
				p++;
				endkey = ']';
			}
			while (*p && (*p != endkey) && (i-- > 0)) {
				*tp++ = *p++;
			}
			if (endkey == ']' && *p == endkey)
				p++;
			*tp = '\0';
		}
		/* See if we copied a domain and have a port */
		if (*p == ':')
			service = p + 1;
		else
			service = "syslog";

		hints = (struct addrinfo){
			.ai_family = family,
			.ai_socktype = SOCK_DGRAM
		};
		error = getaddrinfo(f->fu_forw_hname, service, &hints, &res);
		if (error) {
			logerror(gai_strerror(error));
			break;
		}
		f->fu_forw_addr = res;
		f->f_type = F_FORW;
		break;

	case '/':
		/* XXXMJ may need O_CREAT */
		if ((f->f_file = open(p, O_APPEND | O_WRONLY, 0600)) < 0) {
			f->f_type = F_UNUSED;
			logerror(p);
			break;
		}
		if (syncfile)
			f->f_flags |= FFLAG_SYNC;
		if (isatty(f->f_file)) {
			if (strcmp(p, ctty) == 0)
				f->f_type = F_CONSOLE;
			else
				f->f_type = F_TTY;
			(void)strlcpy(f->fu_fname, p + sizeof(_PATH_DEV) - 1,
			    sizeof(f->fu_fname));
		} else {
			(void)strlcpy(f->fu_fname, p, sizeof(f->fu_fname));
			f->f_type = F_FILE;
		}
		break;

	case '|':
		p++;
		f->fu_pipe_pd = -1;
		(void)strlcpy(f->fu_pipe_pname, p, sizeof(f->fu_pipe_pname));
		f->f_type = F_PIPE;
		break;

	case '*':
		f->f_type = F_WALL;
		break;

	default:
		for (i = 0; i < MAXUNAMES && *p; i++) {
			for (q = p; *q != '\0' && *q != ','; q++)
				;
			(void)strncpy(f->fu_uname[i], p, MAXLOGNAME - 1);
			if (q - p >= MAXLOGNAME)
				f->fu_uname[i][MAXLOGNAME - 1] = '\0';
			else
				f->fu_uname[i][q - p] = '\0';
			for (; *q == ',' || *q == ' '; q++)
				;
			p = q;
		}
		f->f_type = F_USERS;
		break;
	}

	STAILQ_INSERT_TAIL(l, f, next);
}

static int
readconfigfile(FILE *f, bool allow_includes)
{
	char cline[LINE_MAX];
	char host[MAXHOSTNAMELEN];
	char pfilter[LINE_MAX];
	char prog[LINE_MAX];
	char *p, *tmp;
	int i;

	while (fgets(cline, sizeof(cline), f) != NULL) {
		/* Trim leading whitespace, ignore blank lines. */
		for (p = cline; isspace(*p); p++)
			;
		if (*p == '\0')
			continue;

		/* Handle include directives. */
		if (allow_includes &&
		    strncmp(p, include_str, include_str_len) == 0 &&
		    isspace(p[include_str_len])) {
			p += include_str_len;
			for (; isspace(*p); p++)
				;
			tmp = p;
			while (*tmp != '\0' && !isspace(*tmp))
				tmp++;
			*tmp = '\0';
			/* XXXMJ error handling? */
			(void)readconfigdir(p);
			continue;
		}

		/* Check for comments and legacy filter syntax. */
		if (*p == '#') {
			p++;
			if (*p == '\0' || strchr("!+-:", *p) == NULL)
				continue;
		}
		/* Handle hostname filters. */
		if (*p == '+' || *p == '-') {
			host[0] = *p++;
			for (; isspace(*p); p++)
				;
			if (*p == '\0' || *p == '*') {
				(void)strlcpy(host, "*", sizeof(host));
				continue;
			}
			/* XXXMJ transfer LocalHostName here */
			/* XXXMJ maybe do post-processing in the main program. */
#if 0
			if (*p == '@')
				p = LocalHostName;
#endif
			for (i = 1; i < MAXHOSTNAMELEN - 1; i++) {
				if (!isalnum(*p) && *p != '.' && *p != '-' &&
				    *p != ',' && *p != ':' && *p != '%')
					break;
				host[i] = *p++;
			}
			host[i] = '\0';
			continue;
		}
		/* Handle program name filters */
		if (*p == '!') {
			p++;
			for (; isspace(*p); p++)
				;
			if (*p == '\0' || *p == '*') {
				(void)strlcpy(prog, "*", sizeof(prog));
				continue;
			}
			for (i = 0; i < LINE_MAX - 1; i++) {
				if (!isprint(p[i]) || isspace(p[i]))
					break;
				prog[i] = p[i];
			}
			prog[i] = '\0';
			continue;
		}
		/* Handle property filters */
		if (*p == ':') {
			p++;
			for (; isspace(*p); p++)
				;
			if (*p == '\0' || *p == '*') {
				(void)strlcpy(pfilter, "*", sizeof(pfilter));
				continue;
			}
			(void)strlcpy(pfilter, p, sizeof(pfilter));
			continue;
		}
		/* Handle escaped '#' characters. */
		for (p = cline + 1; *p != '\0'; p++) {
			if (*p != '#')
				continue;
			if (*(p - 1) == '\\') {
				strcpy(p - 1, p);
				p--;
				continue;
			}
			*p = '\0';
			break;
		}
		/* Trim trailing whitespace. */
		for (i = strlen(cline) - 1; i >= 0 && isspace(cline[i]); i--)
			cline[i] = '\0';

		/* Process the line. */
		readconfigline(cline, prog, host, pfilter);
	}

	return (0);
}

static int
readconfig(const char *path)
{
	FILE *f;
	int error;

	f = fopen(path, "re");
	if (f == NULL)
		return (-1);

	error = readconfigfile(f, true);
	/* XXX preserve errno? */
	fclose(f);
	return (error);
}

int
cap_readconfig(cap_channel_t *cap, const char *path)
{
#ifdef WITH_CASPER
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "read");
	nvlist_add_string(nvl, "file", path);
	nvl = cap_xfer_nvlist(cap, nvl);
	if (nvl == NULL)
		return (-1);
#endif
	return (0);
}

#ifdef WITH_CASPER
static int
config_command(const char *cmd, const nvlist_t *limits, nvlist_t *nvlin,
    nvlist_t *nvlout)
{
	const char *file;
	int error;

	if (strcmp(cmd, "read") != 0)
		return (EINVAL);

	file = nvlist_get_string(nvlin, "file");
	if (strcmp(file, nvlist_get_string(limits, "file")) != 0)
		return (ENOTCAPABLE);

	error = readconfig(file);
	if (error != 0)
		nvlist_add_number(nvlout, "error", errno);
	return (0);
}

static int
config_limit(const nvlist_t *oldlimits, const nvlist_t *newlimits)
{
	const char *name;
	void *cookie;
	int nvtype;
	bool hasfile;

	/* Limits may only be set once. */
	if (oldlimits != NULL)
		return (ENOTCAPABLE);

	cookie = NULL;
	hasfile = false;
	while ((name = nvlist_next(newlimits, &nvtype, &cookie)) != NULL) {
		if (nvtype == NV_TYPE_STRING && strcmp(name, "file") == 0)
			hasfile = true;
		else
			return (EINVAL);
	}
	return (hasfile ? 0 : EINVAL);
}

CREATE_SERVICE("syslogd.config", config_limit, config_command, 0);
#endif
