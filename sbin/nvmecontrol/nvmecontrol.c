/*-
 * Copyright (C) 2012-2013 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioccom.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "nvmecontrol.h"

static void perftest_usage(void);

static void
usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, DEVLIST_USAGE);
	fprintf(stderr, IDENTIFY_USAGE);
	fprintf(stderr, RESET_USAGE);
	fprintf(stderr, PERFTEST_USAGE);
	exit(EX_USAGE);
}

static void
print_controller_hex(struct nvme_controller_data *cdata, uint32_t length)
{
	uint32_t	*p;
	uint32_t	i, j;

	p = (uint32_t *)cdata;
	length /= sizeof(uint32_t);

	for (i = 0; i < length; i+=8) {
		printf("%03x: ", i*4);
		for (j = 0; j < 8; j++)
			printf("%08x ", p[i+j]);
		printf("\n");
	}

	printf("\n");
}

static void
print_controller(struct nvme_controller_data *cdata)
{
	printf("Controller Capabilities/Features\n");
	printf("================================\n");
	printf("Vendor ID:                  %04x\n", cdata->vid);
	printf("Subsystem Vendor ID:        %04x\n", cdata->ssvid);
	printf("Serial Number:              %s\n", cdata->sn);
	printf("Model Number:               %s\n", cdata->mn);
	printf("Firmware Version:           %s\n", cdata->fr);
	printf("Recommended Arb Burst:      %d\n", cdata->rab);
	printf("IEEE OUI Identifier:        %02x %02x %02x\n",
		cdata->ieee[0], cdata->ieee[1], cdata->ieee[2]);
	printf("Multi-Interface Cap:        %02x\n", cdata->mic);
	/* TODO: Use CAP.MPSMIN to determine true memory page size. */
	printf("Max Data Transfer Size:     ");
	if (cdata->mdts == 0)
		printf("Unlimited\n");
	else
		printf("%d\n", PAGE_SIZE * (1 << cdata->mdts));
	printf("\n");

	printf("Admin Command Set Attributes\n");
	printf("============================\n");
	printf("Security Send/Receive:       %s\n",
		cdata->oacs.security ? "Supported" : "Not Supported");
	printf("Format NVM:                  %s\n",
		cdata->oacs.format ? "Supported" : "Not Supported");
	printf("Firmware Activate/Download:  %s\n",
		cdata->oacs.firmware ? "Supported" : "Not Supported");
	printf("Abort Command Limit:         %d\n", cdata->acl+1);
	printf("Async Event Request Limit:   %d\n", cdata->aerl+1);
	printf("Number of Firmware Slots:    ");
	if (cdata->oacs.firmware != 0)
		printf("%d\n", cdata->frmw.num_slots);
	else
		printf("N/A\n");
	printf("Firmware Slot 1 Read-Only:   ");
	if (cdata->oacs.firmware != 0)
		printf("%s\n", cdata->frmw.slot1_ro ? "Yes" : "No");
	else
		printf("N/A\n");
	printf("Per-Namespace SMART Log:     %s\n",
		cdata->lpa.ns_smart ? "Yes" : "No");
	printf("Error Log Page Entries:      %d\n", cdata->elpe+1);
	printf("Number of Power States:      %d\n", cdata->npss+1);
	printf("\n");

	printf("NVM Command Set Attributes\n");
	printf("==========================\n");
	printf("Submission Queue Entry Size\n");
	printf("  Max:                       %d\n", 1 << cdata->sqes.max);
	printf("  Min:                       %d\n", 1 << cdata->sqes.min);
	printf("Completion Queue Entry Size\n");
	printf("  Max:                       %d\n", 1 << cdata->cqes.max);
	printf("  Min:                       %d\n", 1 << cdata->cqes.min);
	printf("Number of Namespaces:        %d\n", cdata->nn);
	printf("Compare Command:             %s\n",
		cdata->oncs.compare ? "Supported" : "Not Supported");
	printf("Write Uncorrectable Command: %s\n",
		cdata->oncs.write_unc ? "Supported" : "Not Supported");
	printf("Dataset Management Command:  %s\n",
		cdata->oncs.dsm ? "Supported" : "Not Supported");
	printf("Volatile Write Cache:        %s\n",
		cdata->vwc.present ? "Present" : "Not Present");
}

static void
print_namespace_hex(struct nvme_namespace_data *nsdata, uint32_t length)
{
	uint32_t	*p;
	uint32_t	i, j;

	p = (uint32_t *)nsdata;
	length /= sizeof(uint32_t);

	for (i = 0; i < length; i+=8) {
		printf("%03x: ", i*4);
		for (j = 0; j < 8; j++)
			printf("%08x ", p[i+j]);
		printf("\n");
	}

	printf("\n");
}

static void
print_namespace(struct nvme_namespace_data *nsdata)
{
	uint32_t	i;

	printf("Size (in LBAs):              %lld (%lldM)\n",
		(long long)nsdata->nsze,
		(long long)nsdata->nsze / 1024 / 1024);
	printf("Capacity (in LBAs):          %lld (%lldM)\n",
		(long long)nsdata->ncap,
		(long long)nsdata->ncap / 1024 / 1024);
	printf("Utilization (in LBAs):       %lld (%lldM)\n",
		(long long)nsdata->nuse,
		(long long)nsdata->nuse / 1024 / 1024);
	printf("Thin Provisioning:           %s\n",
		nsdata->nsfeat.thin_prov ? "Supported" : "Not Supported");
	printf("Number of LBA Formats:       %d\n", nsdata->nlbaf+1);
	printf("Current LBA Format:          LBA Format #%d\n",
		nsdata->flbas.format);
	for (i = 0; i <= nsdata->nlbaf; i++) {
		printf("LBA Format #%d:\n", i);
		printf("  LBA Data Size:             %d\n",
			1 << nsdata->lbaf[i].lbads);
	}
}

void
read_controller_data(int fd, struct nvme_controller_data *cdata)
{
	struct nvme_pt_command	pt;

	memset(&pt, 0, sizeof(pt));
	pt.cmd.opc = NVME_OPC_IDENTIFY;
	pt.cmd.cdw10 = 1;
	pt.buf = cdata;
	pt.len = sizeof(*cdata);
	pt.is_read = 1;

	if (ioctl(fd, NVME_PASSTHROUGH_CMD, &pt) < 0) {
		printf("Identify request failed. errno=%d (%s)\n",
		    errno, strerror(errno));
		exit(EX_IOERR);
	}

	if (nvme_completion_is_error(&pt.cpl)) {
		printf("Passthrough command returned error.\n");
		exit(EX_IOERR);
	}
}

void
read_namespace_data(int fd, int nsid, struct nvme_namespace_data *nsdata)
{
	struct nvme_pt_command	pt;

	memset(&pt, 0, sizeof(pt));
	pt.cmd.opc = NVME_OPC_IDENTIFY;
	pt.cmd.nsid = nsid;
	pt.buf = nsdata;
	pt.len = sizeof(*nsdata);
	pt.is_read = 1;

	if (ioctl(fd, NVME_PASSTHROUGH_CMD, &pt) < 0) {
		printf("Identify request failed. errno=%d (%s)\n",
		    errno, strerror(errno));
		exit(EX_IOERR);
	}

	if (nvme_completion_is_error(&pt.cpl)) {
		printf("Passthrough command returned error.\n");
		exit(EX_IOERR);
	}
}

int
open_dev(const char *str, int *fd, int show_error, int exit_on_error)
{
	struct stat	devstat;
	char		full_path[64];

	snprintf(full_path, sizeof(full_path), "/dev/%s", str);
	if (stat(full_path, &devstat) != 0) {
		if (show_error)
			fprintf(stderr, "error\n");
		if (exit_on_error)
			exit(EX_NOINPUT);
		else
			return (EX_NOINPUT);
	}

	*fd = open(full_path, O_RDWR);
	if (*fd < 0) {
		if (show_error)
			printf("Could not open %s. errno=%d (%s)\n", full_path,
			    errno, strerror(errno));
		if (exit_on_error)
			exit(EX_NOPERM);
		else
			return (EX_NOPERM);
	}

	return (EX_OK);
}

static void
identify_usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, IDENTIFY_USAGE);
	exit(EX_USAGE);
}

static void
identify_ctrlr(int argc, char *argv[])
{
	struct nvme_controller_data	cdata;
	int				ch, fd, hexflag = 0, hexlength;
	int				verboseflag = 0;

	while ((ch = getopt(argc, argv, "vx")) != -1) {
		switch ((char)ch) {
		case 'v':
			verboseflag = 1;
			break;
		case 'x':
			hexflag = 1;
			break;
		default:
			identify_usage();
		}
	}

	open_dev(argv[optind], &fd, 1, 1);
	read_controller_data(fd, &cdata);
	close(fd);

	if (hexflag == 1) {
		if (verboseflag == 1)
			hexlength = sizeof(struct nvme_controller_data);
		else
			hexlength = offsetof(struct nvme_controller_data,
			    reserved5);
		print_controller_hex(&cdata, hexlength);
		exit(EX_OK);
	}

	if (verboseflag == 1) {
		printf("-v not currently supported without -x.\n");
		identify_usage();
	}

	print_controller(&cdata);
	exit(EX_OK);
}

static void
identify_ns(int argc, char *argv[])
{
	struct nvme_namespace_data	nsdata;
	char				path[64];
	char				*nsloc;
	int				ch, fd, hexflag = 0, hexlength, nsid;
	int				verboseflag = 0;

	while ((ch = getopt(argc, argv, "vx")) != -1) {
		switch ((char)ch) {
		case 'v':
			verboseflag = 1;
			break;
		case 'x':
			hexflag = 1;
			break;
		default:
			identify_usage();
		}
	}

	/*
	 * Check if the specified device node exists before continuing.
	 *  This is a cleaner check for cases where the correct controller
	 *  is specified, but an invalid namespace on that controller.
	 */
	open_dev(argv[optind], &fd, 1, 1);
	close(fd);

	/*
	 * Pull the namespace id from the string. +2 skips past the "ns" part
	 *  of the string.  Don't search past 10 characters into the string,
	 *  otherwise we know it is malformed.
	 */
	nsloc = strnstr(argv[optind], "ns", 10);
	if (nsloc != NULL)
		nsid = strtol(nsloc + 2, NULL, 10);
	if (nsloc == NULL || (nsid == 0 && errno != 0)) {
		printf("Invalid namespace ID %s.\n", argv[optind]);
		exit(EX_IOERR);
	}

	/*
	 * We send IDENTIFY commands to the controller, not the namespace,
	 *  since it is an admin cmd.  So the path should only include the
	 *  nvmeX part of the nvmeXnsY string.
	 */
	snprintf(path, nsloc - argv[optind] + 1, "%s", argv[optind]);
	open_dev(path, &fd, 1, 1);
	read_namespace_data(fd, nsid, &nsdata);
	close(fd);

	if (hexflag == 1) {
		if (verboseflag == 1)
			hexlength = sizeof(struct nvme_namespace_data);
		else
			hexlength = offsetof(struct nvme_namespace_data,
			    reserved6);
		print_namespace_hex(&nsdata, hexlength);
		exit(EX_OK);
	}

	if (verboseflag == 1) {
		printf("-v not currently supported without -x.\n");
		identify_usage();
	}

	print_namespace(&nsdata);
	exit(EX_OK);
}

static void
identify(int argc, char *argv[])
{
	char	*target;

	if (argc < 2)
		identify_usage();

	while (getopt(argc, argv, "vx") != -1) ;

	target = argv[optind];

	optreset = 1;
	optind = 1;

	/*
	 * If device node contains "ns", we consider it a namespace,
	 *  otherwise, consider it a controller.
	 */
	if (strstr(target, "ns") == NULL)
		identify_ctrlr(argc, argv);
	else
		identify_ns(argc, argv);
}

static void
print_perftest(struct nvme_io_test *io_test, bool perthread)
{
	uint32_t i, io_completed = 0, iops, mbps;

	for (i = 0; i < io_test->num_threads; i++)
		io_completed += io_test->io_completed[i];

	iops = io_completed/io_test->time;
	mbps = iops * io_test->size / (1024*1024);

	printf("Threads: %2d Size: %6d %5s Time: %3d IO/s: %7d MB/s: %4d\n",
	    io_test->num_threads, io_test->size,
	    io_test->opc == NVME_OPC_READ ? "READ" : "WRITE",
	    io_test->time, iops, mbps);

	if (perthread)
		for (i = 0; i < io_test->num_threads; i++)
			printf("\t%3d: %8d IO/s\n", i,
			    io_test->io_completed[i]/io_test->time);

	exit(1);
}

static void
perftest_usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, PERFTEST_USAGE);
	exit(EX_USAGE);
}

static void
perftest(int argc, char *argv[])
{
	struct nvme_io_test		io_test;
	int				fd;
	char				ch;
	char				*p;
	u_long				ioctl_cmd = NVME_IO_TEST;
	bool				nflag, oflag, sflag, tflag;
	int				perthread = 0;

	nflag = oflag = sflag = tflag = false;

	memset(&io_test, 0, sizeof(io_test));

	while ((ch = getopt(argc, argv, "f:i:n:o:ps:t:")) != -1) {
		switch (ch) {
		case 'f':
			if (!strcmp(optarg, "refthread"))
				io_test.flags |= NVME_TEST_FLAG_REFTHREAD;
			break;
		case 'i':
			if (!strcmp(optarg, "bio") ||
			    !strcmp(optarg, "wait"))
				ioctl_cmd = NVME_BIO_TEST;
			else if (!strcmp(optarg, "io") ||
				 !strcmp(optarg, "intr"))
				ioctl_cmd = NVME_IO_TEST;
			break;
		case 'n':
			nflag = true;
			io_test.num_threads = strtoul(optarg, &p, 0);
			if (p != NULL && *p != '\0') {
				fprintf(stderr,
				    "\"%s\" not valid number of threads.\n",
				    optarg);
				perftest_usage();
			} else if (io_test.num_threads == 0 ||
				   io_test.num_threads > 128) {
				fprintf(stderr,
				    "\"%s\" not valid number of threads.\n",
				    optarg);
				perftest_usage();
			}
			break;
		case 'o':
			oflag = true;
			if (!strcmp(optarg, "read") || !strcmp(optarg, "READ"))
				io_test.opc = NVME_OPC_READ;
			else if (!strcmp(optarg, "write") ||
				 !strcmp(optarg, "WRITE"))
				io_test.opc = NVME_OPC_WRITE;
			else {
				fprintf(stderr, "\"%s\" not valid opcode.\n",
				    optarg);
				perftest_usage();
			}
			break;
		case 'p':
			perthread = 1;
			break;
		case 's':
			sflag = true;
			io_test.size = strtoul(optarg, &p, 0);
			if (p == NULL || *p == '\0' || toupper(*p) == 'B') {
				// do nothing
			} else if (toupper(*p) == 'K') {
				io_test.size *= 1024;
			} else if (toupper(*p) == 'M') {
				io_test.size *= 1024 * 1024;
			} else {
				fprintf(stderr, "\"%s\" not valid size.\n",
				    optarg);
				perftest_usage();
			}
			break;
		case 't':
			tflag = true;
			io_test.time = strtoul(optarg, &p, 0);
			if (p != NULL && *p != '\0') {
				fprintf(stderr,
				    "\"%s\" not valid time duration.\n",
				    optarg);
				perftest_usage();
			}
			break;
		}
	}

	if (!nflag || !oflag || !sflag || !tflag || optind >= argc)
		perftest_usage();

	open_dev(argv[optind], &fd, 1, 1);
	if (ioctl(fd, ioctl_cmd, &io_test) < 0) {
		fprintf(stderr, "NVME_IO_TEST failed. errno=%d (%s)\n", errno,
		    strerror(errno));
		close(fd);
		exit(EX_IOERR);
	}

	close(fd);
	print_perftest(&io_test, perthread);
	exit(EX_OK);
}

static void
reset_usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, RESET_USAGE);
	exit(EX_USAGE);
}

static void
reset_ctrlr(int argc, char *argv[])
{
	int	ch, fd;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch ((char)ch) {
		default:
			reset_usage();
		}
	}

	open_dev(argv[optind], &fd, 1, 1);
	if (ioctl(fd, NVME_RESET_CONTROLLER) < 0) {
		printf("Reset request to %s failed. errno=%d (%s)\n",
		    argv[optind], errno, strerror(errno));
		exit(EX_IOERR);
	}

	exit(EX_OK);
}

int
main(int argc, char *argv[])
{

	if (argc < 2)
		usage();

	if (strcmp(argv[1], "devlist") == 0)
		devlist(argc-1, &argv[1]);
	else if (strcmp(argv[1], "identify") == 0)
		identify(argc-1, &argv[1]);
	else if (strcmp(argv[1], "perftest") == 0)
		perftest(argc-1, &argv[1]);
	else if (strcmp(argv[1], "reset") == 0)
		reset_ctrlr(argc-1, &argv[1]);

	usage();

	return (0);
}
