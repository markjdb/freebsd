/* $FreeBSD$ */

#include <setjmp.h>
#include <stdlib.h>

#include "dhcpd.h"

extern jmp_buf env;

jmp_buf env;

void	expand_domain_search(struct packet *packet);

static void
no_option_present(void)
{
	int ret;
	struct option_data option;
	struct packet p;

	option.data = NULL;
	option.len  = 0;
	p.options[DHO_DOMAIN_SEARCH] = option;

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (p.options[DHO_DOMAIN_SEARCH].len != 0 ||
	    p.options[DHO_DOMAIN_SEARCH].data != NULL)
		abort();
}

static void
one_domain_valid(void)
{
	int ret;
	struct packet p;
	struct option_data *option;

	const char *data     = "\007example\003org\0";
	const char *expected = "example.org.";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 13;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (option->len != strlen(expected) ||
	    strcmp(option->data, expected) != 0)
		abort();

	free(option->data);
}

static void
one_domain_truncated1(void)
{
	int ret;
	struct option_data *option;
	struct packet p;

	const char *data = "\007example\003org";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 12;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (ret != 1)
		abort();

	free(option->data);
}

static void
one_domain_truncated2(void)
{
	int ret;
	struct option_data *option;
	struct packet p;

	const char *data = "\007ex";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 3;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (ret != 1)
		abort();

	free(option->data);
}

static void
two_domains_valid(void)
{
	int ret;
	struct packet p;
	struct option_data *option;

	const char *data     = "\007example\003org\0\007example\003com\0";
	const char *expected = "example.org. example.com.";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 26;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (option->len != strlen(expected) ||
	    strcmp(option->data, expected) != 0)
		abort();

	free(option->data);
}

static void
two_domains_truncated1(void)
{
	int ret;
	struct option_data *option;
	struct packet p;

	const char *data = "\007example\003org\0\007example\003com";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 25;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (ret != 1)
		abort();

	free(option->data);
}

static void
two_domains_truncated2(void)
{
	int ret;
	struct option_data *option;
	struct packet p;

	const char *data = "\007example\003org\0\007ex";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 16;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (ret != 1)
		abort();

	free(option->data);
}

static void
two_domains_compressed(void)
{
	int ret;
	struct packet p;
	struct option_data *option;

	const char *data     = "\007example\003org\0\006foobar\xc0\x08";
	const char *expected = "example.org. foobar.org.";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 22;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (option->len != strlen(expected) ||
	    strcmp(option->data, expected) != 0)
		abort();

	free(option->data);
}

static void
two_domains_infloop(void)
{
	int ret;
	struct packet p;
	struct option_data *option;

	const char *data = "\007example\003org\0\006foobar\xc0\x0d";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 22;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (ret != 1)
		abort();

	free(option->data);
}

static void
two_domains_forwardptr(void)
{
	int ret;
	struct packet p;
	struct option_data *option;

	const char *data = "\007example\003org\xc0\x0d\006foobar\0";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 22;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (ret != 1)
		abort();

	free(option->data);
}

static void
two_domains_truncatedptr(void)
{
	int ret;
	struct packet p;
	struct option_data *option;

	const char *data = "\007example\003org\0\006foobar\xc0";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 21;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (ret != 1)
		abort();

	free(option->data);
}

static void
multiple_domains_valid(void)
{
	int ret;
	struct packet p;
	struct option_data *option;

	const char *data =
	    "\007example\003org\0\002cl\006foobar\003com\0\002fr\xc0\x10";

	const char *expected = "example.org. cl.foobar.com. fr.foobar.com.";

	option = &p.options[DHO_DOMAIN_SEARCH];
	option->len  = 33;
	option->data = malloc(option->len);
	memcpy(option->data, data, option->len);

	ret = setjmp(env);
	if (ret == 0)
		expand_domain_search(&p);

	if (option->len != strlen(expected) ||
	    strcmp(option->data, expected) != 0)
		abort();

	free(option->data);
}

int
main(void)
{

	no_option_present();

	one_domain_valid();
	one_domain_truncated1();
	one_domain_truncated2();

	two_domains_valid();
	two_domains_truncated1();
	two_domains_truncated2();

	two_domains_compressed();
	two_domains_infloop();
	two_domains_forwardptr();
	two_domains_truncatedptr();

	multiple_domains_valid();

	return (0);
}
