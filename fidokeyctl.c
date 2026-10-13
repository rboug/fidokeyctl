/*
 * Copyright (c) 2026 rboug
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <err.h>
#include <fido.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_DEVS    64

static int		 select_device(char *, size_t, const char *);
static void		 print_aaguid(const fido_cbor_info_t *);
static void		 print_options(const fido_cbor_info_t *);
static void		 print_versions(const fido_cbor_info_t *);
static void		 show_info(const char *);
static const char	*yesno(bool);
static __dead void	 usage(void);

static const char *
yesno(bool value)
{
	return value ? "yes" : "no";
}

static void
print_versions(const fido_cbor_info_t *ci)
{
	char **versions;
	size_t i, n;

	versions = fido_cbor_info_versions_ptr(ci);
	n = fido_cbor_info_versions_len(ci);

	printf("versions:");
	for (i = 0; i < n; i++)
		printf("%s%s", i == 0 ? " " : ", ", versions[i]);
	printf("\n");
}

static void
print_options(const fido_cbor_info_t *ci)
{
	const bool *values;
	char **names;
	size_t i, n;

	names = fido_cbor_info_options_name_ptr(ci);
	values = fido_cbor_info_options_value_ptr(ci);
	n = fido_cbor_info_options_len(ci);

	printf("options:");
	for (i = 0; i < n; i++) {
		printf("%s%s=%s", i == 0 ? " " : ", ", names[i],
		    yesno(values[i]));
	}
	printf("\n");
}

static void
print_aaguid(const fido_cbor_info_t *ci)
{
	const unsigned char *aaguid;
	size_t i, n;

	aaguid = fido_cbor_info_aaguid_ptr(ci);
	n = fido_cbor_info_aaguid_len(ci);

	printf("aaguid: ");
	if (aaguid == NULL || n == 0) {
		printf("undefined\n");
		return;
	}

	for (i = 0; i < n; i++)
		printf("%02x", aaguid[i]);
	printf("\n");
}

static int
select_device(char *path, size_t pathlen, const char *requested)
{
	const fido_dev_info_t *di;
	fido_dev_info_t *devlist;
	const char *devpath, *product;
	size_t i, ndevs;
	int r;

	if (requested != NULL) {
		if (strlcpy(path, requested, pathlen) >= pathlen)
			errx(1, "device path too long");
		return 0;
	}

	if ((devlist = fido_dev_info_new(MAX_DEVS)) == NULL)
		errx(1, "fido_dev_info_new");

	ndevs = 0;
	r = fido_dev_info_manifest(devlist, MAX_DEVS, &ndevs);
	if (r != FIDO_OK)
		errx(1, "fido_dev_info_manifest: %s", fido_strerr(r));

	if (ndevs == 0)
		errx(1, "no FIDO device found");

	if (ndevs > 1) {
		warnx("multiple FIDO devices found:");
		for (i = 0; i < ndevs; i++) {
			di = fido_dev_info_ptr(devlist, i);
			devpath = fido_dev_info_path(di);
			product = fido_dev_info_product_string(di);

			fprintf(stderr, " %s",
			    devpath != NULL ? devpath : "{unknown}");
			if (product != NULL)
				fprintf(stderr, " :%s", product);
			fprintf(stderr, "\n");
		}
		errx(1, "use -f device to select one");
	}

	di = fido_dev_info_ptr(devlist, 0);
	if ((devpath = fido_dev_info_path(di)) == NULL)
		errx(1, "device has no path");

	if (strlcpy(path, devpath, pathlen) >= pathlen)
		errx(1, "device path too long");

	fido_dev_info_free(&devlist, MAX_DEVS);

	return 0;
}

static void
show_info(const char *path)
{
	fido_cbor_info_t *ci;
	fido_dev_t *dev;
	int r;

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	if ((r = fido_dev_open(dev, path)) != FIDO_OK)
		errx(1, "%s: %s", path, fido_strerr(r));

	/*
	 * The device is now open. No further filesystem access should be
	 * necessary.
	 */
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	printf("device: %s\n", path);
	printf("protocol: %s\n", fido_dev_is_fido2(dev) ? "FIDO2" : "U2F");
	printf("pin-supported: %s\n", yesno(fido_dev_supports_pin(dev)));
	printf("pin-set: %s\n", yesno(fido_dev_has_pin(dev)));
	printf("uv-supported: %s\n", yesno(fido_dev_supports_uv(dev)));
	printf("uv-configured: %s\n", yesno(fido_dev_has_uv(dev)));
	printf("credential-management: %s\n",
	    yesno(fido_dev_supports_credman(dev)));

	if ((ci = fido_cbor_info_new()) == NULL)
		errx(1, "fido_cbor_info_new");

	r = fido_dev_get_cbor_info(dev, ci);
	if (r != FIDO_OK)
		errx(1, "fido_dev_get_cbor_info: %s", fido_strerr(r));

	print_versions(ci);
	print_options(ci);
	print_aaguid(ci);

	fido_cbor_info_free(&ci);

	if ((r = fido_dev_close(dev)) != FIDO_OK)
		warnx("fido_dev_close: %s", fido_strerr(r));

	fido_dev_free(&dev);
}

static __dead void
usage(void)
{
	fprintf(stderr, "Usage: %s [-d] -i [-f device]\n", getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	char device[PATH_MAX];
	const char *requested;
	int ch, debug, info;

	debug = 0;
	info = 0;
	requested = NULL;

	while ((ch = getopt(argc, argv, "dif:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			requested = optarg;
			break;
		case 'i':
			info = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || !info)
		usage();

	/*
	 * Restrict the available syscall classes before device discovery.
	 * unveil remains available until the selected device is known.
	 */
	if (pledge("stdio rpath wpath unveil", NULL) == -1)
		err(1, "pledge");

	fido_init(debug ? FIDO_DEBUG : 0);

	select_device(device, sizeof(device), requested);

	/*
	 * From this point on, the process may only see the selected FIDO
	 * device in the filesystem.
	 */
	if (unveil(device, "rw") == -1)
		err(1, "unveil %s", device);
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");

	show_info(device);

	return 0;
}
