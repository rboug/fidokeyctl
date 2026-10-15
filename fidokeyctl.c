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
#include <readpassphrase.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_DEVS	64
#define PIN_BUFSIZE	64

static int		 select_device(char *, size_t, const char *, int);
static void		 print_aaguid(const fido_cbor_info_t *);
static void		 print_options(const fido_cbor_info_t *);
static void		 print_versions(const fido_cbor_info_t *);
static void		 show_info(fido_dev_t *, const char *);
static int		 get_retries(fido_dev_t *);
static void		 show_retries(fido_dev_t *);
static void		 read_new_pin(char *, size_t);
static void		 set_pin(fido_dev_t *);
static void		 update_pin(fido_dev_t *);
static void		 confirm_reset(void);
static void		 reset_device(void);
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

	if (n != 16) {
		printf("invalid\n");
		return;
	}

	for (i = 0; i < n; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			putchar('-');
		printf("%02x", aaguid[i]);
	}
	printf("\n");
}

static int
select_device(char *path, size_t pathlen, const char *requested,
    int allow_select)
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
				fprintf(stderr, ": %s", product);
			fprintf(stderr, "\n");
		}

		if (allow_select)
			errx(1, "use -f device to select one");
		else
			errx(1, "connect only the authenticator to reset");
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
confirm_reset(void)
{
	char buf[16];

	fprintf(stderr,
	    "WARNING: FIDO reset will erase the PIN and all FIDO credentials\n"
	    "stored on this authenticator.\n\n"
	    "Type \"RESET\" to continue: ");

	if (fgets(buf, sizeof(buf), stdin) == NULL)
		err(1, "fgets");

	buf[strcspn(buf, "\n")] = '\0';

	if (strcmp(buf, "RESET") != 0)
		errx(1, "reset cancelled");
}

static void
reset_device(void)
{
	char path[PATH_MAX];
	fido_dev_t *dev;
	int r;

	/* Ensure that only one authenticator is currently connected. */
	select_device(path, sizeof(path), NULL, 0);

	confirm_reset();

	fprintf(stderr, "Remove and reinsert the authenticator, then press "
	    "Enter immediately.\n");

	if (getchar() == EOF)
		err(1, "getchar");

	/* Discover the authenticator again after the power cycle. */
	select_device(path, sizeof(path), NULL, 0);

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	if ((r = fido_dev_open(dev, path)) != FIDO_OK)
		errx(1, "%s: %s", path, fido_strerr(r));

	fprintf(stderr, "Touch the authenticator to confirm reset.\n");

	r = fido_dev_reset(dev);

	if (r != FIDO_OK) {
		if (r == FIDO_ERR_NOT_ALLOWED)
			errx(1, "reset not allowed, remove and reinsert the "
			    "authenticator and try again");
		if (r == FIDO_ERR_ACTION_TIMEOUT)
			errx(1, "reset confirmation timed out");
		errx(1, "fido_dev_reset: %s", fido_strerr(r));
	}

	printf("FIDO authenticator reset\n");

	if ((r = fido_dev_close(dev)) != FIDO_OK)
		warnx("fido_dev_close: %s", fido_strerr(r));

	fido_dev_free(&dev);
}

static void
show_info(fido_dev_t *dev, const char *path)
{
	fido_cbor_info_t *ci;
	int r;

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
}

static int
get_retries(fido_dev_t *dev)
{
	int retries;
	int r;

	r = fido_dev_get_retry_count(dev, &retries);
	if (r == FIDO_ERR_PIN_NOT_SET)
		return -1;
	if (r != FIDO_OK)
		errx(1, "fido_dev_get_retry_count: %s", fido_strerr(r));

	return retries;
}

static void
show_retries(fido_dev_t *dev)
{
	int retries;

	retries = get_retries(dev);

	if (retries == -1)
		printf("pin-retries: not-set\n");
	else
		printf("pin-retries: %d\n", retries);
}

static void
read_new_pin(char *pin, size_t pinsz)
{
	char confirm[PIN_BUFSIZE];

	if (readpassphrase("New PIN: ", pin, pinsz, RPP_REQUIRE_TTY) == NULL)
		err(1, "readpassphrase");

	if (readpassphrase("Confirm PIN: ", confirm, sizeof(confirm),
	    RPP_REQUIRE_TTY) == NULL) {
		explicit_bzero(pin, pinsz);
		err(1, "readpassphrase");
	}

	if (strcmp(pin, confirm) != 0) {
		explicit_bzero(pin, pinsz);
		explicit_bzero(confirm, sizeof(confirm));
		errx(1, "PINs do not match");
	}

	explicit_bzero(confirm, sizeof(confirm));
}

static void
set_pin(fido_dev_t *dev)
{
	char pin[PIN_BUFSIZE];
	int r;

	if (fido_dev_has_pin(dev))
		errx(1, "PIN already set");

	read_new_pin(pin, sizeof(pin));

	r = fido_dev_set_pin(dev, pin, NULL);

	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_dev_set_pin: %s", fido_strerr(r));

	printf("PIN set\n");
}

static void
update_pin(fido_dev_t *dev)
{
	char oldpin[PIN_BUFSIZE];
	char pin[PIN_BUFSIZE];
	int r, retries;

	if (!fido_dev_has_pin(dev))
		errx(1, "PIN not set");

	if (readpassphrase("Current PIN: ", oldpin, sizeof(oldpin),
	    RPP_REQUIRE_TTY) == NULL)
		err(1, "readpassphrase");

	read_new_pin(pin, sizeof(pin));

	r = fido_dev_set_pin(dev, pin, oldpin);

	explicit_bzero(oldpin, sizeof(oldpin));
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK) {
		if (r == FIDO_ERR_PIN_INVALID) {
			retries = get_retries(dev);
			if (retries >= 0)
				errx(1, "incorrect PIN (%d retries remaining)",
				    retries);
			errx(1, "incorrect PIN");
		}
		if (r == FIDO_ERR_PIN_AUTH_BLOCKED)
			errx(1, "PIN authentication temporarily blocked, "
			    "remove and reinsert device");
		if (r == FIDO_ERR_PIN_BLOCKED)
			errx(1, "PIN blocked, FIDO reset required");
		errx(1, "fido_dev_set_pin: %s", fido_strerr(r));
	}

	printf("PIN updated\n");
}

static __dead void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-diPpr] [-f device]\n"
	    "       %s -R\n",
	    getprogname(), getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	char device[PATH_MAX];
	const char *requested;
	int ch, debug, info, pinop, reset, retries, setpin, updatepin;
	fido_dev_t *dev;
	int r;

	debug = 0;
	info = 0;
	requested = NULL;
	reset = 0;
	retries = 0;
	setpin = 0;
	updatepin = 0;

	while ((ch = getopt(argc, argv, "dif:pPrR")) != -1) {
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
		case 'P':
			updatepin = 1;
			break;
		case 'p':
			setpin = 1;
			break;
		case 'R':
			reset = 1;
			break;
		case 'r':
			retries = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (reset) {
		if (debug || info || retries || setpin || updatepin
		    || requested != NULL)
			errx(1, "-R cannot be combined with other options");
	} else if (!info && !retries && !setpin && !updatepin)
		usage();

	if (setpin && updatepin)
		errx(1, "-p and -P are mutually exclusive");

	if (reset) {
		if (pledge("stdio rpath wpath unveil", NULL) == -1)
			err(1, "pledge");

		fido_init(0);

		/*
		 * Keep /dev/fido visible during the power-cycle so the
		 * authenticator can be rediscovered.
		 */
		if (unveil("/dev/fido", "rw") == -1)
			err(1, "unveil /dev/fido");
		if (unveil(NULL, NULL) == -1)
			err(1, "unveil");

		if (pledge("stdio rpath wpath", NULL) == -1)
			err(1, "pledge");

		reset_device();

		return 0;
	}

	pinop = setpin || updatepin;

	/*
	 * Disable debug mode for PIN operations to prevent display of
	 * sensitive data.
	 */
	if (debug && pinop)
		errx(1, "-d cannot be used with PIN operations");

	/* Restrict the available syscall classes. */
	if (pinop) {
		if (pledge("stdio tty rpath wpath unveil", NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio rpath wpath unveil", NULL) == -1)
			err(1, "pledge");
	}

	fido_init(debug ? FIDO_DEBUG : 0);

	select_device(device, sizeof(device), requested, 1);

	/* Restrict filesystem visibility to the selected authenticator. */
	if (unveil(device, "rw") == -1)
		err(1, "unveil %s", device);
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");

	/* Open device. */
	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	if ((r = fido_dev_open(dev, device)) != FIDO_OK)
		errx(1, "%s: %s", device, fido_strerr(r));

	/* if a PIN operation follows, retain terminal access temporarily. */
	if (pinop) {
		if (pledge("stdio tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio", NULL) == -1)
			err(1, "pledge");
	}

	if (info)
		show_info(dev, device);

	if (retries)
		show_retries(dev);

	if (setpin)
		set_pin(dev);

	if (updatepin)
		update_pin(dev);

	if (pinop) {
		if (pledge("stdio", NULL) == -1)
			err(1, "pledge");
	}

	if ((r = fido_dev_close(dev)) != FIDO_OK)
		warnx("fido_dev_close: %s", fido_strerr(r));

	fido_dev_free(&dev);

	return 0;
}
