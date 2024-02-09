#include "bpfilter.h"

#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/timeout.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/endian.h>

#include <machine/bus.h>
#include <machine/intr.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_amrr.h>
#include <net80211/ieee80211_radiotap.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>

#include <dev/usb/if_urtwmvar.h>

int urtwm_match(struct device *, void *, void *);
void urtwm_attach(struct device *, struct device *, void *);
int urtwm_detach(struct device *, int);

struct cfdriver urtwm_cd = {
	NULL, "urtwm", DV_IFNET
};

const struct cfattach urtwm_ca = {
	sizeof(struct urtwm_softc), urtwm_match, urtwm_attach, urtwm_detach
};

// XXX: DONT FORGET TO FIX usbdevs.h before submit
static const struct urtwm_type {
	struct usb_devno        dev;
	uint32_t		chip;
} urtwm_devs[] = {
	{ { USB_VENDOR_TPLINK,	USB_PRODUCT_TPLINK_RTL8822BU } },
};

#define urtwm_lookup(v, p)	\
	((const struct urtwm_type *)usb_lookup(urtwm_devs, v, p))

int
urtwm_match(struct device *parent, void *match, void *aux)
{
	struct usb_attach_arg *uaa = aux;

	if (uaa->iface == NULL || uaa->configno != 1)
		return (UMATCH_NONE);

	return ((urtwm_lookup(uaa->vendor, uaa->product) != NULL) ?
	    UMATCH_VENDOR_PRODUCT_CONF_IFACE : UMATCH_NONE);
}

void
urtwm_attach(struct device *parent, struct device *self, void *aux)
{
}

int
urtwm_detach(struct device *self, int flags)
{
	return (0);
}
