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

#include <dev/ic/rtw88reg.h>

/* -------------------------------------------------------------------------- */

#define	BIT(x)	(1 << (x))

/* -------------------------------------------------------------------------- */

struct rtw_chip_info {
//	struct rtw_chip_ops *ops;
//	uint8_t id;
//
//	const char *fw_name;
//	enum rtw_wlan_cpu wlan_cpu;
//	uint8_t tx_pkt_desc_sz;
//	uint8_t tx_buf_desc_sz;
//	uint8_t rx_pkt_desc_sz;
//	uint8_t rx_buf_desc_sz;
	uint32_t phy_efuse_size;
	uint32_t log_efuse_size;
	uint32_t ptct_efuse_size;
//	uint32_t txff_size;
//	uint32_t rxff_size;
//	uint32_t fw_rxff_size;
//	uint16_t rsvd_drv_pg_num;
//	uint8_t band;
//	uint8_t page_size;
//	uint8_t csi_buf_pg_num;
//	uint8_t dig_max;
//	uint8_t dig_min;
//	uint8_t txgi_factor;
//	bool is_pwr_by_rate_dec;
//	bool rx_ldpc;
//	bool tx_stbc;
//	uint8_t max_power_index;
//	uint8_t ampdu_density;
//
//	uint16_t fw_fifo_addr[RTW_FW_FIFO_MAX];
//	const struct rtw_fwcd_segs *fwcd_segs;
//
//	uint8_t default_1ss_tx_path;
//
//	bool path_div_supported;
//	bool ht_supported;
//	bool vht_supported;
//	uint8_t lps_deep_mode_supported;
//
//	/* init values */
//	uint8_t sys_func_en;
//	const struct rtw_pwr_seq_cmd **pwr_on_seq;
//	const struct rtw_pwr_seq_cmd **pwr_off_seq;
//	const struct rtw_rqpn *rqpn_table;
//	const struct rtw_prioq_addrs *prioq_addrs;
//	const struct rtw_page_table *page_table;
//	const struct rtw_intf_phy_para_table *intf_table;
//
//	const struct rtw_hw_reg *dig;
//	const struct rtw_hw_reg *dig_cck;
//	uint32_t rf_base_addr[2];
//	uint32_t rf_sipi_addr[2];
//	const struct rtw_rf_sipi_addr *rf_sipi_read_addr;
	uint8_t fix_rf_phy_num;
//	const struct rtw_ltecoex_addr *ltecoex_addr;
//
//	const struct rtw_table *mac_tbl;
//	const struct rtw_table *agc_tbl;
//	const struct rtw_table *bb_tbl;
//	const struct rtw_table *rf_tbl[RTW_RF_PATH_MAX];
//	const struct rtw_table *rfk_init_tbl;
//
//	const struct rtw_rfe_def *rfe_defs;
//	uint32_t rfe_defs_size;
//
//	bool en_dis_dpd;
//	uint16_t dpd_ratemask;
//	uint8_t iqk_threshold;
//	uint8_t lck_threshold;
//	const struct rtw_pwr_track_tbl *pwr_track_tbl;
//
//	uint8_t bfer_su_max_num;
//	uint8_t bfer_mu_max_num;
//
//	struct rtw_hw_reg_offset *edcca_th;
//	s8 l2h_th_ini_cs;
//	s8 l2h_th_ini_ad;
//
//	const char *wow_fw_name;
//	const struct wiphy_wowlan_support *wowlan_stub;
//	const uint8_t max_sched_scan_ssids;
//	const uint16_t max_scan_ie_len;
//
//	/* coex paras */
//	uint32_t coex_para_ver;
//	uint8_t bt_desired_ver;
//	bool scbd_support;
//	bool new_scbd10_def; /* true: fix 2M(8822c) */
//	bool ble_hid_profile_support;
//	bool wl_mimo_ps_support;
//	uint8_t pstdma_type; /* 0: LPSoff, 1:LPSon */
//	uint8_t bt_rssi_type;
//	uint8_t ant_isolation;
//	uint8_t rssi_tolerance;
//	uint8_t table_sant_num;
//	uint8_t table_nsant_num;
//	uint8_t tdma_sant_num;
//	uint8_t tdma_nsant_num;
//	uint8_t bt_afh_span_bw20;
//	uint8_t bt_afh_span_bw40;
//	uint8_t afh_5g_num;
//	uint8_t wl_rf_para_num;
//	uint8_t coex_info_hw_regs_num;
//	const uint8_t *bt_rssi_step;
//	const uint8_t *wl_rssi_step;
//	const struct coex_table_para *table_nsant;
//	const struct coex_table_para *table_sant;
//	const struct coex_tdma_para *tdma_sant;
//	const struct coex_tdma_para *tdma_nsant;
//	const struct coex_rf_para *wl_rf_para_tx;
//	const struct coex_rf_para *wl_rf_para_rx;
//	const struct coex_5g_afh_map *afh_5g;
//	const struct rtw_hw_reg *btg_reg;
//	const struct rtw_reg_domain *coex_info_hw_regs;
//	uint32_t wl_fw_desired_ver;
};

const struct rtw_chip_info rtw8822b_hw_spec = {
//	.ops = &rtw8822b_ops,
//	.id = RTW_CHIP_TYPE_8822B,
//	.fw_name = "rtw88/rtw8822b_fw.bin",
//	.wlan_cpu = RTW_WCPU_11AC,
//	.tx_pkt_desc_sz = 48,
//	.tx_buf_desc_sz = 16,
//	.rx_pkt_desc_sz = 24,
//	.rx_buf_desc_sz = 8,
	.phy_efuse_size = 1024,
	.log_efuse_size = 768,
	.ptct_efuse_size = 96,
//	.txff_size = 262144,
//	.rxff_size = 24576,
//	.fw_rxff_size = 12288,
//	.rsvd_drv_pg_num = 8,
//	.txgi_factor = 1,
//	.is_pwr_by_rate_dec = true,
//	.max_power_index = 0x3f,
//	.csi_buf_pg_num = 0,
//	.band = RTW_BAND_2G | RTW_BAND_5G,
//	.page_size = TX_PAGE_SIZE,
//	.dig_min = 0x1c,
//	.ht_supported = true,
//	.vht_supported = true,
//	.lps_deep_mode_supported = BIT(LPS_DEEP_MODE_LCLK),
//	.sys_func_en = 0xDC,
//	.pwr_on_seq = card_enable_flow_8822b,
//	.pwr_off_seq = card_disable_flow_8822b,
//	.page_table = page_table_8822b,
//	.rqpn_table = rqpn_table_8822b,
//	.prioq_addrs = &prioq_addrs_8822b,
//	.intf_table = &phy_para_table_8822b,
//	.dig = rtw8822b_dig,
//	.dig_cck = NULL,
//	.rf_base_addr = {0x2800, 0x2c00},
//	.rf_sipi_addr = {0xc90, 0xe90},
//	.ltecoex_addr = &rtw8822b_ltecoex_addr,
//	.mac_tbl = &rtw8822b_mac_tbl,
//	.agc_tbl = &rtw8822b_agc_tbl,
//	.bb_tbl = &rtw8822b_bb_tbl,
//	.rf_tbl = {&rtw8822b_rf_a_tbl, &rtw8822b_rf_b_tbl},
//	.rfe_defs = rtw8822b_rfe_defs,
//	.rfe_defs_size = ARRAY_SIZE(rtw8822b_rfe_defs),
//	.pwr_track_tbl = &rtw8822b_rtw_pwr_track_tbl,
//	.iqk_threshold = 8,
//	.bfer_su_max_num = 2,
//	.bfer_mu_max_num = 1,
//	.rx_ldpc = true,
//	.edcca_th = rtw8822b_edcca_th,
//	.l2h_th_ini_cs = 10 + EDCCA_IGI_BASE,
//	.l2h_th_ini_ad = -14 + EDCCA_IGI_BASE,
//	.ampdu_density = IEEE80211_HT_MPDU_DENSITY_2,
//	.max_scan_ie_len = IEEE80211_MAX_DATA_LEN,
//
//	.coex_para_ver = 0x20070206,
//	.bt_desired_ver = 0x6,
//	.scbd_support = true,
//	.new_scbd10_def = false,
//	.ble_hid_profile_support = false,
//	.wl_mimo_ps_support = false,
//	.pstdma_type = COEX_PSTDMA_FORCE_LPSOFF,
//	.bt_rssi_type = COEX_BTRSSI_RATIO,
//	.ant_isolation = 15,
//	.rssi_tolerance = 2,
//	.wl_rssi_step = wl_rssi_step_8822b,
//	.bt_rssi_step = bt_rssi_step_8822b,
//	.table_sant_num = ARRAY_SIZE(table_sant_8822b),
//	.table_sant = table_sant_8822b,
//	.table_nsant_num = ARRAY_SIZE(table_nsant_8822b),
//	.table_nsant = table_nsant_8822b,
//	.tdma_sant_num = ARRAY_SIZE(tdma_sant_8822b),
//	.tdma_sant = tdma_sant_8822b,
//	.tdma_nsant_num = ARRAY_SIZE(tdma_nsant_8822b),
//	.tdma_nsant = tdma_nsant_8822b,
//	.wl_rf_para_num = ARRAY_SIZE(rf_para_tx_8822b),
//	.wl_rf_para_tx = rf_para_tx_8822b,
//	.wl_rf_para_rx = rf_para_rx_8822b,
//	.bt_afh_span_bw20 = 0x24,
//	.bt_afh_span_bw40 = 0x36,
//	.afh_5g_num = ARRAY_SIZE(afh_5g_8822b),
//	.afh_5g = afh_5g_8822b,
//
//	.coex_info_hw_regs_num = ARRAY_SIZE(coex_info_hw_regs_8822b),
//	.coex_info_hw_regs = coex_info_hw_regs_8822b,
//
//	.fw_fifo_addr = {0x780, 0x700, 0x780, 0x660, 0x650, 0x680},
};

enum rtw_bb_path {
	BB_PATH_A = BIT(0),
	BB_PATH_B = BIT(1),
	BB_PATH_C = BIT(2),
	BB_PATH_D = BIT(3),

	BB_PATH_AB = (BB_PATH_A | BB_PATH_B),
	BB_PATH_AC = (BB_PATH_A | BB_PATH_C),
	BB_PATH_AD = (BB_PATH_A | BB_PATH_D),
	BB_PATH_BC = (BB_PATH_B | BB_PATH_C),
	BB_PATH_BD = (BB_PATH_B | BB_PATH_D),
	BB_PATH_CD = (BB_PATH_C | BB_PATH_D),

	BB_PATH_ABC = (BB_PATH_A | BB_PATH_B | BB_PATH_C),
	BB_PATH_ABD = (BB_PATH_A | BB_PATH_B | BB_PATH_D),
	BB_PATH_ACD = (BB_PATH_A | BB_PATH_C | BB_PATH_D),
	BB_PATH_BCD = (BB_PATH_B | BB_PATH_C | BB_PATH_D),

	BB_PATH_ABCD = (BB_PATH_A | BB_PATH_B | BB_PATH_C | BB_PATH_D),
};

enum rtw_rf_type {
	RF_1T1R			= 0,
	RF_1T2R			= 1,
	RF_2T2R			= 2,
	RF_2T3R			= 3,
	RF_2T4R			= 4,
	RF_3T3R			= 5,
	RF_3T4R			= 6,
	RF_4T4R			= 7,
	RF_TYPE_MAX,
};

struct rtw_efuse {
	uint32_t size;
	uint32_t physical_size;
	uint32_t logical_size;
	uint32_t protect_size;
//
//	uint8_t addr[ETH_ALEN];
//	uint8_t channel_plan;
//	uint8_t country_code[2];
//	uint8_t rf_board_option;
//	uint8_t rfe_option;
//	uint8_t power_track_type;
//	uint8_t thermal_meter[RTW_RF_PATH_MAX];
//	uint8_t thermal_meter_k;
//	uint8_t crystal_cap;
//	uint8_t ant_div_cfg;
//	uint8_t ant_div_type;
//	uint8_t regd;
//	uint8_t afe;
//
//	uint8_t lna_type_2g;
//	uint8_t lna_type_5g;
//	uint8_t glna_type;
//	uint8_t alna_type;
//	bool ext_lna_2g;
//	bool ext_lna_5g;
//	uint8_t pa_type_2g;
//	uint8_t pa_type_5g;
//	uint8_t gpa_type;
//	uint8_t apa_type;
//	bool ext_pa_2g;
//	bool ext_pa_5g;
//	uint8_t tx_bb_swing_setting_2g;
//	uint8_t tx_bb_swing_setting_5g;
//
//	bool btcoex;
//	/* bt share antenna with wifi */
//	bool share_ant;
//	uint8_t bt_setting;
//
//	struct {
//		uint8_t hci;
//		uint8_t bw;
//		uint8_t ptcl;
//		uint8_t nss;
//		uint8_t ant_num;
//	} hw_cap;
//
//	struct rtw_txpwr_idx txpwr_idx_table[4];
};

enum rtw_hci_type {
	RTW_HCI_TYPE_PCIE,
	RTW_HCI_TYPE_USB,
	RTW_HCI_TYPE_SDIO,

	RTW_HCI_TYPE_UNDEFINE,
};

struct rtw_hci {
//	struct rtw_hci_ops *ops;
//	enum rtw_hci_type type;
//
	uint32_t rpwm_addr;
	uint32_t cpwm_addr;
//
//	uint8_t bulkout_num;
};

struct rtw_hal {
	uint32_t rcr;
//
	uint32_t chip_version;
	uint32_t cut_version;
	uint8_t mp_chip;
//	uint8_t oem_id;
//	uint8_t pkg_type;
//	struct rtw_phy_cond phy_cond;
//	bool rfe_btg;
//
//	uint8_t ps_mode;
//	uint8_t current_channel;
//	uint8_t current_primary_channel_index;
//	uint8_t current_band_width;
//	uint8_t current_band_type;
//	uint8_t primary_channel;
//
//	/* center channel for different available bandwidth,
//	 * val of (bw > current_band_width) is invalid
//	 */
//	uint8_t cch_by_bw[RTW_MAX_CHANNEL_WIDTH + 1];
//
//	uint8_t sec_ch_offset;
	uint8_t rf_type;
	uint8_t rf_path_num;
	uint8_t rf_phy_num;
	uint32_t antenna_tx;
	uint32_t antenna_rx;
	uint8_t bfee_sts_cap;
//	bool txrx_1ss;
//
//	/* protect tx power section */
//	struct mutex tx_power_mutex;
//	s8 tx_pwr_by_rate_offset_2g[RTW_RF_PATH_MAX]
//				   [DESC_RATE_MAX];
//	s8 tx_pwr_by_rate_offset_5g[RTW_RF_PATH_MAX]
//				   [DESC_RATE_MAX];
//	s8 tx_pwr_by_rate_base_2g[RTW_RF_PATH_MAX]
//				 [RTW_RATE_SECTION_MAX];
//	s8 tx_pwr_by_rate_base_5g[RTW_RF_PATH_MAX]
//				 [RTW_RATE_SECTION_MAX];
//	s8 tx_pwr_limit_2g[RTW_REGD_MAX]
//			  [RTW_CHANNEL_WIDTH_MAX]
//			  [RTW_RATE_SECTION_MAX]
//			  [RTW_MAX_CHANNEL_NUM_2G];
//	s8 tx_pwr_limit_5g[RTW_REGD_MAX]
//			  [RTW_CHANNEL_WIDTH_MAX]
//			  [RTW_RATE_SECTION_MAX]
//			  [RTW_MAX_CHANNEL_NUM_5G];
//	s8 tx_pwr_tbl[RTW_RF_PATH_MAX]
//		     [DESC_RATE_MAX];
//
//	enum rtw_sar_bands sar_band;
//	struct rtw_sar sar;
//
//	/* for 8821c set channel */
//	uint32_t ch_param[3];
};

struct rtw_dev {
//	struct ieee80211_hw *hw;
//	struct device *dev;
//
	struct rtw_hci hci;
//
//	struct rtw_hw_scan_info scan_info;
	const struct rtw_chip_info *chip;
	struct rtw_hal hal;
//	struct rtw_fifo_conf fifo;
//	struct rtw_fw_state fw;
	struct rtw_efuse efuse;
//	struct rtw_sec_desc sec;
//	struct rtw_traffic_stats stats;
//	struct rtw_regd regd;
//	struct rtw_bf_info bf_info;
//
//	struct rtw_dm_info dm_info;
//	struct rtw_coex coex;
//
//	/* ensures exclusive access from mac80211 callbacks */
//	struct mutex mutex;
//
//	/* watch dog every 2 sec */
//	struct delayed_work watch_dog_work;
//	uint32_t watch_dog_cnt;
//
//	struct list_head rsvd_page_list;
//
//	/* c2h cmd queue & handler work */
//	struct sk_buff_head c2h_queue;
//	struct work_struct c2h_work;
//	struct work_struct ips_work;
//	struct work_struct fw_recovery_work;
//	struct work_struct update_beacon_work;
//
//	/* used to protect txqs list */
//	spinlock_t txq_lock;
//	struct list_head txqs;
//	struct workqueue_struct *tx_wq;
//	struct work_struct tx_work;
//	struct work_struct ba_work;
//
//	struct rtw_tx_report tx_report;
//
//	struct {
//		/* indicate the mail box to use with fw */
//		uint8_t last_box_num;
//		uint32_t seq;
//	} h2c;
//
//	/* lps power state & handler work */
//	struct rtw_lps_conf lps_conf;
//	bool ps_enabled;
//	bool beacon_loss;
//	struct completion lps_leave_check;
//
//	struct dentry *debugfs;
//
//	uint8_t sta_cnt;
//	uint32_t rts_threshold;
//
//	DECLARE_BITMAP(hw_port, RTW_PORT_NUM);
//	DECLARE_BITMAP(mac_id_map, RTW_MAX_MAC_ID_NUM);
//	DECLARE_BITMAP(flags, NUM_OF_RTW_FLAGS);
//
//	uint8_t mp_mode;
//	struct rtw_path_div dm_path_div;
//
//	struct rtw_fw_state wow_fw;
//	struct rtw_wow_param wow;
//
//	bool need_rfk;
//	struct completion fw_scan_density;
//	bool ap_active;
//
//	/* hci related data, must be last */
//	uint8_t priv[] __aligned(sizeof(void *));
};

struct urtwm_softc {
	struct device			*sc_pdev;
	struct ieee80211com		sc_ic;

	struct usbd_device		*sc_udev;
	struct usbd_interface		*sc_iface;
	struct usb_task			sc_task;

	struct rtw_dev			rtw_dev;

	/* from rtw_hci */
//	uint32_t			rpwm_addr;
//	uint32_t			cpwm_addr;

	/* from rtw_hal */
//	uint32_t			chip_version;
};

/* -------------------------------------------------------------------------- */

int urtwm_match(struct device *, void *, void *);
void urtwm_attach(struct device *, struct device *, void *);
int urtwm_detach(struct device *, int);

int
urtwm_read_region_1(struct urtwm_softc *sc, uint16_t addr, uint8_t *buf,
    int len)
{
#define	RTW88_REQ_REGS 0x5
	usb_device_request_t req;

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = RTW88_REQ_REGS;
	USETW(req.wValue, addr);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);
	return (usbd_do_request(sc->sc_udev, &req, buf));
}

uint8_t
urtwm_read_1(void *cookie, uint16_t addr)
{
	struct urtwm_softc *sc = cookie;
	uint8_t val;

	if (urtwm_read_region_1(sc, addr, &val, 1) != 0)
		return (0xff);
	return (val);
}

uint16_t
urtwm_read_2(void *cookie, uint16_t addr)
{
	struct urtwm_softc *sc = cookie;
	uint16_t val;

	if (urtwm_read_region_1(sc, addr, (uint8_t *)&val, 2) != 0)
		return (0xffff);
	return (letoh16(val));
}

uint32_t
urtwm_read_4(void *cookie, uint16_t addr)
{
	struct urtwm_softc *sc = cookie;
	uint32_t val;

	if (urtwm_read_region_1(sc, addr, (uint8_t *)&val, 4) != 0)
		return (0xffffffff);
	return (letoh32(val));
}

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
urtwm_task(void *arg)
{
}

int
urtwm_chip_parameter_setup(struct urtwm_softc *sc)
{
	struct rtw_dev *rtwdev = &sc->rtw_dev;
	const struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_hal *hal = &rtwdev->hal;
	struct rtw_efuse *efuse = &rtwdev->efuse;

	// TODO check for hal type
	rtwdev->hci.rpwm_addr = 0xfe58;
	rtwdev->hci.cpwm_addr = 0xfe57;

	hal->chip_version = urtwm_read_4(sc, RTW88_REG_SYS_CFG1);
	printf("%s: chip_version=%i\n", __func__, hal->chip_version);
	hal->cut_version = RTW88_BIT_GET_CHIP_VER(hal->chip_version);
	hal->mp_chip = (hal->chip_version & RTW88_BIT_RTL_ID) ? 0 : 1;

	if (hal->chip_version & RTW88_BIT_RF_TYPE_ID) {
		hal->rf_type = RF_2T2R;
		hal->rf_path_num = 2;
		hal->antenna_tx = BB_PATH_AB;
		hal->antenna_rx = BB_PATH_AB;
	} else {
		hal->rf_type = RF_1T1R;
		hal->rf_path_num = 1;
		hal->antenna_tx = BB_PATH_A;
		hal->antenna_rx = BB_PATH_A;
	}
	hal->rf_phy_num = chip->fix_rf_phy_num ? chip->fix_rf_phy_num :
			  hal->rf_path_num;

	efuse->physical_size = chip->phy_efuse_size;
	efuse->logical_size = chip->log_efuse_size;
	efuse->protect_size = chip->ptct_efuse_size;

	/* default use ack */
	rtwdev->hal.rcr |= RTW88_BIT_VHT_DACK;

	hal->bfee_sts_cap = 3;

	return 0;
}

void
urtwm_attach(struct device *parent, struct device *self, void *aux)
{
	struct urtwm_softc *sc = (struct urtwm_softc *)self;
	struct rtw_dev *rtwdev = &sc->rtw_dev;
	struct usb_attach_arg *uaa = aux;

	sc->sc_udev = uaa->device;
	sc->sc_iface = uaa->iface;

	rtwdev->chip = &rtw8822b_hw_spec;

	usb_init_task(&sc->sc_task, urtwm_task, sc, USB_TASK_TYPE_GENERIC);

	urtwm_chip_parameter_setup(sc);
}

int
urtwm_detach(struct device *self, int flags)
{
	return (0);
}
