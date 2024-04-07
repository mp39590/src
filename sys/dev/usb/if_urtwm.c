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
#define clear_bit(i, a) ((a)) &= ~(1 << (i))
#define set_bit(i, a) ((a)) |= (1 << (i))

#define BITS_TO_LONGS(x)	howmany((x), 8 * sizeof(long))
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#define cut_version_to_mask(cut) (0x1 << ((cut) + 1))

/* -------------------------------------------------------------------------- */

enum rtw_c2h_cmd_id {
	RTW88_C2H_CCX_TX_RPT = 0x03,
	RTW88_C2H_BT_INFO = 0x09,
	RTW88_C2H_BT_MP_INFO = 0x0b,
	RTW88_C2H_BT_HID_INFO = 0x45,
	RTW88_C2H_RA_RPT = 0x0c,
	RTW88_C2H_HW_FEATURE_REPORT = 0x19,
	RTW88_C2H_WLAN_INFO = 0x27,
	RTW88_C2H_WLAN_RFON = 0x32,
	RTW88_C2H_BCN_FILTER_NOTIFY = 0x36,
	RTW88_C2H_ADAPTIVITY = 0x37,
	RTW88_C2H_SCAN_RESULT = 0x38,
	RTW88_C2H_HW_FEATURE_DUMP = 0xfd,
	RTW88_C2H_HALMAC = 0xff,
};

enum rtw88_wlan_cpu {
	RTW88_WCPU_11AC,
	RTW88_WCPU_11N,
};

enum rtw_flags {
	RTW88_RTW_FLAG_RUNNING,
	RTW88_RTW_FLAG_FW_RUNNING,
	RTW88_RTW_FLAG_SCANNING,
	RTW88_RTW_FLAG_POWERON,
	RTW88_RTW_FLAG_LEISURE_PS,
	RTW88_RTW_FLAG_LEISURE_PS_DEEP,
	RTW88_RTW_FLAG_DIG_DISABLE,
	RTW88_RTW_FLAG_BUSY_TRAFFIC,
	RTW88_RTW_FLAG_WOWLAN,
	RTW88_RTW_FLAG_RESTARTING,
	RTW88_RTW_FLAG_RESTART_TRIGGERING,
	RTW88_RTW_FLAG_FORCE_LOWEST_RATE,

	NUM_OF_RTW_FLAGS,
};

struct rtw88_pwr_seq_cmd {
	uint16_t offset;
	uint8_t cut_mask;
	uint8_t intf_mask;
	uint8_t base:4;
	uint8_t cmd:4;
	uint8_t mask;
	uint8_t value;
};


struct rtw88_chip_info {
//	struct rtw_chip_ops *ops;
//	uint8_t id;
//
	const char *fw_name;
	enum rtw88_wlan_cpu wlan_cpu;
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
	uint8_t sys_func_en;
	const struct rtw88_pwr_seq_cmd **pwr_on_seq;
	const struct rtw88_pwr_seq_cmd **pwr_off_seq;
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

#define RTW88_RTW_PWR_POLLING_CNT	20000

#define RTW88_RTW_PWR_CMD_READ	0x00
#define RTW88_RTW_PWR_CMD_WRITE	0x01
#define RTW88_RTW_PWR_CMD_POLLING	0x02
#define RTW88_RTW_PWR_CMD_DELAY	0x03
#define RTW88_RTW_PWR_CMD_END		0x04

/* define the base address of each block */
#define RTW88_RTW_PWR_ADDR_MAC	0x00
#define RTW88_RTW_PWR_ADDR_USB	0x01
#define RTW88_RTW_PWR_ADDR_PCIE	0x02
#define RTW88_RTW_PWR_ADDR_SDIO	0x03

#define RTW88_RTW_PWR_INTF_SDIO_MSK	BIT(0)
#define RTW88_RTW_PWR_INTF_USB_MSK	BIT(1)
#define RTW88_RTW_PWR_INTF_PCI_MSK	BIT(2)
#define RTW88_RTW_PWR_INTF_ALL_MSK	(BIT(0) | BIT(1) | BIT(2) | BIT(3))

#define RTW88_RTW_PWR_CUT_TEST_MSK	BIT(0)
#define RTW88_RTW_PWR_CUT_A_MSK	BIT(1)
#define RTW88_RTW_PWR_CUT_B_MSK	BIT(2)
#define RTW88_RTW_PWR_CUT_C_MSK	BIT(3)
#define RTW88_RTW_PWR_CUT_D_MSK	BIT(4)
#define RTW88_RTW_PWR_CUT_E_MSK	BIT(5)
#define RTW88_RTW_PWR_CUT_F_MSK	BIT(6)
#define RTW88_RTW_PWR_CUT_G_MSK	BIT(7)
#define RTW88_RTW_PWR_CUT_ALL_MSK	0xFF

enum rtw88_pwr_seq_cmd_delay_unit {
	RTW88_RTW_PWR_DELAY_US,
	RTW88_RTW_PWR_DELAY_MS,
};

const struct rtw88_pwr_seq_cmd trans_carddis_to_cardemu_8822b[] = {
	{0x0086,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), 0},
	{0x0086,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_POLLING, BIT(1), BIT(1)},
	{0x004A,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), 0},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(3) | BIT(4) | BIT(7), 0},
	{0x0300,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_PCI_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0},
	{0x0301,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_PCI_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0},
	{0xFFFF,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 0,
	 RTW88_RTW_PWR_CMD_END, 0, 0},
};

const struct rtw88_pwr_seq_cmd trans_cardemu_to_act_8822b[] = {
	{0x0012,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(1), 0},
	{0x0012,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0020,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK | RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0001,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK | RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_DELAY, 1, RTW88_RTW_PWR_DELAY_MS},
	{0x0000,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK | RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(5), 0},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, (BIT(4) | BIT(3) | BIT(2)), 0},
	{0x0075,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_PCI_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0006,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_POLLING, BIT(1), BIT(1)},
	{0x0075,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_PCI_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), 0},
	{0xFF1A,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0},
	{0x0006,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(7), 0},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, (BIT(4) | BIT(3)), 0},
	{0x10C3,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_POLLING, BIT(0), 0},
	{0x0020,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(3), BIT(3)},
	{0x10A8,
	 RTW88_RTW_PWR_CUT_C_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0},
	{0x10A9,
	 RTW88_RTW_PWR_CUT_C_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0xef},
	{0x10AA,
	 RTW88_RTW_PWR_CUT_C_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0x0c},
	{0x0068,
	 RTW88_RTW_PWR_CUT_C_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(4), BIT(4)},
	{0x0029,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0xF9},
	{0x0024,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(2), 0},
	{0x0074,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_PCI_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(5), BIT(5)},
	{0x00AF,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(5), BIT(5)},
	{0xFFFF,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 0,
	 RTW88_RTW_PWR_CMD_END, 0, 0},
};

const struct rtw88_pwr_seq_cmd trans_act_to_cardemu_8822b[] = {
	{0x0003,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(2), 0},
	{0x0093,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(3), 0},
	{0x001F,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0},
	{0x00EF,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0},
	{0xFF1A,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0x30},
	{0x0049,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(1), 0},
	{0x0006,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0002,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(1), 0},
	{0x10C3,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), 0},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(1), BIT(1)},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_POLLING, BIT(1), 0},
	{0x0020,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(3), 0},
	{0x0000,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK | RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(5), BIT(5)},
	{0xFFFF,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 0,
	 RTW88_RTW_PWR_CMD_END, 0, 0},
};

const struct rtw88_pwr_seq_cmd trans_cardemu_to_carddis_8822b[] = {
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(7), BIT(7)},
	{0x0007,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK | RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0x20},
	{0x0067,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(5), 0},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_PCI_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(2), BIT(2)},
	{0x004A,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), 0},
	{0x0067,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(5), 0},
	{0x0067,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(4), 0},
	{0x004F,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), 0},
	{0x0067,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(1), 0},
	{0x0046,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(6), BIT(6)},
	{0x0067,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(2), 0},
	{0x0046,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(7), BIT(7)},
	{0x0062,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(4), BIT(4)},
	{0x0081,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(7) | BIT(6), 0},
	{0x0005,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK | RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(3) | BIT(4), BIT(3)},
	{0x0086,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(0), BIT(0)},
	{0x0086,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_POLLING, BIT(1), 0},
	{0x0090,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_USB_MSK | RTW88_RTW_PWR_INTF_PCI_MSK,
	 RTW88_RTW_PWR_ADDR_MAC,
	 RTW88_RTW_PWR_CMD_WRITE, BIT(1), 0},
	{0x0044,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0},
	{0x0040,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0x90},
	{0x0041,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0x00},
	{0x0042,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_SDIO_MSK,
	 RTW88_RTW_PWR_ADDR_SDIO,
	 RTW88_RTW_PWR_CMD_WRITE, 0xFF, 0x04},
	{0xFFFF,
	 RTW88_RTW_PWR_CUT_ALL_MSK,
	 RTW88_RTW_PWR_INTF_ALL_MSK,
	 0,
	 RTW88_RTW_PWR_CMD_END, 0, 0},
};

const struct rtw88_pwr_seq_cmd *card_enable_flow_8822b[] = {
	trans_carddis_to_cardemu_8822b,
	trans_cardemu_to_act_8822b,
	NULL
};

const struct rtw88_pwr_seq_cmd *card_disable_flow_8822b[] = {
	trans_act_to_cardemu_8822b,
	trans_cardemu_to_carddis_8822b,
	NULL
};


const struct rtw88_chip_info rtw8822b_hw_spec = {
//	.ops = &rtw8822b_ops,
//	.id = RTW_CHIP_TYPE_8822B,
	.fw_name = "rtw88/rtw8822b_fw.bin",
	.wlan_cpu = RTW88_WCPU_11AC,
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
	.sys_func_en = 0xDC,
	.pwr_on_seq = card_enable_flow_8822b,
	.pwr_off_seq = card_disable_flow_8822b,
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

struct rtw88_efuse {
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

enum rtw88_hci_type {
	RTW88_HCI_TYPE_PCIE,
	RTW88_HCI_TYPE_USB,
	RTW88_HCI_TYPE_SDIO,

	RTW88_HCI_TYPE_UNDEFINE,
};

struct urtwm_softc;
struct rtw88_dev;

/* ops for PCI, USB and SDIO */
struct rtw88_hci_ops {
//	int (*tx_write)(struct rtw88_dev *rtwdev,
//	    struct rtw88_tx_pkt_info *pkt_info,
//	    struct sk_buff *skb);
//	void (*tx_kick_off)(struct rtw88_dev *rtwdev);
//	void (*flush_queues)(struct rtw88_dev *rtwdev, u32 queues, bool drop);
	int (*setup)(struct rtw88_dev *rtwdev);
//	int (*start)(struct rtw88_dev *rtwdev);
//	void (*stop)(struct rtw88_dev *rtwdev);
//	void (*deep_ps)(struct rtw88_dev *rtwdev, bool enter);
//	void (*link_ps)(struct rtw88_dev *rtwdev, bool enter);
//	void (*interface_cfg)(struct rtw88_dev *rtwdev);
//
//	int (*write_data_rsvd_page)(struct rtw88_dev *rtwdev, u8 *buf, u32 size);
//	int (*write_data_h2c)(struct rtw88_dev *rtwdev, u8 *buf, u32 size);

	uint8_t (*read8)(struct rtw88_dev *rtwdev, uint16_t addr);
	uint16_t (*read16)(struct rtw88_dev *rtwdev, uint16_t addr);
	uint32_t (*read32)(struct rtw88_dev *rtwdev, uint16_t addr);
	int (*write8)(struct rtw88_dev *rtwdev, uint16_t addr, uint8_t val);
	int (*write16)(struct rtw88_dev *rtwdev, uint16_t addr, uint16_t val);
	int (*write32)(struct rtw88_dev *rtwdev, uint16_t addr, uint32_t val);
};



struct rtw88_hci {
	struct rtw88_hci_ops *ops;
	enum rtw88_hci_type type;
//
	uint32_t rpwm_addr;
	uint32_t cpwm_addr;
//
//	uint8_t bulkout_num;
};

struct rtw88_hal {
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

struct rtw_fw_state {
//	const struct firmware *firmware;
//	struct rtw88_dev *rtwdev;
//	struct completion completion;
//	struct rtw_fwcd_desc fwcd_desc;
//	u16 version;
//	u8 sub_version;
//	u8 sub_index;
//	u16 h2c_version;
//	u32 feature;
//	u32 feature_ext;
//	enum rtw_fw_type type;
	u_char *fwdata;
	size_t fwsize;
};


struct rtw88_dev {
//	struct ieee80211_hw *hw;
//	struct device *dev;
//
	struct rtw88_hci hci;
	void	*cookie;
//
//	struct rtw_hw_scan_info scan_info;
	const struct rtw88_chip_info *chip;
	struct rtw88_hal hal;
//	struct rtw_fifo_conf fifo;
	struct rtw_fw_state fw;
	struct rtw88_efuse efuse;
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
	// TODO - used to be DECLARE_BITMAP
	unsigned long flags;
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

struct rtw88_softc {
	struct rtw88_dev		rtw_dev;
};

struct urtwm_softc {
	struct device			*sc_pdev;
	struct ieee80211com		sc_ic;
	struct rtw88_softc		sc_sc;

	struct usbd_device		*sc_udev;
	struct usbd_interface		*sc_iface;
	struct usb_task			sc_task;
};

/* -------------------------------------------------------------------------- */


inline int rtw88_chip_wcpu_11n(struct rtw88_dev *rtwdev)
{
	return rtwdev->chip->wlan_cpu == RTW88_WCPU_11N;
}

inline int rtw88_chip_wcpu_11ac(struct rtw88_dev *rtwdev)
{
	return rtwdev->chip->wlan_cpu == RTW88_WCPU_11AC;
}


inline enum rtw88_hci_type rtw88_hci_type(struct rtw88_dev *rtwdev)
{
	return rtwdev->hci.type;
}

uint8_t
rtw88_read8(struct rtw88_dev *rtwdev, uint32_t addr)
{
	return rtwdev->hci.ops->read8(rtwdev, addr);
}

uint16_t
rtw88_read16(struct rtw88_dev *rtwdev, uint32_t addr)
{
	return rtwdev->hci.ops->read16(rtwdev, addr);
}

uint32_t
rtw88_read32(struct rtw88_dev *rtwdev, uint32_t addr)
{
	return rtwdev->hci.ops->read32(rtwdev, addr);
}

int
rtw88_write8(struct rtw88_dev *rtwdev, uint32_t addr, uint8_t val)
{
	return rtwdev->hci.ops->write8(rtwdev, addr, val);
}

int
rtw88_write16(struct rtw88_dev *rtwdev, uint32_t addr, uint16_t val)
{
	return rtwdev->hci.ops->write16(rtwdev, addr, val);
}

int
rtw88_write32(struct rtw88_dev *rtwdev, uint32_t addr, uint16_t val)
{
	return rtwdev->hci.ops->write32(rtwdev, addr, val);
}

uint32_t urtwm_read_4(struct rtw88_dev *, uint16_t);

int
rtw88_usb_setup(struct rtw88_dev *rtwdev)
{
	/* empty function for rtw_hci_ops */
	return 0;
}

inline void
rtw88_write8_set(struct rtw88_dev *rtwdev, uint32_t addr, uint8_t bit)
{
	uint8_t val;

	val = rtw88_read8(rtwdev, addr);
	rtw88_write8(rtwdev, addr, val | bit);
}

inline void
rtw88_write16_clr(struct rtw88_dev *rtwdev, uint32_t addr, uint16_t bit)
{
        uint16_t val;

        val = rtw88_read16(rtwdev, addr);
        rtw88_write16(rtwdev, addr, val & ~bit);
}


/* -------------------------------------------------------------------------- */

int urtwm_match(struct device *, void *, void *);
void urtwm_attach(struct device *, struct device *, void *);
int urtwm_detach(struct device *, int);

#define	RTW88_REQ_REGS 0x5
#define RTW88_USB_CMD_WRITE 0x40
#define RTW88_USB_CMD_READ 0xc0
int
urtwm_write_region_1(struct urtwm_softc *sc, uint16_t addr, uint8_t *buf,
    int len)
{
	usb_device_request_t req;

	req.bmRequestType = RTW88_USB_CMD_WRITE;
	req.bRequest = RTW88_REQ_REGS;
	USETW(req.wValue, addr);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);
	return (usbd_do_request(sc->sc_udev, &req, buf));
}

int
urtwm_write_8(struct rtw88_dev *rtwdev, uint16_t addr, uint8_t val)
{
	struct urtwm_softc *sc = rtwdev->cookie;

	return urtwm_write_region_1(sc, addr, &val, 1);
}

int
urtwm_write_16(struct rtw88_dev *rtwdev, uint16_t addr, uint16_t val)
{
	struct urtwm_softc *sc = rtwdev->cookie;

	val = htole16(val);
	return urtwm_write_region_1(sc, addr, (uint8_t *)&val, 2);
}

int
urtwm_write_32(struct rtw88_dev *rtwdev, uint16_t addr, uint32_t val)
{
	struct urtwm_softc *sc = rtwdev->cookie;

	val = htole32(val);
	return urtwm_write_region_1(sc, addr, (uint8_t *)&val, 4);
}

int
urtwm_read_region_1(struct urtwm_softc *sc, uint16_t addr, uint8_t *buf,
    int len)
{
	usb_device_request_t req;

	req.bmRequestType = RTW88_USB_CMD_READ;
	req.bRequest = RTW88_REQ_REGS;
	USETW(req.wValue, addr);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);
	return (usbd_do_request(sc->sc_udev, &req, buf));
}

uint8_t
urtwm_read_8(struct rtw88_dev *rtwdev, uint16_t addr)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	uint8_t val;

	if (urtwm_read_region_1(sc, addr, &val, 1) != 0)
		return (0xff);
	return (val);
}

uint16_t
urtwm_read_16(struct rtw88_dev *rtwdev, uint16_t addr)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	uint16_t val;

	if (urtwm_read_region_1(sc, addr, (uint8_t *)&val, 2) != 0)
		return (0xffff);
	return (letoh16(val));
}

uint32_t
urtwm_read_32(struct rtw88_dev *rtwdev, uint16_t addr)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	uint32_t val;

	if (urtwm_read_region_1(sc, addr, (uint8_t *)&val, 4) != 0)
		return (0xffffffff);
	return (letoh32(val));
}

struct rtw88_hci_ops rtw88_usb_ops = {
	.setup = rtw88_usb_setup,
	.write8 = urtwm_write_8,
	.write16 = urtwm_write_16,
	.write32 = urtwm_write_32,
	.read8= urtwm_read_8,
	.read16 = urtwm_read_16,
	.read32 = urtwm_read_32,
};

/* -------------------------------------------------------------------------- */

struct cfdriver urtwm_cd = {
	NULL, "urtwm", DV_IFNET
};

const struct cfattach urtwm_ca = {
	sizeof(struct urtwm_softc), urtwm_match, urtwm_attach, urtwm_detach
};

// XXX: DONT FORGET TO FIX usbdevs.h before submit
static const struct urtwm_type {
	struct usb_devno	dev;
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
rtw88_hci_setup(struct rtw88_dev *rtwdev)
{
	return rtwdev->hci.ops->setup(rtwdev);
}

/* -------------------------------------------------------------------------- */
int
__rtw88_mac_init_system_cfg(struct rtw88_dev *rtwdev)
{
	uint8_t sys_func_en = rtwdev->chip->sys_func_en;
	uint8_t value8;
	uint32_t value, tmp;

	value = rtw88_read32(rtwdev, RTW88_REG_CPU_DMEM_CON);
	value |= RTW88_BIT_WL_PLATFORM_RST | RTW88_BIT_DDMA_EN;
	rtw88_write32(rtwdev, RTW88_REG_CPU_DMEM_CON, value);

	rtw88_write8_set(rtwdev, RTW88_REG_SYS_FUNC_EN + 1, sys_func_en);
	value8 = (rtw88_read8(rtwdev, RTW88_REG_CR_EXT + 3) & 0xF0) | 0x0C;
	rtw88_write8(rtwdev, RTW88_REG_CR_EXT + 3, value8);

	/* disable boot-from-flash for driver's DL FW */
	tmp = rtw88_read32(rtwdev, RTW88_REG_MCUFW_CTRL);
	if (tmp & RTW88_BIT_BOOT_FSPI_EN) {
		rtw88_write32(rtwdev, RTW88_REG_MCUFW_CTRL, tmp & (~RTW88_BIT_BOOT_FSPI_EN));
		value = rtw88_read32(rtwdev, RTW88_REG_GPIO_MUXCFG) & (~RTW88_BIT_FSPI_EN);
		rtw88_write32(rtwdev, RTW88_REG_GPIO_MUXCFG, value);
	}

	return 0;
}

int
__rtw88_mac_init_system_cfg_legacy(struct rtw88_dev *rtwdev)
{
	rtw88_write8(rtwdev, RTW88_REG_CR, 0xff);
	DELAY(2 * 1000);
	rtw88_write8(rtwdev, RTW88_REG_HWSEQ_CTRL, 0x7f);
	DELAY(2 * 1000);

	rtw88_write8_set(rtwdev, RTW88_REG_SYS_CLKR, RTW88_BIT_WAKEPAD_EN);
	rtw88_write16_clr(rtwdev, RTW88_REG_GPIO_MUXCFG, RTW88_BIT_EN_SIC);

	rtw88_write16(rtwdev, RTW88_REG_CR, 0x2ff);

	return 0;
}

int
rtw88_mac_init_system_cfg(struct rtw88_dev *rtwdev)
{
	if (rtw88_chip_wcpu_11n(rtwdev))
		return __rtw88_mac_init_system_cfg_legacy(rtwdev);

	return __rtw88_mac_init_system_cfg(rtwdev);
}

#define RTW88_SDIO_LOCAL_OFFSET			      0x10250000

#define USEC_PER_SEC 1000000L

// TODO: freebsd stuff
void
timevalfix(struct timeval *t1)
{

	if (t1->tv_usec < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
	if (t1->tv_usec >= 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

void
timevaladd(struct timeval *t1, const struct timeval *t2)
{

	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}

#define timevalcmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define read_poll_timeout_atomic(_pollfp, _var, _cond, _us, _to, _early_sleep, ...)	\
({										\
	struct timeval __now, __end;						\
	if (_to) {								\
		__end.tv_sec = (_to) / USEC_PER_SEC;				\
		__end.tv_usec = (_to) % USEC_PER_SEC;				\
		microtime(&__now);						\
		timevaladd(&__end, &__now);					\
	}									\
										\
	if ((_early_sleep) && (_us) > 0)					\
		DELAY(_us);							\
	do {									\
		(_var) = _pollfp(__VA_ARGS__);					\
		if (_cond)							\
			break;							\
		if (_to) {							\
			microtime(&__now);					\
			if (timevalcmp(&__now, &__end, >))			\
				break;						\
		}								\
		if ((_us) != 0)							\
			DELAY(_us);						\
	} while (1);								\
	(_cond) ? 0 : (-ETIMEDOUT);						\
})

int
rtw88_do_pwr_poll_cmd(struct rtw88_dev *rtwdev, uint32_t addr, uint32_t mask,
    uint32_t target)
{
	uint32_t val;

	target &= mask;

	return read_poll_timeout_atomic(rtw88_read8, val, (val & mask) == target,
	    50, 50 * RTW88_RTW_PWR_POLLING_CNT, false,
	    rtwdev, addr) == 0;
}


int
rtw88_pwr_cmd_polling(struct rtw88_dev *rtwdev, const struct rtw88_pwr_seq_cmd *cmd)
{
	struct urtwm_softc *sc = rtwdev->cookie;
//	uint8_t value;
	uint32_t offset;

	if (cmd->base == RTW88_RTW_PWR_ADDR_SDIO)
		offset = cmd->offset | RTW88_SDIO_LOCAL_OFFSET;
	else
		offset = cmd->offset;

	if (rtw88_do_pwr_poll_cmd(rtwdev, offset, cmd->mask, cmd->value))
		return 0;

	if (rtw88_hci_type(rtwdev) != RTW88_HCI_TYPE_PCIE)
		goto err;

//	/* if PCIE, toggle BIT_PFM_WOWL and try again */
//	value = rtw_read8(rtwdev, REG_SYS_PW_CTRL);
//	if (rtwdev->chip->id == RTW_CHIP_TYPE_8723D)
//		rtw_write8(rtwdev, REG_SYS_PW_CTRL, value & ~BIT_PFM_WOWL);
//	rtw_write8(rtwdev, REG_SYS_PW_CTRL, value | BIT_PFM_WOWL);
//	rtw_write8(rtwdev, REG_SYS_PW_CTRL, value & ~BIT_PFM_WOWL);
//	if (rtwdev->chip->id == RTW_CHIP_TYPE_8723D)
//		rtw_write8(rtwdev, REG_SYS_PW_CTRL, value | BIT_PFM_WOWL);
//
//	if (rtw88_do_pwr_poll_cmd(rtwdev, offset, cmd->mask, cmd->value))
//		return 0;

err:
	printf("%s: %s: failed to poll offset=0x%x mask=0x%x value=0x%x\n",
	     sc->sc_pdev->dv_xname, __func__, offset, cmd->mask, cmd->value);
	return EBUSY;
}

int rtw88_sub_pwr_seq_parser(struct rtw88_dev *rtwdev, uint8_t intf_mask,
    uint8_t cut_mask, const struct rtw88_pwr_seq_cmd *cmd)
{
	const struct rtw88_pwr_seq_cmd *cur_cmd;
	uint32_t offset;
	uint8_t value;

	for (cur_cmd = cmd; cur_cmd->cmd != RTW88_RTW_PWR_CMD_END; cur_cmd++) {
		if (!(cur_cmd->intf_mask & intf_mask) ||
		    !(cur_cmd->cut_mask & cut_mask))
			continue;

		switch (cur_cmd->cmd) {
		case RTW88_RTW_PWR_CMD_WRITE:
			offset = cur_cmd->offset;

			if (cur_cmd->base == RTW88_RTW_PWR_ADDR_SDIO)
				offset |= RTW88_SDIO_LOCAL_OFFSET;

			value = rtw88_read8(rtwdev, offset);
			value &= ~cur_cmd->mask;
			value |= (cur_cmd->value & cur_cmd->mask);
			rtw88_write8(rtwdev, offset, value);
			break;
		case RTW88_RTW_PWR_CMD_POLLING:
			if (rtw88_pwr_cmd_polling(rtwdev, cur_cmd))
				return EBUSY;
			break;
		case RTW88_RTW_PWR_CMD_DELAY:
			if (cur_cmd->value == RTW88_RTW_PWR_DELAY_US)
				DELAY(cur_cmd->offset);
			else
				DELAY(cur_cmd->offset * 1000);
			break;
		case RTW88_RTW_PWR_CMD_READ:
			break;
		default:
			return EINVAL;
		}
	}

	return 0;
}

int
rtw88_pwr_seq_parser(struct rtw88_dev *rtwdev,
    const struct rtw88_pwr_seq_cmd **cmd_seq)
{
	const struct rtw88_pwr_seq_cmd *cmd;
	uint8_t cut_mask;
	uint8_t intf_mask;
	uint8_t cut;
	uint32_t idx = 0;
	int ret;

	cut = rtwdev->hal.cut_version;
	cut_mask = cut_version_to_mask(cut);
	switch (rtw88_hci_type(rtwdev)) {
//	case RTW88_HCI_TYPE_PCIE:
//		intf_mask = RTW_PWR_INTF_PCI_MSK;
//		break;
	case RTW88_HCI_TYPE_USB:
		intf_mask = RTW88_RTW_PWR_INTF_USB_MSK;
		break;
//	case RTW88_HCI_TYPE_SDIO:
//		intf_mask = RTW_PWR_INTF_SDIO_MSK;
//		break;
	default:
		return EINVAL;
	}

	do {
		cmd = cmd_seq[idx];
		if (!cmd)
			break;

		ret = rtw88_sub_pwr_seq_parser(rtwdev, intf_mask, cut_mask, cmd);
		if (ret)
			return ret;

		idx++;
	} while (1);

	return 0;
}

int
rtw88_mac_power_switch(struct rtw88_dev *rtwdev, int pwr_on)
{
	const struct rtw88_chip_info *chip = rtwdev->chip;
	const struct rtw88_pwr_seq_cmd **pwr_seq;
//	uint32_t imr = 0;
	uint8_t rpwm;
	bool cur_pwr;
	int ret;

	if (rtw88_chip_wcpu_11ac(rtwdev)) {
		rpwm = rtw88_read8(rtwdev, rtwdev->hci.rpwm_addr);

		/* Check FW still exist or not */
		if (rtw88_read16(rtwdev, RTW88_REG_MCUFW_CTRL) == 0xC078) {
			rpwm = (rpwm ^ RTW88_BIT_RPWM_TOGGLE) & RTW88_BIT_RPWM_TOGGLE;
			rtw88_write8(rtwdev, rtwdev->hci.rpwm_addr, rpwm);
		}
	}

	if (rtw88_read8(rtwdev, RTW88_REG_CR) == 0xea)
		cur_pwr = 0;
	else if (rtw88_hci_type(rtwdev) == RTW88_HCI_TYPE_USB &&
	    (rtw88_read8(rtwdev, RTW88_REG_SYS_STATUS1 + 1) & BIT(0)))
		cur_pwr = 0;
	else
		cur_pwr = 1;

	if (pwr_on == cur_pwr)
		return EALREADY;

	// TODO
//	if (rtw88_hci_type(rtwdev) == RTW88_HCI_TYPE_SDIO) {
//		imr = rtw88_read32(rtwdev, REG_SDIO_HIMR);
//		rtw88_write32(rtwdev, REG_SDIO_HIMR, 0);
//	}

	if (!pwr_on)
		clear_bit(RTW88_RTW_FLAG_POWERON, rtwdev->flags);

	pwr_seq = pwr_on ? chip->pwr_on_seq : chip->pwr_off_seq;
	ret = rtw88_pwr_seq_parser(rtwdev, pwr_seq);

	// TODO
//	if (rtw88_hci_type(rtwdev) == RTW88_HCI_TYPE_SDIO)
//		rtw88_write32(rtwdev, RTW88_RTW_REG_SDIO_HIMR, imr);

	if (!ret && pwr_on)
		set_bit(RTW88_RTW_FLAG_POWERON, rtwdev->flags);

	return ret;
}

int
rtw88_mac_pre_system_cfg(struct rtw88_dev *rtwdev)
{
//	unsigned int retry;
	uint32_t value32;
	uint8_t value8;

	rtw88_write8(rtwdev, RTW88_REG_RSV_CTRL, 0);

	if (rtw88_chip_wcpu_11n(rtwdev)) {
		if (rtw88_read32(rtwdev, RTW88_REG_SYS_CFG1) & RTW88_BIT_LDO)
			rtw88_write8(rtwdev, RTW88_REG_LDO_SWR_CTRL, RTW88_LDO_SEL);
		else
			rtw88_write8(rtwdev, RTW88_REG_LDO_SWR_CTRL, RTW88_SPS_SEL);
		return 0;
	}

	switch (rtw88_hci_type(rtwdev)) {
	// TODO
//	case RTW_HCI_TYPE_PCIE:
//		rtw88_write32_set(rtwdev, RTW88_REG_HCI_OPT_CTRL, BIT_USB_SUS_DIS);
//		break;
//	case RTW_HCI_TYPE_SDIO:
//		rtw88_write8_clr(rtwdev, RTW88_REG_SDIO_HSUS_CTRL, BIT_HCI_SUS_REQ);
//
//		for (retry = 0; retry < RTW_PWR_POLLING_CNT; retry++) {
//			if (rtw88_read8(rtwdev, RTW88_REG_SDIO_HSUS_CTRL) & BIT_HCI_RESUME_RDY)
//				break;
//
//			usleep_range(10, 50);
//		}
//
//		if (retry == RTW_PWR_POLLING_CNT) {
//			rtw_err(rtwdev, "failed to poll RTW88_REG_SDIO_HSUS_CTRL[1]");
//			return -ETIMEDOUT;
//		}
//
//		if (rtw_sdio_is_sdio30_supported(rtwdev))
//			rtw88_write8_set(rtwdev, RTW88_REG_HCI_OPT_CTRL + 2,
//			    BIT_SDIO_PAD_E5 >> 16);
//		else
//			rtw88_write8_clr(rtwdev, RTW88_REG_HCI_OPT_CTRL + 2,
//			    BIT_SDIO_PAD_E5 >> 16);
//		break;
	case RTW88_HCI_TYPE_USB:
		break;
	default:
		return -EINVAL;
	}

	/* config PIN Mux */
	value32 = rtw88_read32(rtwdev, RTW88_REG_PAD_CTRL1);
	value32 |= RTW88_BIT_PAPE_WLBT_SEL | RTW88_BIT_LNAON_WLBT_SEL;
	rtw88_write32(rtwdev, RTW88_REG_PAD_CTRL1, value32);

	value32 = rtw88_read32(rtwdev, RTW88_REG_LED_CFG);
	value32 &= ~(RTW88_BIT_PAPE_SEL_EN | RTW88_BIT_LNAON_SEL_EN);
	rtw88_write32(rtwdev, RTW88_REG_LED_CFG, value32);

	value32 = rtw88_read32(rtwdev, RTW88_REG_GPIO_MUXCFG);
	value32 |= RTW88_BIT_WLRFE_4_5_EN;
	rtw88_write32(rtwdev, RTW88_REG_GPIO_MUXCFG, value32);

	/* disable BB/RF */
	value8 = rtw88_read8(rtwdev, RTW88_REG_SYS_FUNC_EN);
	value8 &= ~(RTW88_BIT_FEN_BB_RSTB | RTW88_BIT_FEN_BB_GLB_RST);
	rtw88_write8(rtwdev, RTW88_REG_SYS_FUNC_EN, value8);

	value8 = rtw88_read8(rtwdev, RTW88_REG_RF_CTRL);
	value8 &= ~(RTW88_BIT_RF_SDM_RSTB | RTW88_BIT_RF_RSTB | RTW88_BIT_RF_EN);
	rtw88_write8(rtwdev, RTW88_REG_RF_CTRL, value8);

	value32 = rtw88_read32(rtwdev, RTW88_REG_WLRF1);
	value32 &= ~RTW88_BIT_WLRF1_BBRF_EN;
	rtw88_write32(rtwdev, RTW88_REG_WLRF1, value32);

	return (0);
}


int
rtw88_mac_power_on(struct rtw88_dev *rtwdev)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	int ret = 0;

	ret = rtw88_mac_pre_system_cfg(rtwdev);
	if (ret)
		goto err;

	ret = rtw88_mac_power_switch(rtwdev, 1);
	if (ret == EALREADY) {
		rtw88_mac_power_switch(rtwdev, false);

		ret = rtw88_mac_pre_system_cfg(rtwdev);
		if (ret)
			goto err;

		ret = rtw88_mac_power_switch(rtwdev, true);
		if (ret)
			goto err;
	} else if (ret) {
		goto err;
	}

	ret = rtw88_mac_init_system_cfg(rtwdev);
	if (ret)
		goto err;

	return 0;

err:
	printf("%s: %s: mac power on failed, error=%i", sc->sc_pdev->dv_xname,
	    __func__, ret);
	return ret;
}


int
rtw88_chip_efuse_enable(struct rtw88_dev *rtwdev)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	struct rtw_fw_state *fw = &rtwdev->fw;
	int ret;

	ret = rtw88_hci_setup(rtwdev);
	if (ret) {
		printf("%s: %s: failed to setup hci, error=%i\n",
		    sc->sc_pdev->dv_xname, __func__, ret);
		goto err;
	}

	ret = rtw88_mac_power_on(rtwdev);
	if (ret) {
		printf("%s: %s: failed to power on mac, error=%i\n",
		    sc->sc_pdev->dv_xname, __func__, ret);
		goto err;
	}

	rtw88_write8(rtwdev, RTW88_REG_C2HEVT, RTW88_C2H_HW_FEATURE_DUMP);

	// TODO: remove linusism
//	wait_for_completion(&fw->completion);
//	if (!fw->firmware) {
//		ret = -EINVAL;
//		rtw88_err(rtwdev, "failed to load firmware\n");
//		goto err;
//	}
	ret = loadfirmware(rtwdev->chip->fw_name, &fw->fwdata, &fw->fwsize);
	if (ret) {
		printf("%s: %s: could not read %s, error=%i\n",
		    sc->sc_pdev->dv_xname, __func__, rtwdev->chip->fw_name,
		    ret);
		goto err;
	};


//	ret = rtw88_download_firmware(rtwdev, fw);
//	if (ret) {
//		printf("%s: %s: failed to download firmware, error=%i\n",
//		    sc->sc_pdev->dv_xname, __func__, ret);
//		goto err_off;
//	}
//
//	return 0;
//
//err_off:
//	rtw88_mac_power_off(rtwdev);
//
err:
	return ret;
}

int
rtw88_chip_efuse_info_setup(struct rtw88_dev *rtwdev) {
	struct urtwm_softc *sc = rtwdev->cookie;
//	struct rtw88_efuse *efuse = &rtwdev->efuse;
	int ret;

	/* power on mac to read efuse */
	ret = rtw88_chip_efuse_enable(rtwdev);
	if (ret) {
		printf("%s: %s: rtw_chip_efuse_enable failed, error=%i\n",
		    sc->sc_pdev->dv_xname, __func__, ret);
		return ret;
	};

//	ret = rtw88_parse_efuse_map(sc);
//	if (ret)
//		goto out_disable;
//
//	ret = rtw88_dump_hw_feature(sc);
//	if (ret)
//		goto out_disable;
//
//	ret = rtw88_check_supported_rfe(sc);
//	if (ret)
//		goto out_disable;
//
//	if (efuse->crystal_cap == 0xff)
//		efuse->crystal_cap = 0;
//	if (efuse->pa_type_2g == 0xff)
//		efuse->pa_type_2g = 0;
//	if (efuse->pa_type_5g == 0xff)
//		efuse->pa_type_5g = 0;
//	if (efuse->lna_type_2g == 0xff)
//		efuse->lna_type_2g = 0;
//	if (efuse->lna_type_5g == 0xff)
//		efuse->lna_type_5g = 0;
//	if (efuse->channel_plan == 0xff)
//		efuse->channel_plan = 0x7f;
//	if (efuse->rf_board_option == 0xff)
//		efuse->rf_board_option = 0;
//	if (efuse->bt_setting & BIT(0))
//		efuse->share_ant = true;
//	if (efuse->regd == 0xff)
//		efuse->regd = 0;
//	if (efuse->tx_bb_swing_setting_2g == 0xff)
//		efuse->tx_bb_swing_setting_2g = 0;
//	if (efuse->tx_bb_swing_setting_5g == 0xff)
//		efuse->tx_bb_swing_setting_5g = 0;
//
//	efuse->btcoex = (efuse->rf_board_option & 0xe0) == 0x20;
//	efuse->ext_pa_2g = efuse->pa_type_2g & BIT(4) ? 1 : 0;
//	efuse->ext_lna_2g = efuse->lna_type_2g & BIT(3) ? 1 : 0;
//	efuse->ext_pa_5g = efuse->pa_type_5g & BIT(0) ? 1 : 0;
//	efuse->ext_lna_2g = efuse->lna_type_5g & BIT(3) ? 1 : 0;
//
//	if (!is_valid_ether_addr(efuse->addr)) {
//		eth_random_addr(efuse->addr);
//		dev_warn(rtwdev->dev, "efuse MAC invalid, using random\n");
//	}
//
//out_disable:
//	rtw_chip_efuse_disable(rtwdev);
	return ret;
}

/* -------------------------------------------------------------------------- */

int
rtw88_chip_parameter_setup(struct rtw88_dev *rtwdev)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	const struct rtw88_chip_info *chip = rtwdev->chip;
	struct rtw88_hal *hal = &rtwdev->hal;
	struct rtw88_efuse *efuse = &rtwdev->efuse;

	switch (rtw88_hci_type(rtwdev)) {
	case RTW88_HCI_TYPE_PCIE:
		rtwdev->hci.rpwm_addr = 0x03d9;
		rtwdev->hci.cpwm_addr = 0x03da;
		break;
	case RTW88_HCI_TYPE_SDIO:
		// TODO
//		rtwdev->hci.rpwm_addr = RTW88_REG_SDIO_HRPWM1;
//		rtwdev->hci.cpwm_addr = RTW88_REG_SDIO_HCPWM1_V2;
		break;
	case RTW88_HCI_TYPE_USB:
		rtwdev->hci.rpwm_addr = 0xfe58;
		rtwdev->hci.cpwm_addr = 0xfe57;
		break;
	default:
		printf("%s: %s: unsupported hci type\n",
		    sc->sc_pdev->dv_xname, __func__);
		return -EINVAL;
	}


	hal->chip_version = rtw88_read32(rtwdev, RTW88_REG_SYS_CFG1);
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

/* -------------------------------------------------------------------------- */

void
urtwm_attach(struct device *parent, struct device *self, void *aux)
{
	struct urtwm_softc *sc = (struct urtwm_softc *)self;
	struct rtw88_softc *sc_sc = &sc->sc_sc;
	struct rtw88_dev *rtwdev = &sc_sc->rtw_dev;
	struct usb_attach_arg *uaa = aux;
	int ret;

	sc->sc_udev = uaa->device;
	sc->sc_iface = uaa->iface;

	rtwdev->chip = &rtw8822b_hw_spec;

	rtwdev->hci.type = RTW88_HCI_TYPE_USB;
	rtwdev->hci.ops = &rtw88_usb_ops;
	rtwdev->cookie = sc;

	usb_init_task(&sc->sc_task, urtwm_task, sc, USB_TASK_TYPE_GENERIC);

	if ((ret = rtw88_chip_parameter_setup(rtwdev))) {
		printf("%s: %s: failed to setup chip parameters, error=%i\n",
		    sc->sc_pdev->dv_xname, __func__, ret);
		return;
	}

//	if ((ret = rtw88_chip_efuse_info_setup(rtwdev))) {
//		printf("%s: %s: failed to setup chip efuse info, error=%i\n",
//		    sc->sc_pdev->dv_xname, __func__, ret);
//		return;
//	}
	return;
}

int
urtwm_detach(struct device *self, int flags)
{
	return (0);
}
