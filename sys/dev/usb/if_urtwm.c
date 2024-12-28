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


typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int16_t __le16;
typedef int32_t __le32;
typedef int64_t __le64;

#define le32_to_cpu le32toh
#define cpu_to_le64 htole64
#define cpu_to_le32 htole32
#define cpu_to_le16 htole16
#define __le16_to_cpu le16toh

#define	BIT(x)	(1 << (x))
#define clear_bit(i, a) ((a)) &= ~(1 << (i))
#define set_bit(i, a) ((a)) |= (1 << (i))

#define BITS_TO_LONGS(x)	howmany((x), 8 * sizeof(long))
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#define cut_version_to_mask(cut) (0x1 << ((cut) + 1))

#define DLFW_RESTORE_REG_NUM 6
#define FW_HDR_CHKSUM_SIZE		8
#define FW_HDR_SIZE			64

#define REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1		0x1700
#define REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1	0x1704
#define REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1	0x1708
#define LTECOEX_READY		BIT(29)
#define LTECOEX_ACCESS_CTRL REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1
#define LTECOEX_WRITE_DATA REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1
#define LTECOEX_READ_DATA REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1

#define REG_RSV_CTRL		0x001C
#define BIT_WLMCU_IOIF		BIT(0)
#define REG_SYS_FUNC_EN		0x0002
#define BIT_FEN_CPUEN		BIT(2)

#define RTW_HW_PORT_NUM		5
#define cut_version_to_mask(cut) (0x1 << ((cut) + 1))
#define DDMA_POLLING_COUNT	1000
#define C2H_PKT_BUF		256
#define REPORT_BUF		128
#define PHY_STATUS_SIZE		4
#define ILLEGAL_KEY_GROUP	0xFAAAAA00

/* HW memory address */
#define OCPBASE_RXBUF_FW_88XX		0x18680000
#define OCPBASE_TXBUF_88XX		0x18780000
#define OCPBASE_ROM_88XX		0x00000000
#define OCPBASE_IMEM_88XX		0x00030000
#define OCPBASE_DMEM_88XX		0x00200000
#define OCPBASE_EMEM_88XX		0x00100000

#define RSVD_PG_DRV_NUM			16
#define RSVD_PG_H2C_EXTRAINFO_NUM	24
#define RSVD_PG_H2C_STATICINFO_NUM	8
#define RSVD_PG_H2CQ_NUM		8
#define RSVD_PG_CPU_INSTRUCTION_NUM	0
#define RSVD_PG_FW_TXBUF_NUM		4

#include <dev/ic/rtw88/reg.h>

#define rtw_hci_type rtw88_hci_type

// {{{ data structures

enum rtw_dma_mapping {
	RTW_DMA_MAPPING_EXTRA	= 0,
	RTW_DMA_MAPPING_LOW	= 1,
	RTW_DMA_MAPPING_NORMAL	= 2,
	RTW_DMA_MAPPING_HIGH	= 3,

	RTW_DMA_MAPPING_MAX,
	RTW_DMA_MAPPING_UNDEF,
};

struct rtw_rqpn {
	enum rtw_dma_mapping dma_map_vo;
	enum rtw_dma_mapping dma_map_vi;
	enum rtw_dma_mapping dma_map_be;
	enum rtw_dma_mapping dma_map_bk;
	enum rtw_dma_mapping dma_map_mg;
	enum rtw_dma_mapping dma_map_hi;
};


struct rtw_fifo_conf {
	/* tx fifo information */
	u16 rsvd_boundary;
	u16 rsvd_pg_num;
	u16 rsvd_drv_pg_num;
	u16 txff_pg_num;
	u16 acq_pg_num;
	u16 rsvd_drv_addr;
	u16 rsvd_h2c_info_addr;
	u16 rsvd_h2c_sta_info_addr;
	u16 rsvd_h2cq_addr;
	u16 rsvd_cpu_instr_addr;
	u16 rsvd_fw_txbuf_addr;
	u16 rsvd_csibuf_addr;
	const struct rtw_rqpn *rqpn;
};

enum rtw_trx_desc_rate {
	DESC_RATE1M	= 0x00,
	DESC_RATE2M	= 0x01,
	DESC_RATE5_5M	= 0x02,
	DESC_RATE11M	= 0x03,

	DESC_RATE6M	= 0x04,
	DESC_RATE9M	= 0x05,
	DESC_RATE12M	= 0x06,
	DESC_RATE18M	= 0x07,
	DESC_RATE24M	= 0x08,
	DESC_RATE36M	= 0x09,
	DESC_RATE48M	= 0x0a,
	DESC_RATE54M	= 0x0b,

	DESC_RATEMCS0	= 0x0c,
	DESC_RATEMCS1	= 0x0d,
	DESC_RATEMCS2	= 0x0e,
	DESC_RATEMCS3	= 0x0f,
	DESC_RATEMCS4	= 0x10,
	DESC_RATEMCS5	= 0x11,
	DESC_RATEMCS6	= 0x12,
	DESC_RATEMCS7	= 0x13,
	DESC_RATEMCS8	= 0x14,
	DESC_RATEMCS9	= 0x15,
	DESC_RATEMCS10	= 0x16,
	DESC_RATEMCS11	= 0x17,
	DESC_RATEMCS12	= 0x18,
	DESC_RATEMCS13	= 0x19,
	DESC_RATEMCS14	= 0x1a,
	DESC_RATEMCS15	= 0x1b,
	DESC_RATEMCS16	= 0x1c,
	DESC_RATEMCS17	= 0x1d,
	DESC_RATEMCS18	= 0x1e,
	DESC_RATEMCS19	= 0x1f,
	DESC_RATEMCS20	= 0x20,
	DESC_RATEMCS21	= 0x21,
	DESC_RATEMCS22	= 0x22,
	DESC_RATEMCS23	= 0x23,
	DESC_RATEMCS24	= 0x24,
	DESC_RATEMCS25	= 0x25,
	DESC_RATEMCS26	= 0x26,
	DESC_RATEMCS27	= 0x27,
	DESC_RATEMCS28	= 0x28,
	DESC_RATEMCS29	= 0x29,
	DESC_RATEMCS30	= 0x2a,
	DESC_RATEMCS31	= 0x2b,

	DESC_RATEVHT1SS_MCS0	= 0x2c,
	DESC_RATEVHT1SS_MCS1	= 0x2d,
	DESC_RATEVHT1SS_MCS2	= 0x2e,
	DESC_RATEVHT1SS_MCS3	= 0x2f,
	DESC_RATEVHT1SS_MCS4	= 0x30,
	DESC_RATEVHT1SS_MCS5	= 0x31,
	DESC_RATEVHT1SS_MCS6	= 0x32,
	DESC_RATEVHT1SS_MCS7	= 0x33,
	DESC_RATEVHT1SS_MCS8	= 0x34,
	DESC_RATEVHT1SS_MCS9	= 0x35,

	DESC_RATEVHT2SS_MCS0	= 0x36,
	DESC_RATEVHT2SS_MCS1	= 0x37,
	DESC_RATEVHT2SS_MCS2	= 0x38,
	DESC_RATEVHT2SS_MCS3	= 0x39,
	DESC_RATEVHT2SS_MCS4	= 0x3a,
	DESC_RATEVHT2SS_MCS5	= 0x3b,
	DESC_RATEVHT2SS_MCS6	= 0x3c,
	DESC_RATEVHT2SS_MCS7	= 0x3d,
	DESC_RATEVHT2SS_MCS8	= 0x3e,
	DESC_RATEVHT2SS_MCS9	= 0x3f,

	DESC_RATEVHT3SS_MCS0	= 0x40,
	DESC_RATEVHT3SS_MCS1	= 0x41,
	DESC_RATEVHT3SS_MCS2	= 0x42,
	DESC_RATEVHT3SS_MCS3	= 0x43,
	DESC_RATEVHT3SS_MCS4	= 0x44,
	DESC_RATEVHT3SS_MCS5	= 0x45,
	DESC_RATEVHT3SS_MCS6	= 0x46,
	DESC_RATEVHT3SS_MCS7	= 0x47,
	DESC_RATEVHT3SS_MCS8	= 0x48,
	DESC_RATEVHT3SS_MCS9	= 0x49,

	DESC_RATEVHT4SS_MCS0	= 0x4a,
	DESC_RATEVHT4SS_MCS1	= 0x4b,
	DESC_RATEVHT4SS_MCS2	= 0x4c,
	DESC_RATEVHT4SS_MCS3	= 0x4d,
	DESC_RATEVHT4SS_MCS4	= 0x4e,
	DESC_RATEVHT4SS_MCS5	= 0x4f,
	DESC_RATEVHT4SS_MCS6	= 0x50,
	DESC_RATEVHT4SS_MCS7	= 0x51,
	DESC_RATEVHT4SS_MCS8	= 0x52,
	DESC_RATEVHT4SS_MCS9	= 0x53,

	DESC_RATE_MAX,
};


struct rtw_tx_desc {
	__le32 w0;
	__le32 w1;
	__le32 w2;
	__le32 w3;
	__le32 w4;
	__le32 w5;
	__le32 w6;
	__le32 w7;
	__le32 w8;
	__le32 w9;
} __packed;


enum rtw_tx_desc_queue_select {
	TX_DESC_QSEL_TID0	= 0,
	TX_DESC_QSEL_TID1	= 1,
	TX_DESC_QSEL_TID2	= 2,
	TX_DESC_QSEL_TID3	= 3,
	TX_DESC_QSEL_TID4	= 4,
	TX_DESC_QSEL_TID5	= 5,
	TX_DESC_QSEL_TID6	= 6,
	TX_DESC_QSEL_TID7	= 7,
	TX_DESC_QSEL_TID8	= 8,
	TX_DESC_QSEL_TID9	= 9,
	TX_DESC_QSEL_TID10	= 10,
	TX_DESC_QSEL_TID11	= 11,
	TX_DESC_QSEL_TID12	= 12,
	TX_DESC_QSEL_TID13	= 13,
	TX_DESC_QSEL_TID14	= 14,
	TX_DESC_QSEL_TID15	= 15,
	TX_DESC_QSEL_BEACON	= 16,
	TX_DESC_QSEL_HIGH	= 17,
	TX_DESC_QSEL_MGMT	= 18,
	TX_DESC_QSEL_H2C	= 19,
};

struct rtw_tx_pkt_info {
	u32 tx_pkt_size;
	u8 offset;
	u8 pkt_offset;
	u8 tim_offset;
	u8 mac_id;
	u8 rate_id;
	u8 rate;
	u8 qsel;
	u8 bw;
	u8 sec_type;
	u8 sn;
	bool ampdu_en;
	u8 ampdu_factor;
	u8 ampdu_density;
	u16 seq;
	bool stbc;
	bool ldpc;
	bool dis_rate_fallback;
	bool bmc;
	bool use_rate;
	bool ls;
	bool fs;
	bool short_gi;
	bool report;
	bool rts;
	bool dis_qselseq;
	bool en_hwseq;
	u8 hw_ssn_sel;
	bool nav_use_hdr;
	bool bt_null;
};

struct rtw_ltecoex_addr {
	u32 ctrl;
	u32 wdata;
	u32 rdata;
};

static const struct rtw_ltecoex_addr rtw8822b_ltecoex_addr = {
	.ctrl = LTECOEX_ACCESS_CTRL,
	.wdata = LTECOEX_WRITE_DATA,
	.rdata = LTECOEX_READ_DATA,
};

struct rtw_backup_info {
	u8 len;
	u32 reg;
	u32 val;
};

struct rtw_fw_hdr {
	__le16 signature;
	u8 category;
	u8 function;
	__le16 version;		/* 0x04 */
	u8 subversion;
	u8 subindex;
	__le32 rsvd;		/* 0x08 */
	__le32 feature;		/* 0x0C */
	u8 month;		/* 0x10 */
	u8 day;
	u8 hour;
	u8 min;
	__le16 year;		/* 0x14 */
	__le16 rsvd3;
	u8 mem_usage;		/* 0x18 */
	u8 rsvd4[3];
	__le16 h2c_fmt_ver;	/* 0x1C */
	__le16 rsvd5;
	__le32 dmem_addr;	/* 0x20 */
	__le32 dmem_size;
	__le32 rsvd6;
	__le32 rsvd7;
	__le32 imem_size;	/* 0x30 */
	__le32 emem_size;
	__le32 emem_addr;
	__le32 imem_addr;
} __packed;

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
	uint8_t tx_pkt_desc_sz;
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
	const struct rtw_rqpn *rqpn_table;
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
	const struct rtw_ltecoex_addr *ltecoex_addr;
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

#define rtw_chip_info rtw88_chip_info

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

static const struct rtw_rqpn rqpn_table_8822b[] = {
        {RTW_DMA_MAPPING_NORMAL, RTW_DMA_MAPPING_NORMAL,
         RTW_DMA_MAPPING_LOW, RTW_DMA_MAPPING_LOW,
         RTW_DMA_MAPPING_EXTRA, RTW_DMA_MAPPING_HIGH},
        {RTW_DMA_MAPPING_NORMAL, RTW_DMA_MAPPING_NORMAL,
         RTW_DMA_MAPPING_LOW, RTW_DMA_MAPPING_LOW,
         RTW_DMA_MAPPING_EXTRA, RTW_DMA_MAPPING_HIGH},
        {RTW_DMA_MAPPING_NORMAL, RTW_DMA_MAPPING_NORMAL,
         RTW_DMA_MAPPING_NORMAL, RTW_DMA_MAPPING_HIGH,
         RTW_DMA_MAPPING_HIGH, RTW_DMA_MAPPING_HIGH},
        {RTW_DMA_MAPPING_NORMAL, RTW_DMA_MAPPING_NORMAL,
         RTW_DMA_MAPPING_LOW, RTW_DMA_MAPPING_LOW,
         RTW_DMA_MAPPING_HIGH, RTW_DMA_MAPPING_HIGH},
        {RTW_DMA_MAPPING_NORMAL, RTW_DMA_MAPPING_NORMAL,
         RTW_DMA_MAPPING_LOW, RTW_DMA_MAPPING_LOW,
         RTW_DMA_MAPPING_EXTRA, RTW_DMA_MAPPING_HIGH},
};

const struct rtw88_chip_info rtw8822b_hw_spec = {
//	.ops = &rtw8822b_ops,
//	.id = RTW_CHIP_TYPE_8822B,
	.fw_name = "rtw88/rtw8822b_fw.bin",
	.wlan_cpu = RTW88_WCPU_11AC,
	.tx_pkt_desc_sz = 48,
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
	.rqpn_table = rqpn_table_8822b,
//	.prioq_addrs = &prioq_addrs_8822b,
//	.intf_table = &phy_para_table_8822b,
//	.dig = rtw8822b_dig,
//	.dig_cck = NULL,
//	.rf_base_addr = {0x2800, 0x2c00},
//	.rf_sipi_addr = {0xc90, 0xe90},
	.ltecoex_addr = &rtw8822b_ltecoex_addr,
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
struct rtw_dev;


/* ops for PCI, USB and SDIO */
struct rtw88_hci_ops {
//	int (*tx_write)(struct rtw_dev *rtwdev,
//	    struct rtw88_tx_pkt_info *pkt_info,
//	    struct sk_buff *skb);
//	void (*tx_kick_off)(struct rtw_dev *rtwdev);
//	void (*flush_queues)(struct rtw_dev *rtwdev, u32 queues, bool drop);
	int (*setup)(struct rtw_dev *rtwdev);
//	int (*start)(struct rtw_dev *rtwdev);
//	void (*stop)(struct rtw_dev *rtwdev);
//	void (*deep_ps)(struct rtw_dev *rtwdev, bool enter);
//	void (*link_ps)(struct rtw_dev *rtwdev, bool enter);
//	void (*interface_cfg)(struct rtw_dev *rtwdev);
//
	int (*write_data_rsvd_page)(struct rtw_dev *rtwdev, u8 *buf, u32 size);
//	int (*write_data_h2c)(struct rtw_dev *rtwdev, u8 *buf, u32 size);

	uint8_t (*read8)(struct rtw_dev *rtwdev, uint16_t addr);
	uint16_t (*read16)(struct rtw_dev *rtwdev, uint16_t addr);
	uint32_t (*read32)(struct rtw_dev *rtwdev, uint16_t addr);
	int (*write8)(struct rtw_dev *rtwdev, uint16_t addr, uint8_t val);
	int (*write16)(struct rtw_dev *rtwdev, uint16_t addr, uint16_t val);
	int (*write32)(struct rtw_dev *rtwdev, uint16_t addr, uint32_t val);
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
//	struct rtw_dev *rtwdev;
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


struct rtw_dev {
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
	struct rtw_dev		rtw_dev;
};

struct urtwm_softc {
	struct device			*sc_pdev;
	struct ieee80211com		sc_ic;
	struct rtw88_softc		sc_sc;

	struct usbd_device		*sc_udev;
	struct usbd_interface		*sc_iface;
	struct usb_task			sc_task;
	struct usbd_pipe		*rx_pipe;
#define RTW_USB_EP_MAX			4
	struct usbd_pipe		*tx_pipe[RTW_USB_EP_MAX];
	struct usbd_pipe		*int_pipe;
#define TX_DESC_QSEL_MAX                20
	int				qsel_to_ep[TX_DESC_QSEL_MAX];
};

// }}}

// {{{ read/write/other operations

#define rtw_read8 rtw88_read8
#define rtw_read16 rtw88_read16
#define rtw_read32 rtw88_read32

#define rtw_write8 rtw88_write8
#define rtw_write16 rtw88_write16
#define rtw_write32 rtw88_write32

#define rtw_chip_wcpu_11n rtw88_chip_wcpu_11n

inline int rtw88_chip_wcpu_11n(struct rtw_dev *rtwdev)
{
	return rtwdev->chip->wlan_cpu == RTW88_WCPU_11N;
}

inline int rtw88_chip_wcpu_11ac(struct rtw_dev *rtwdev)
{
	return rtwdev->chip->wlan_cpu == RTW88_WCPU_11AC;
}


inline enum rtw88_hci_type rtw88_hci_type(struct rtw_dev *rtwdev)
{
	return rtwdev->hci.type;
}

uint8_t
rtw88_read8(struct rtw_dev *rtwdev, uint32_t addr)
{
	return rtwdev->hci.ops->read8(rtwdev, addr);
}

uint16_t
rtw88_read16(struct rtw_dev *rtwdev, uint32_t addr)
{
	return rtwdev->hci.ops->read16(rtwdev, addr);
}

uint32_t
rtw88_read32(struct rtw_dev *rtwdev, uint32_t addr)
{
	return rtwdev->hci.ops->read32(rtwdev, addr);
}

int
rtw88_write8(struct rtw_dev *rtwdev, uint32_t addr, uint8_t val)
{
	return rtwdev->hci.ops->write8(rtwdev, addr, val);
}

int
rtw88_write16(struct rtw_dev *rtwdev, uint32_t addr, uint16_t val)
{
	return rtwdev->hci.ops->write16(rtwdev, addr, val);
}

int
rtw88_write32(struct rtw_dev *rtwdev, uint32_t addr, uint16_t val)
{
	return rtwdev->hci.ops->write32(rtwdev, addr, val);
}

uint32_t urtwm_read_4(struct rtw_dev *, uint16_t);

int
rtw88_usb_setup(struct rtw_dev *rtwdev)
{
	/* empty function for rtw_hci_ops */
	return 0;
}

inline void
rtw88_write8_set(struct rtw_dev *rtwdev, uint32_t addr, uint8_t bit)
{
	uint8_t val;

	val = rtw88_read8(rtwdev, addr);
	rtw88_write8(rtwdev, addr, val | bit);
}

inline void
rtw88_write16_clr(struct rtw_dev *rtwdev, uint32_t addr, uint16_t bit)
{
	uint16_t val;

	val = rtw88_read16(rtwdev, addr);
	rtw88_write16(rtwdev, addr, val & ~bit);
}

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
urtwm_write_8(struct rtw_dev *rtwdev, uint16_t addr, uint8_t val)
{
	struct urtwm_softc *sc = rtwdev->cookie;

	return urtwm_write_region_1(sc, addr, &val, 1);
}

int
urtwm_write_16(struct rtw_dev *rtwdev, uint16_t addr, uint16_t val)
{
	struct urtwm_softc *sc = rtwdev->cookie;

	val = htole16(val);
	return urtwm_write_region_1(sc, addr, (uint8_t *)&val, 2);
}

int
urtwm_write_32(struct rtw_dev *rtwdev, uint16_t addr, uint32_t val)
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
urtwm_read_8(struct rtw_dev *rtwdev, uint16_t addr)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	uint8_t val;

	if (urtwm_read_region_1(sc, addr, &val, 1) != 0)
		return (0xff);
	return (val);
}

uint16_t
urtwm_read_16(struct rtw_dev *rtwdev, uint16_t addr)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	uint16_t val;

	if (urtwm_read_region_1(sc, addr, (uint8_t *)&val, 2) != 0)
		return (0xffff);
	return (letoh16(val));
}

uint32_t
urtwm_read_32(struct rtw_dev *rtwdev, uint16_t addr)
{
	struct urtwm_softc *sc = rtwdev->cookie;
	uint32_t val;

	if (urtwm_read_region_1(sc, addr, (uint8_t *)&val, 4) != 0)
		return (0xffffffff);
	return (letoh32(val));
}

// ---------- write usb packet start ----------


// -- defines start

static inline uint64_t ___lsb(uint64_t f) { return (f & -f); }
static inline uint64_t ___bitmask(uint64_t f) { return (f / ___lsb(f)); }


#ifdef __LP64__
#define BITS_PER_LONG		64
#else
#define BITS_PER_LONG		32
#endif

#define BITS_PER_LONG_LONG	64

#define GENMASK(h, l)		(((~0UL) >> (BITS_PER_LONG - (h) - 1)) & ((~0UL) << (l)))

#define RTW_TX_DESC_W0_TXPKTSIZE GENMASK(15, 0)
#define RTW_TX_DESC_W0_OFFSET GENMASK(23, 16)
#define RTW_TX_DESC_W0_BMC BIT(24)
#define RTW_TX_DESC_W0_LS BIT(26)
#define RTW_TX_DESC_W0_DISQSELSEQ BIT(31)
#define RTW_TX_DESC_W1_MACID GENMASK(7, 0)
#define RTW_TX_DESC_W1_QSEL GENMASK(12, 8)
#define RTW_TX_DESC_W1_RATE_ID GENMASK(20, 16)
#define RTW_TX_DESC_W1_SEC_TYPE GENMASK(23, 22)
#define RTW_TX_DESC_W1_PKT_OFFSET GENMASK(28, 24)
#define RTW_TX_DESC_W1_MORE_DATA BIT(29)
#define RTW_TX_DESC_W2_AGG_EN BIT(12)
#define RTW_TX_DESC_W2_SPE_RPT BIT(19)
#define RTW_TX_DESC_W2_AMPDU_DEN GENMASK(22, 20)
#define RTW_TX_DESC_W2_BT_NULL BIT(23)
#define RTW_TX_DESC_W3_HW_SSN_SEL GENMASK(7, 6)
#define RTW_TX_DESC_W3_USE_RATE BIT(8)
#define RTW_TX_DESC_W3_DISDATAFB BIT(10)
#define RTW_TX_DESC_W3_USE_RTS BIT(12)
#define RTW_TX_DESC_W3_NAVUSEHDR BIT(15)
#define RTW_TX_DESC_W3_MAX_AGG_NUM GENMASK(21, 17)
#define RTW_TX_DESC_W4_DATARATE GENMASK(6, 0)
#define RTW_TX_DESC_W4_RTSRATE GENMASK(28, 24)
#define RTW_TX_DESC_W5_DATA_SHORT BIT(4)
#define RTW_TX_DESC_W5_DATA_BW GENMASK(6, 5)
#define RTW_TX_DESC_W5_DATA_LDPC BIT(7)
#define RTW_TX_DESC_W5_DATA_STBC GENMASK(9, 8)
#define RTW_TX_DESC_W5_DATA_RTS_SHORT BIT(12)
#define RTW_TX_DESC_W6_SW_DEFINE GENMASK(11, 0)
#define RTW_TX_DESC_W7_TXDESC_CHECKSUM GENMASK(15, 0)
#define RTW_TX_DESC_W7_DMA_TXAGG_NUM GENMASK(31, 24)
#define RTW_TX_DESC_W8_EN_HWSEQ BIT(15)
#define RTW_TX_DESC_W9_SW_SEQ GENMASK(23, 12)
#define RTW_TX_DESC_W9_TIM_EN BIT(7)
#define RTW_TX_DESC_W9_TIM_OFFSET GENMASK(6, 0)

#define _leX_encode_bits(_n)						\
	static __inline uint ## _n ## _t				\
	le ## _n ## _encode_bits(__le ## _n v, uint ## _n ## _t f)	\
	{								\
		return (cpu_to_le ## _n((v & ___bitmask(f)) * ___lsb(f))); \
	}

//_leX_encode_bits(64)
_leX_encode_bits(32)
//_leX_encode_bits(16)

#define _leXp_replace_bits(_n)						\
	static __inline void						\
	le ## _n ## p_replace_bits(uint ## _n ## _t *p,			\
	    uint ## _n ## _t v, uint ## _n ## _t f)			\
	{								\
		*p = (*p & ~(cpu_to_le ## _n(f))) |			\
		     le ## _n ## _encode_bits(v, f);			\
	}

//_leXp_replace_bits(64)
_leXp_replace_bits(32)
//_leXp_replace_bits(16)

// -- defines end

static inline
void fill_txdesc_checksum_common(u8 *txdesc, size_t words)
{
	__le16 chksum = 0;
	__le16 *data = (__le16 *)(txdesc);
	struct rtw_tx_desc *tx_desc = (struct rtw_tx_desc *)txdesc;

	le32p_replace_bits(&tx_desc->w7, 0, RTW_TX_DESC_W7_TXDESC_CHECKSUM);

	while (words--)
		chksum ^= *data++;

	le32p_replace_bits(&tx_desc->w7, __le16_to_cpu(chksum),
			   RTW_TX_DESC_W7_TXDESC_CHECKSUM);
}

static void rtw8822b_fill_txdesc_checksum(struct rtw_dev *rtwdev,
					  struct rtw_tx_pkt_info *pkt_info,
					  u8 *txdesc)
{
	size_t words = 32 / 2; /* calculate the first 32 bytes (16 words) */

	fill_txdesc_checksum_common(txdesc, words);
}

static inline void rtw_tx_fill_txdesc_checksum(struct rtw_dev *rtwdev,
					       struct rtw_tx_pkt_info *pkt_info,
					       u8 *txdesc)
{
//	  const struct rtw_chip_info *chip = rtwdev->chip;

	// FIXME:misha -- use real indirrect
//	  chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, txdesc);
	rtw8822b_fill_txdesc_checksum(rtwdev, pkt_info, txdesc);
}

void rtw_tx_fill_tx_desc(struct rtw_tx_pkt_info *pkt_info, u8 *data)
{
	struct rtw_tx_desc *tx_desc = (struct rtw_tx_desc *)data;
	bool more_data = false;

	if (pkt_info->qsel == TX_DESC_QSEL_HIGH)
		more_data = true;

	tx_desc->w0 = le32_encode_bits(pkt_info->tx_pkt_size, RTW_TX_DESC_W0_TXPKTSIZE) |
		      le32_encode_bits(pkt_info->offset, RTW_TX_DESC_W0_OFFSET) |
		      le32_encode_bits(pkt_info->bmc, RTW_TX_DESC_W0_BMC) |
		      le32_encode_bits(pkt_info->ls, RTW_TX_DESC_W0_LS) |
		      le32_encode_bits(pkt_info->dis_qselseq, RTW_TX_DESC_W0_DISQSELSEQ);

	tx_desc->w1 = le32_encode_bits(pkt_info->mac_id, RTW_TX_DESC_W1_MACID) |
		      le32_encode_bits(pkt_info->qsel, RTW_TX_DESC_W1_QSEL) |
		      le32_encode_bits(pkt_info->rate_id, RTW_TX_DESC_W1_RATE_ID) |
		      le32_encode_bits(pkt_info->sec_type, RTW_TX_DESC_W1_SEC_TYPE) |
		      le32_encode_bits(pkt_info->pkt_offset, RTW_TX_DESC_W1_PKT_OFFSET) |
		      le32_encode_bits(more_data, RTW_TX_DESC_W1_MORE_DATA);

	tx_desc->w2 = le32_encode_bits(pkt_info->ampdu_en, RTW_TX_DESC_W2_AGG_EN) |
		      le32_encode_bits(pkt_info->report, RTW_TX_DESC_W2_SPE_RPT) |
		      le32_encode_bits(pkt_info->ampdu_density, RTW_TX_DESC_W2_AMPDU_DEN) |
		      le32_encode_bits(pkt_info->bt_null, RTW_TX_DESC_W2_BT_NULL);

	tx_desc->w3 = le32_encode_bits(pkt_info->hw_ssn_sel, RTW_TX_DESC_W3_HW_SSN_SEL) |
		      le32_encode_bits(pkt_info->use_rate, RTW_TX_DESC_W3_USE_RATE) |
		      le32_encode_bits(pkt_info->dis_rate_fallback, RTW_TX_DESC_W3_DISDATAFB) |
		      le32_encode_bits(pkt_info->rts, RTW_TX_DESC_W3_USE_RTS) |
		      le32_encode_bits(pkt_info->nav_use_hdr, RTW_TX_DESC_W3_NAVUSEHDR) |
		      le32_encode_bits(pkt_info->ampdu_factor, RTW_TX_DESC_W3_MAX_AGG_NUM);

	tx_desc->w4 = le32_encode_bits(pkt_info->rate, RTW_TX_DESC_W4_DATARATE);

	tx_desc->w5 = le32_encode_bits(pkt_info->short_gi, RTW_TX_DESC_W5_DATA_SHORT) |
		      le32_encode_bits(pkt_info->bw, RTW_TX_DESC_W5_DATA_BW) |
		      le32_encode_bits(pkt_info->ldpc, RTW_TX_DESC_W5_DATA_LDPC) |
		      le32_encode_bits(pkt_info->stbc, RTW_TX_DESC_W5_DATA_STBC);

	tx_desc->w6 = le32_encode_bits(pkt_info->sn, RTW_TX_DESC_W6_SW_DEFINE);

	tx_desc->w8 = le32_encode_bits(pkt_info->en_hwseq, RTW_TX_DESC_W8_EN_HWSEQ);

	tx_desc->w9 = le32_encode_bits(pkt_info->seq, RTW_TX_DESC_W9_SW_SEQ);

	if (pkt_info->rts) {
		tx_desc->w4 |= le32_encode_bits(DESC_RATE24M, RTW_TX_DESC_W4_RTSRATE);
		tx_desc->w5 |= le32_encode_bits(1, RTW_TX_DESC_W5_DATA_RTS_SHORT);
	}

	if (pkt_info->tim_offset)
		tx_desc->w9 |= le32_encode_bits(1, RTW_TX_DESC_W9_TIM_EN) |
			       le32_encode_bits(pkt_info->tim_offset, RTW_TX_DESC_W9_TIM_OFFSET);
}


//static int qsel_to_ep(struct rtw_usb *rtwusb, unsigned int qsel)
static int qsel_to_ep(struct rtw_dev *rtwdev, unsigned int qsel)
{
	struct urtwm_softc *sc = rtwdev->cookie;
//        if (qsel >= ARRAY_SIZE(rtwusb->qsel_to_ep))
//                return -EINVAL;

	if (qsel >= nitems(sc->qsel_to_ep))
		return -EINVAL;

        return sc->qsel_to_ep[qsel];
}

void
urtwm_txeof(struct usbd_xfer *xfer, void *priv,
    usbd_status status)
{
	printf("%s: TX status=%d\n", __func__, status);
}
//static int rtw_usb_write_port(struct rtw_dev *rtwdev, u8 qsel, struct sk_buff *skb,
//                              usb_complete_t cb, void *context)
static int rtw_usb_write_port(struct rtw_dev *rtwdev, u8 qsel, struct mbuf *m)
{
//        struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
//        struct usb_device *usbd = rtwusb->udev;
//        struct urb *urb;
//        unsigned int pipe;
//        int ret;
	struct urtwm_softc *sc = rtwdev->cookie;
	struct usbd_xfer                *xfer;
	struct usbd_pipe *pipe;
	int error;
        int ep = qsel_to_ep(rtwdev, qsel);
        ep = 1;
        printf("%s: ep=%i\n", __func__, ep);
//
	if (ep < 0)
		return ep;

//        pipe = usb_sndbulkpipe(usbd, rtwusb->out_ep[ep]);
//        urb = usb_alloc_urb(0, GFP_ATOMIC);
//        if (!urb)
//                return -ENOMEM;
//
//        usb_fill_bulk_urb(urb, usbd, pipe, skb->data, skb->len, cb, context);
//        urb->transfer_flags |= URB_ZERO_PACKET;
//        ret = usb_submit_urb(urb, GFP_ATOMIC);
//
//        usb_free_urb(urb);
//
//        return ret;

	xfer = usbd_alloc_xfer(sc->sc_udev);
	pipe = sc->tx_pipe[ep];
	if (xfer == NULL) {
		printf("%s: could not alloc xfer\n", __func__);
		return ENOMEM;
	}
	usbd_setup_xfer(xfer, pipe, NULL, m->m_data, m->m_len,
	    USBD_FORCE_SHORT_XFER | USBD_NO_COPY, 5000 /*timeout*/,
	    urtwm_txeof);
	error = usbd_transfer(xfer);
	printf("%s: error=%i\n", __func__, error);

	return 0;

}

static int rtw_usb_write_data(struct rtw_dev *rtwdev,
			      struct rtw_tx_pkt_info *pkt_info,
			      u8 *buf)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
//	  struct sk_buff *skb;
	struct mbuf *m;
	unsigned int size;
	u8 qsel;
	int ret = 0;
	u8 *data;

	size = pkt_info->tx_pkt_size;
	qsel = pkt_info->qsel;

	// FIXME:misha -- must free, M_NOWAIT?
	data = malloc(chip->tx_pkt_desc_sz + size, M_DEVBUF, M_NOWAIT);
	// TODO: must be free'ed
	m = m_get(M_NOWAIT, M_DEVBUF);
	if (m == NULL) {
		printf("%s: m_get == NULL\n", __func__);
		return ENOMEM;
	}
	m->m_data = data;
	m->m_len = chip->tx_pkt_desc_sz + size;
	m->m_nextpkt = NULL;
	m->m_type = 0;
	m->m_flags = 0;

//	  skb = dev_alloc_skb(chip->tx_pkt_desc_sz + size);
//	  if (unlikely(!skb))
//		  return -ENOMEM;
//
//	  skb_reserve(skb, chip->tx_pkt_desc_sz);
//	  skb_put_data(skb, buf, size);
//	  skb_push(skb, chip->tx_pkt_desc_sz);
//	  memset(skb->data, 0, chip->tx_pkt_desc_sz);
//	  rtw_tx_fill_tx_desc(pkt_info, skb);
//	  rtw_tx_fill_txdesc_checksum(rtwdev, pkt_info, skb->data);
	rtw_tx_fill_tx_desc(pkt_info, data);
	rtw_tx_fill_txdesc_checksum(rtwdev, pkt_info, data);

	ret = rtw_usb_write_port(rtwdev, qsel, m);
//	  if (unlikely(ret))
//		  rtw_err(rtwdev, "failed to do USB write, ret=%d\n", ret);

	return ret;
}

static int rtw_usb_write_data_rsvd_page(struct rtw_dev *rtwdev, u8 *buf,
					u32 size)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_tx_pkt_info pkt_info = {0};

	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = TX_DESC_QSEL_BEACON;
	pkt_info.offset = chip->tx_pkt_desc_sz;

	return rtw_usb_write_data(rtwdev, &pkt_info, buf);
}

// ---------- write usb packet end ----------

struct rtw88_hci_ops rtw88_usb_ops = {
	.setup = rtw88_usb_setup,
	.write8 = urtwm_write_8,
	.write16 = urtwm_write_16,
	.write32 = urtwm_write_32,
	.read8= urtwm_read_8,
	.read16 = urtwm_read_16,
	.read32 = urtwm_read_32,
	.write_data_rsvd_page = rtw_usb_write_data_rsvd_page,
};

int
rtw88_hci_setup(struct rtw_dev *rtwdev)
{
	return rtwdev->hci.ops->setup(rtwdev);
}

static inline u32
rtw_read32_mask(struct rtw_dev *rtwdev, u32 addr, u32 mask)
{
	u32 shift = ffs(mask);
	u32 orig;
	u32 ret;

	orig = rtw_read32(rtwdev, addr);
	ret = (orig & mask) >> shift;

	return ret;
}


static inline void rtw_write8_set(struct rtw_dev *rtwdev, u32 addr, u8 bit)
{
	u8 val;

	val = rtw_read8(rtwdev, addr);
	rtw_write8(rtwdev, addr, val | bit);
}

//static inline void rtw_write16_set(struct rtw_dev *rtwdev, u32 addr, u16 bit)
//{
//	  u16 val;
//
//	  val = rtw_read16(rtwdev, addr);
//	  rtw_write16(rtwdev, addr, val | bit);
//}
//
static inline void rtw_write32_set(struct rtw_dev *rtwdev, u32 addr, u32 bit)
{
	u32 val;

	val = rtw_read32(rtwdev, addr);
	rtw_write32(rtwdev, addr, val | bit);
}
//
static inline void rtw_write8_clr(struct rtw_dev *rtwdev, u32 addr, u8 bit)
{
	u8 val;

	val = rtw_read8(rtwdev, addr);
	rtw_write8(rtwdev, addr, val & ~bit);
}
//
//static inline void rtw_write16_clr(struct rtw_dev *rtwdev, u32 addr, u16 bit)
//{
//	  u16 val;
//
//	  val = rtw_read16(rtwdev, addr);
//	  rtw_write16(rtwdev, addr, val & ~bit);
//}
//
//static inline void rtw_write32_clr(struct rtw_dev *rtwdev, u32 addr, u32 bit)
//{
//	  u32 val;
//
//	  val = rtw_read32(rtwdev, addr);
//	  rtw_write32(rtwdev, addr, val & ~bit);
//}

bool check_hw_ready(struct rtw_dev *rtwdev, u32 addr, u32 mask, u32 target)
{
	u32 cnt;

	for (cnt = 0; cnt < 1000; cnt++) {
		if (rtw_read32_mask(rtwdev, addr, mask) == target)
			return true;

		// XXX:misha udelay?
//		  udelay(10);
		DELAY(1000);
	}

	return false;
}


static inline int
rtw_hci_write_data_rsvd_page(struct rtw_dev *rtwdev, u8 *buf, u32 size)
{
	return rtwdev->hci.ops->write_data_rsvd_page(rtwdev, buf, size);
}

// }}}

// {{{ other stuff

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

// }}}

// {{{ rtw88_download_firmware

int rtw_fw_write_data_rsvd_page(struct rtw_dev *rtwdev, u16 pg_addr,
				u8 *buf, u32 size)
{
	u8 bckp[2];
	u8 val;
//	  u16 rsvd_pg_head;
	u32 bcn_valid_addr;
	u32 bcn_valid_mask;
	int ret;

	// XXX:misha -- KASSERT here
//	  lockdep_assert_held(&rtwdev->mutex);

	if (!size)
		return -EINVAL;

	if (rtw_chip_wcpu_11n(rtwdev)) {
		rtw_write32_set(rtwdev, REG_DWBCN0_CTRL, BIT_BCN_VALID);
	} else {
		pg_addr &= BIT_MASK_BCN_HEAD_1_V1;
		pg_addr |= BIT_BCN_VALID_V1;
		rtw_write16(rtwdev, REG_FIFOPAGE_CTRL_2, pg_addr);
	}

	val = rtw_read8(rtwdev, REG_CR + 1);
	bckp[0] = val;
	val |= BIT_ENSWBCN >> 8;
	rtw_write8(rtwdev, REG_CR + 1, val);

	if (rtw_hci_type(rtwdev) == RTW88_HCI_TYPE_PCIE) {
		val = rtw_read8(rtwdev, REG_FWHW_TXQ_CTRL + 2);
		bckp[1] = val;
		val &= ~(BIT_EN_BCNQ_DL >> 16);
		rtw_write8(rtwdev, REG_FWHW_TXQ_CTRL + 2, val);
	}

	ret = rtw_hci_write_data_rsvd_page(rtwdev, buf, size);
	if (ret) {
		printf("%s: failed to write data to rsvd page\n", __func__);
		// FIXME:misha -- remove return
//		  goto restore;
		return ret;
	}

	if (rtw_chip_wcpu_11n(rtwdev)) {
		bcn_valid_addr = REG_DWBCN0_CTRL;
		bcn_valid_mask = BIT_BCN_VALID;
	} else {
		bcn_valid_addr = REG_FIFOPAGE_CTRL_2;
		bcn_valid_mask = BIT_BCN_VALID_V1;
	}

	if (!check_hw_ready(rtwdev, bcn_valid_addr, bcn_valid_mask, 1)) {
		printf("%s: error beacon valid\n", __func__);
		ret = -EBUSY;
	}

//restore:
//	  rsvd_pg_head = rtwdev->fifo.rsvd_boundary;
//	  rtw_write16(rtwdev, REG_FIFOPAGE_CTRL_2,
//		      rsvd_pg_head | BIT_BCN_VALID_V1);
//	  if (rtw_hci_type(rtwdev) == RTW88_HCI_TYPE_PCIE)
//		  rtw_write8(rtwdev, REG_FWHW_TXQ_CTRL + 2, bckp[1]);
//	  rtw_write8(rtwdev, REG_CR + 1, bckp[0]);

	return ret;
}

#define TX_DESC_SIZE 48

static int send_firmware_pkt_rsvd_page(struct rtw_dev *rtwdev, u16 pg_addr,
				       const u8 *data, u32 size)
{
	u8 *buf;
	int ret;

//	  buf = kmemdup(data, size, GFP_KERNEL);
	// XXX:misha -- M_NOWAIT? why kmemdup at all?
	buf = malloc(size, M_DEVBUF, M_NOWAIT);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, data, size);

	ret = rtw_fw_write_data_rsvd_page(rtwdev, pg_addr, buf, size);
	// FIXME: misha -- free?
//	  kfree(buf);
	return ret;
}


static int
send_firmware_pkt(struct rtw_dev *rtwdev, u16 pg_addr, const u8 *data, u32 size)
{
	int ret;

	if (rtw_hci_type(rtwdev) == RTW88_HCI_TYPE_USB &&
	    !((size + TX_DESC_SIZE) & (512 - 1)))
		size += 1;

	ret = send_firmware_pkt_rsvd_page(rtwdev, pg_addr, data, size);
	if (ret)
		printf("%s: failed to download rsvd page\n", __func__);

	return ret;
}

static int
download_firmware_to_mem(struct rtw_dev *rtwdev, const u8 *data,
			 u32 src, u32 dst, u32 size)
{
//	  const struct rtw_chip_info *chip = rtwdev->chip;
//	  u32 desc_size = chip->tx_pkt_desc_sz;
	u8 first_part;
	u32 mem_offset;
	u32 residue_size;
	u32 pkt_size;
	u32 max_size = 0x1000;
	u32 val;
	int ret;

	mem_offset = 0;
	first_part = 1;
	residue_size = size;

	val = rtw_read32(rtwdev, REG_DDMA_CH0CTRL);
	val |= BIT_DDMACH0_RESET_CHKSUM_STS;
	rtw_write32(rtwdev, REG_DDMA_CH0CTRL, val);

	while (residue_size) {
		if (residue_size >= max_size)
			pkt_size = max_size;
		else
			pkt_size = residue_size;

		ret = send_firmware_pkt(rtwdev, (u16)(src >> 7),
					data + mem_offset, pkt_size);
		if (ret)
			return ret;

//		  ret = iddma_download_firmware(rtwdev, OCPBASE_TXBUF_88XX +
//						src + desc_size,
//						dst + mem_offset, pkt_size,
//						first_part);
//		  if (ret)
//			  return ret;

		first_part = 0;
		mem_offset += pkt_size;
		residue_size -= pkt_size;
	}

//	  if (!check_fw_checksum(rtwdev, dst))
//		  return -EINVAL;

	return 0;
}

static int
start_download_firmware(struct rtw_dev *rtwdev, const u8 *data, u32 size)
{
	const struct rtw_fw_hdr *fw_hdr = (const struct rtw_fw_hdr *)data;
	const u8 *cur_fw;
	u16 val;
	u32 imem_size;
	u32 dmem_size;
	u32 emem_size;
	u32 addr;
	int ret;

	dmem_size = le32_to_cpu(fw_hdr->dmem_size);
	imem_size = le32_to_cpu(fw_hdr->imem_size);
	emem_size = (fw_hdr->mem_usage & BIT(4)) ?
		    le32_to_cpu(fw_hdr->emem_size) : 0;
	dmem_size += FW_HDR_CHKSUM_SIZE;
	imem_size += FW_HDR_CHKSUM_SIZE;
	emem_size += emem_size ? FW_HDR_CHKSUM_SIZE : 0;

	val = (u16)(rtw_read16(rtwdev, REG_MCUFW_CTRL) & 0x3800);
	val |= BIT_MCUFWDL_EN;
	rtw_write16(rtwdev, REG_MCUFW_CTRL, val);

	cur_fw = data + FW_HDR_SIZE;
	addr = le32_to_cpu(fw_hdr->dmem_addr);
	addr &= ~BIT(31);
	ret = download_firmware_to_mem(rtwdev, cur_fw, 0, addr, dmem_size);
	if (ret)
		return ret;

	cur_fw = data + FW_HDR_SIZE + dmem_size;
	addr = le32_to_cpu(fw_hdr->imem_addr);
	addr &= ~BIT(31);
	ret = download_firmware_to_mem(rtwdev, cur_fw, 0, addr, imem_size);
	if (ret)
		return ret;

	if (emem_size) {
		cur_fw = data + FW_HDR_SIZE + dmem_size + imem_size;
		addr = le32_to_cpu(fw_hdr->emem_addr);
		addr &= ~BIT(31);
		ret = download_firmware_to_mem(rtwdev, cur_fw, 0, addr,
					       emem_size);
		if (ret)
			return ret;
	}

	return 0;
}

static void download_firmware_reset_platform(struct rtw_dev *rtwdev)
{
	rtw_write8_clr(rtwdev, REG_CPU_DMEM_CON + 2, BIT_WL_PLATFORM_RST >> 16);
	rtw_write8_clr(rtwdev, REG_SYS_CLK_CTRL + 1, BIT_CPU_CLK_EN >> 8);
	rtw_write8_set(rtwdev, REG_CPU_DMEM_CON + 2, BIT_WL_PLATFORM_RST >> 16);
	rtw_write8_set(rtwdev, REG_SYS_CLK_CTRL + 1, BIT_CPU_CLK_EN >> 8);
}

static void download_firmware_reg_backup(struct rtw_dev *rtwdev,
					 struct rtw_backup_info *bckp)
{
	u8 tmp;
	u8 bckp_idx = 0;

	/* set HIQ to hi priority */
	bckp[bckp_idx].len = 1;
	bckp[bckp_idx].reg = REG_TXDMA_PQ_MAP + 1;
	bckp[bckp_idx].val = rtw_read8(rtwdev, REG_TXDMA_PQ_MAP + 1);
	bckp_idx++;
	tmp = RTW_DMA_MAPPING_HIGH << 6;
	rtw_write8(rtwdev, REG_TXDMA_PQ_MAP + 1, tmp);

	/* DLFW only use HIQ, map HIQ to hi priority */
	bckp[bckp_idx].len = 1;
	bckp[bckp_idx].reg = REG_CR;
	bckp[bckp_idx].val = rtw_read8(rtwdev, REG_CR);
	bckp_idx++;
	bckp[bckp_idx].len = 4;
	bckp[bckp_idx].reg = REG_H2CQ_CSR;
	bckp[bckp_idx].val = BIT_H2CQ_FULL;
	bckp_idx++;
	tmp = BIT_HCI_TXDMA_EN | BIT_TXDMA_EN;
	rtw_write8(rtwdev, REG_CR, tmp);
	rtw_write32(rtwdev, REG_H2CQ_CSR, BIT_H2CQ_FULL);

	/* Config hi priority queue and public priority queue page number */
	bckp[bckp_idx].len = 2;
	bckp[bckp_idx].reg = REG_FIFOPAGE_INFO_1;
	bckp[bckp_idx].val = rtw_read16(rtwdev, REG_FIFOPAGE_INFO_1);
	bckp_idx++;
	bckp[bckp_idx].len = 4;
	bckp[bckp_idx].reg = REG_RQPN_CTRL_2;
	bckp[bckp_idx].val = rtw_read32(rtwdev, REG_RQPN_CTRL_2) | BIT_LD_RQPN;
	bckp_idx++;
	rtw_write16(rtwdev, REG_FIFOPAGE_INFO_1, 0x200);
	rtw_write32(rtwdev, REG_RQPN_CTRL_2, bckp[bckp_idx - 1].val);

	//XXX:misha -- usb only
//	  if (rtw_hci_type(rtwdev) == RTW88_HCI_TYPE_SDIO)
//		  rtw_read32(rtwdev, REG_SDIO_FREE_TXPG);

	/* Disable beacon related functions */
	tmp = rtw_read8(rtwdev, REG_BCN_CTRL);
	bckp[bckp_idx].len = 1;
	bckp[bckp_idx].reg = REG_BCN_CTRL;
	bckp[bckp_idx].val = tmp;
	bckp_idx++;
	tmp = (u8)((tmp & (~BIT_EN_BCN_FUNCTION)) | BIT_DIS_TSF_UDT);
	rtw_write8(rtwdev, REG_BCN_CTRL, tmp);

//	  WARN(bckp_idx != DLFW_RESTORE_REG_NUM, "wrong backup number\n");
	if (bckp_idx != DLFW_RESTORE_REG_NUM)
		printf("%s: wrong backup number: %i\n", __func__, bckp_idx);
}


static void wlan_cpu_enable(struct rtw_dev *rtwdev, bool enable)
{
	if (enable) {
		/* cpu io interface enable */
		rtw_write8_set(rtwdev, REG_RSV_CTRL + 1, BIT_WLMCU_IOIF);

		/* cpu enable */
		rtw_write8_set(rtwdev, REG_SYS_FUNC_EN + 1, BIT_FEN_CPUEN);
	} else {
		/* cpu io interface disable */
		rtw_write8_clr(rtwdev, REG_SYS_FUNC_EN + 1, BIT_FEN_CPUEN);

		/* cpu disable */
		rtw_write8_clr(rtwdev, REG_RSV_CTRL + 1, BIT_WLMCU_IOIF);
	}
}


bool ltecoex_read_reg(struct rtw_dev *rtwdev, u16 offset, u32 *val)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	const struct rtw_ltecoex_addr *ltecoex = chip->ltecoex_addr;

	if (!check_hw_ready(rtwdev, ltecoex->ctrl, LTECOEX_READY, 1))
		return false;

	rtw_write32(rtwdev, ltecoex->ctrl, 0x800F0000 | offset);
	*val = rtw_read32(rtwdev, ltecoex->rdata);

	return true;
}

static bool check_firmware_size(const u8 *data, u32 size)
{
	const struct rtw_fw_hdr *fw_hdr = (const struct rtw_fw_hdr *)data;
	u32 dmem_size;
	u32 imem_size;
	u32 emem_size;
	u32 real_size;

	dmem_size = le32_to_cpu(fw_hdr->dmem_size);
	imem_size = le32_to_cpu(fw_hdr->imem_size);
	emem_size = (fw_hdr->mem_usage & BIT(4)) ?
		    le32_to_cpu(fw_hdr->emem_size) : 0;

	dmem_size += FW_HDR_CHKSUM_SIZE;
	imem_size += FW_HDR_CHKSUM_SIZE;
	emem_size += emem_size ? FW_HDR_CHKSUM_SIZE : 0;
	real_size = FW_HDR_SIZE + dmem_size + imem_size + emem_size;
	if (real_size != size)
		return false;

	return true;
}

static int __rtw_download_firmware(struct rtw_dev *rtwdev,
				   struct rtw_fw_state *fw)
{
	struct rtw_backup_info bckp[DLFW_RESTORE_REG_NUM];
	const u8 *data = fw->fwdata;
	u32 size = fw->fwsize;
//	u32 ltecoex_bckp;
	int ret;

	if (!check_firmware_size(data, size)) {
		printf("%s: invalid fw size\n", __func__);
		return -EINVAL;
	};
//
	// TODO: returns EBUSY
//	if (!ltecoex_read_reg(rtwdev, 0x38, &ltecoex_bckp)) {
//		printf("%s: !ltecoex_read_reg\n", __func__);
//		return -EBUSY;
//	}
//
	wlan_cpu_enable(rtwdev, false);
//
	download_firmware_reg_backup(rtwdev, bckp);
	download_firmware_reset_platform(rtwdev);
//
	ret = start_download_firmware(rtwdev, data, size);
	if (ret) {
		printf("%s: start_download_firmware=%d\n", __func__, ret);
		goto dlfw_fail;
	};
//
//	download_firmware_reg_restore(rtwdev, bckp, DLFW_RESTORE_REG_NUM);
//
//	download_firmware_end_flow(rtwdev);
//
//	wlan_cpu_enable(rtwdev, true);
//
//	if (!ltecoex_reg_write(rtwdev, 0x38, ltecoex_bckp)) {
//		ret = -EBUSY;
//		goto dlfw_fail;
//	}
//
//	ret = download_firmware_validate(rtwdev);
//	if (ret)
//		goto dlfw_fail;
//
//	/* reset desc and index */
//	rtw_hci_setup(rtwdev);
//
//	rtwdev->h2c.last_box_num = 0;
//	rtwdev->h2c.seq = 0;
//
//	set_bit(RTW_FLAG_FW_RUNNING, rtwdev->flags);
//
	return 0;
//
dlfw_fail:
	/* Disable FWDL_EN */
	rtw_write8_clr(rtwdev, REG_MCUFW_CTRL, BIT_MCUFWDL_EN);
	rtw_write8_set(rtwdev, REG_SYS_FUNC_EN + 1, BIT_FEN_CPUEN);

	return ret;
}

static
int _rtw_download_firmware(struct rtw_dev *rtwdev, struct rtw_fw_state *fw)
{
	// XXX:misha -- we work with AC device only for now
//	if (rtw_chip_wcpu_11n(rtwdev))
//		return __rtw_download_firmware_legacy(rtwdev, fw);

	return __rtw_download_firmware(rtwdev, fw);
}

int rtw_download_firmware(struct rtw_dev *rtwdev, struct rtw_fw_state *fw)
{
	int ret;

	ret = _rtw_download_firmware(rtwdev, fw);
	if (ret)
		return ret;

	// XXX:misha -- not applicable for urtwm
//	if (rtw_hci_type(rtwdev) == RTW_HCI_TYPE_PCIE &&
//	    rtwdev->chip->id == RTW_CHIP_TYPE_8821C)
//		rtw_fw_set_recover_bt_device(rtwdev);

	return 0;
}

// }}}

// {{{ rtw88_mac_power_on

int
__rtw88_mac_init_system_cfg(struct rtw_dev *rtwdev)
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
__rtw88_mac_init_system_cfg_legacy(struct rtw_dev *rtwdev)
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
rtw88_mac_init_system_cfg(struct rtw_dev *rtwdev)
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
rtw88_do_pwr_poll_cmd(struct rtw_dev *rtwdev, uint32_t addr, uint32_t mask,
    uint32_t target)
{
	uint32_t val;

	target &= mask;

	return read_poll_timeout_atomic(rtw88_read8, val, (val & mask) == target,
	    50, 50 * RTW88_RTW_PWR_POLLING_CNT, false,
	    rtwdev, addr) == 0;
}


int
rtw88_pwr_cmd_polling(struct rtw_dev *rtwdev, const struct rtw88_pwr_seq_cmd *cmd)
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

int rtw88_sub_pwr_seq_parser(struct rtw_dev *rtwdev, uint8_t intf_mask,
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
rtw88_pwr_seq_parser(struct rtw_dev *rtwdev,
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
rtw88_mac_power_switch(struct rtw_dev *rtwdev, int pwr_on)
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
rtw88_mac_pre_system_cfg(struct rtw_dev *rtwdev)
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
rtw88_mac_power_on(struct rtw_dev *rtwdev)
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

void rtw_mac_power_off(struct rtw_dev *rtwdev)
{
	rtw88_mac_power_switch(rtwdev, false);
}

// }}}

int
rtw88_chip_efuse_enable(struct rtw_dev *rtwdev)
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


	ret = rtw_download_firmware(rtwdev, fw);
	if (ret) {
		printf("%s: %s: failed to download firmware, error=%i\n",
//		    sc->sc_pdev->dv_xname, __func__, ret);
		    "HARDCODED NOT NULL", __func__, ret);
		goto err_off;
	}

	return 0;
//
err_off:
	rtw_mac_power_off(rtwdev);

err:
	return ret;
}

int
rtw88_chip_efuse_info_setup(struct rtw_dev *rtwdev) {
//	struct urtwm_softc *sc = rtwdev->cookie;
//	struct rtw88_efuse *efuse = &rtwdev->efuse;
	int ret;

	/* power on mac to read efuse */
	ret = rtw88_chip_efuse_enable(rtwdev);
	if (ret) {
		printf("%s: %s: rtw_chip_efuse_enable failed, error=%i\n",
//		    sc->sc_pdev->dv_xname, __func__, ret);
		    "HARDCODED NOT NULL", __func__, ret);
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
rtw88_chip_parameter_setup(struct rtw_dev *rtwdev)
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


static int dma_mapping_to_ep(enum rtw_dma_mapping dma_mapping)
{
        switch (dma_mapping) {
        case RTW_DMA_MAPPING_HIGH:
                return 0;
        case RTW_DMA_MAPPING_NORMAL:
                return 1;
        case RTW_DMA_MAPPING_LOW:
                return 2;
        case RTW_DMA_MAPPING_EXTRA:
                return 3;
        default:
                return -EINVAL;
        }
}

// TODO: proper cleanup (goto fail)
static int rtw_usb_parse(struct rtw_dev *rtwdev)
{
//	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
//	struct usb_host_interface *host_interface = &interface->altsetting[0];
//	struct usb_interface_descriptor *interface_desc = &host_interface->desc;
//	struct usb_endpoint_descriptor *endpoint;
//	int num_out_pipes = 0;
//	int i;
//	u8 num;
	const struct rtw_chip_info *chip = rtwdev->chip;
	const struct rtw_rqpn *rqpn;
	struct urtwm_softc *sc = rtwdev->cookie;
	uint8_t rx_no, int_no, out_no;
	usb_interface_descriptor_t *id;
	usb_endpoint_descriptor_t *ed;
	int i, error, nrx = 0, nint = 0, num_out_pipes = 0;

	id = usbd_get_interface_descriptor(sc->sc_iface);
//	for (i = 0; i < interface_desc->bNumEndpoints; i++) {
//		endpoint = &host_interface->endpoint[i].desc;
//		num = usb_endpoint_num(endpoint);
//
//		if (usb_endpoint_dir_in(endpoint) &&
//		    usb_endpoint_xfer_bulk(endpoint)) {
//			if (rtwusb->pipe_in) {
//				rtw_err(rtwdev, "IN pipes overflow\n");
//				return -EINVAL;
//			}
//
//			rtwusb->pipe_in = num;
//		}
//
//		if (usb_endpoint_dir_in(endpoint) &&
//		    usb_endpoint_xfer_int(endpoint)) {
//			if (rtwusb->pipe_interrupt) {
//				rtw_err(rtwdev, "INT pipes overflow\n");
//				return -EINVAL;
//			}
//
//			rtwusb->pipe_interrupt = num;
//		}
//
//		if (usb_endpoint_dir_out(endpoint) &&
//		    usb_endpoint_xfer_bulk(endpoint)) {
//			if (num_out_pipes >= ARRAY_SIZE(rtwusb->out_ep)) {
//				rtw_err(rtwdev, "OUT pipes overflow\n");
//				return -EINVAL;
//			}
//
//			rtwusb->out_ep[num_out_pipes++] = num;
//		}
//	}
	for (i = 0; i < id->bNumEndpoints; i++) {
		printf("%s: i=%i\n", __func__, i);
		ed = usbd_interface2endpoint_descriptor(sc->sc_iface, i);
//
////		if (ed == NULL || UE_GET_XFERTYPE(ed->bmAttributes) != UE_BULK)
////			continue;
//
//		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN) {
//			rx_no = ed->bEndpointAddress;
//			nrx++;
//		} else {
//			if (sc->ntx < R92C_MAX_EPOUT)
//				epaddr[sc->ntx] = ed->bEndpointAddress;
//			sc->ntx++;
//		}
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK) {
			if (nrx) {
				printf("%s: %s: IN pipes overflow\n",
				    sc->sc_pdev->dv_xname, __func__);
				return EINVAL;
			}
			rx_no = ed->bEndpointAddress;
			nrx++;
			error = usbd_open_pipe(sc->sc_iface, rx_no, 0,
			    &sc->rx_pipe);
			if (error != 0) {
				printf("%s: %s could not open Rx bulk pipe, "
				    "error=%i\n", sc->sc_pdev->dv_xname,
				    __func__, error);
				return EINVAL;
			}
		}

		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_INTERRUPT) {
			if (nint) {
				printf("%s: %s: INT pipes overflow\n",
				    sc->sc_pdev->dv_xname, __func__);
				return EINVAL;
			}
			int_no = ed->bEndpointAddress;
			nint++;
			error = usbd_open_pipe(sc->sc_iface, int_no, 0,
			    &sc->int_pipe);
			if (error != 0) {
				printf("%s: %s could not open Int pipe, "
				    "error=%i\n", sc->sc_pdev->dv_xname,
				    __func__, error);
				return EINVAL;
			}

		}

		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK) {
			if (num_out_pipes >= nitems(sc->tx_pipe)) {
				printf("%s: %s: OUT pipes overflow\n",
				    sc->sc_pdev->dv_xname, __func__);
				return EINVAL;
			}
			out_no = ed->bEndpointAddress;
			error = usbd_open_pipe(sc->sc_iface, out_no, 0,
			    &sc->tx_pipe[num_out_pipes++]);
			if (error != 0) {
				printf("%s: %s could not open Tx bulk pipe "
				    "0x%02x\n, error=%i\n",
				    sc->sc_pdev->dv_xname, __func__,  out_no,
				    error);
				return EINVAL;
			}
		}

	}

//	rtwdev->hci.bulkout_num = num_out_pipes;
//
//	if (num_out_pipes < 1 || num_out_pipes > 4) {
//		rtw_err(rtwdev, "invalid number of endpoints %d\n", num_out_pipes);
//		return -EINVAL;
//	}
	if (num_out_pipes < 1 || num_out_pipes > 4) {
		printf("%s: %s invalid number of endpoints %d\n",
		    sc->sc_pdev->dv_xname, __func__, num_out_pipes);
		return EINVAL;
	}
	rqpn = &chip->rqpn_table[num_out_pipes];
//
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID0] = dma_mapping_to_ep(rqpn->dma_map_be);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID1] = dma_mapping_to_ep(rqpn->dma_map_bk);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID2] = dma_mapping_to_ep(rqpn->dma_map_bk);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID3] = dma_mapping_to_ep(rqpn->dma_map_be);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID4] = dma_mapping_to_ep(rqpn->dma_map_vi);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID5] = dma_mapping_to_ep(rqpn->dma_map_vi);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID6] = dma_mapping_to_ep(rqpn->dma_map_vo);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID7] = dma_mapping_to_ep(rqpn->dma_map_vo);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID8] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID9] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID10] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID11] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID12] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID13] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID14] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_TID15] = -EINVAL;
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_BEACON] = dma_mapping_to_ep(rqpn->dma_map_hi);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_HIGH] = dma_mapping_to_ep(rqpn->dma_map_hi);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_MGMT] = dma_mapping_to_ep(rqpn->dma_map_mg);
//	rtwusb->qsel_to_ep[TX_DESC_QSEL_H2C] = dma_mapping_to_ep(rqpn->dma_map_hi);

	sc->qsel_to_ep[TX_DESC_QSEL_TID0] = dma_mapping_to_ep(rqpn->dma_map_be);
	sc->qsel_to_ep[TX_DESC_QSEL_TID1] = dma_mapping_to_ep(rqpn->dma_map_bk);
	sc->qsel_to_ep[TX_DESC_QSEL_TID2] = dma_mapping_to_ep(rqpn->dma_map_bk);
	sc->qsel_to_ep[TX_DESC_QSEL_TID3] = dma_mapping_to_ep(rqpn->dma_map_be);
	sc->qsel_to_ep[TX_DESC_QSEL_TID4] = dma_mapping_to_ep(rqpn->dma_map_vi);
	sc->qsel_to_ep[TX_DESC_QSEL_TID5] = dma_mapping_to_ep(rqpn->dma_map_vi);
	sc->qsel_to_ep[TX_DESC_QSEL_TID6] = dma_mapping_to_ep(rqpn->dma_map_vo);
	sc->qsel_to_ep[TX_DESC_QSEL_TID7] = dma_mapping_to_ep(rqpn->dma_map_vo);
	sc->qsel_to_ep[TX_DESC_QSEL_TID8] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_TID9] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_TID10] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_TID11] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_TID12] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_TID13] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_TID14] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_TID15] = -EINVAL;
	sc->qsel_to_ep[TX_DESC_QSEL_BEACON] = dma_mapping_to_ep(rqpn->dma_map_hi);
	sc->qsel_to_ep[TX_DESC_QSEL_HIGH] = dma_mapping_to_ep(rqpn->dma_map_hi);
	sc->qsel_to_ep[TX_DESC_QSEL_MGMT] = dma_mapping_to_ep(rqpn->dma_map_mg);
	sc->qsel_to_ep[TX_DESC_QSEL_H2C] = dma_mapping_to_ep(rqpn->dma_map_hi);
	return 0;
}


static int rtw_usb_intf_init(struct rtw_dev *rtwdev)
{
//	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
//	struct usb_device *udev = usb_get_dev(interface_to_usbdev(intf));
	int ret;
//
//	rtwusb->udev = udev;
	ret = rtw_usb_parse(rtwdev);
	if (ret)
		return ret;
//
//	rtwusb->usb_data = kcalloc(RTW_USB_MAX_RXTX_COUNT, sizeof(u32),
//				   GFP_KERNEL);
//	if (!rtwusb->usb_data)
//		return -ENOMEM;
//
//	usb_set_intfdata(intf, rtwdev->hw);
//
//	SET_IEEE80211_DEV(rtwdev->hw, &intf->dev);
//	spin_lock_init(&rtwusb->usb_lock);

	return 0;
}

void
urtwm_attach(struct device *parent, struct device *self, void *aux)
{
	struct urtwm_softc *sc = (struct urtwm_softc *)self;
	struct rtw88_softc *sc_sc = &sc->sc_sc;
	struct rtw_dev *rtwdev = &sc_sc->rtw_dev;
	struct usb_attach_arg *uaa = aux;
	int ret;

	sc->sc_udev = uaa->device;
	sc->sc_iface = uaa->iface;

	rtwdev->chip = &rtw8822b_hw_spec;

	rtwdev->hci.type = RTW88_HCI_TYPE_USB;
	rtwdev->hci.ops = &rtw88_usb_ops;
	rtwdev->cookie = sc;

	usb_init_task(&sc->sc_task, urtwm_task, sc, USB_TASK_TYPE_GENERIC);

//	ret = rtw_usb_alloc_rx_bufs(rtwusb);
//	if (ret)
//		goto err_release_hw;
//
//	// TODO - ATTENTION - some flags are set here
//	ret = rtw_core_init(rtwdev);
//	if (ret)
//		goto err_free_rx_bufs;

	// TODO - setup usb before downloading firmware
	ret = rtw_usb_intf_init(rtwdev);
	if (ret) {
//		rtw_err(rtwdev, "failed to init USB interface\n");
		printf("%s: %s: failed to init USB interface, error=%i\n",
//		    sc->sc_pdev->dv_xname, __func__, ret);
		    "HARDCODED NOT NULL", __func__, ret);
		return;
		// TODO: cleanup
//		goto err_deinit_core;
	}
//
//	ret = rtw_usb_init_tx(rtwdev);
//	if (ret) {
//		rtw_err(rtwdev, "failed to init USB TX\n");
//		goto err_destroy_usb;
//	}
//
//	ret = rtw_usb_init_rx(rtwdev);
//	if (ret) {
//		rtw_err(rtwdev, "failed to init USB RX\n");
//		goto err_destroy_txwq;
//	}

	ret = rtw88_chip_parameter_setup(rtwdev);
	if (ret) {
		printf("%s: %s: failed to setup chip parameters, error=%i\n",
//		    sc->sc_pdev->dv_xname, __func__, ret);
		    "HARDCODED NOT NULL", __func__, ret);
		return;
	}

	ret = rtw88_chip_efuse_info_setup(rtwdev);
	if (ret) {
		printf("%s: %s: failed to setup chip efuse info, error=%i\n",
//		    sc->sc_pdev->dv_xname, __func__, ret);
		    "HARDCODED NOT NULL", __func__, ret);
		return;
	}
	return;
}

int
urtwm_detach(struct device *self, int flags)
{
	return (0);
}
