#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "os/os.h"
#include "nimble/nimble_port.h"
#include "nimble/transport.h"
#include "nimble/hci_common.h"
#include "host/ble_hs.h"
#include "host/ble_hs_hci.h"
#include "host/ble_att.h"
#include "host/ble_store.h"
#include "host/ble_sm.h"
#include "host/ble_l2cap.h"
#include "host/ble_hs_mbuf.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/ans/ble_svc_ans.h"
#include "services/bas/ble_svc_bas.h"
#include "services/dis/ble_svc_dis.h"
#include "services/ias/ble_svc_ias.h"
#include "services/lls/ble_svc_lls.h"
#include "services/tps/ble_svc_tps.h"

#include "ble_hs_priv.h"
#include "ble_hs_conn_priv.h"
#include "nimble_env.h"

#define PUT_LE16(p, v) do { (p)[0] = (uint8_t)(v); (p)[1] = (uint8_t)((v) >> 8); } while (0)

extern void ble_store_config_init(void);
typedef int ble_hs_hci_phony_ack_fn(uint8_t *ack, int ack_buf_len);
extern void ble_hs_hci_set_phony_ack_cb(ble_hs_hci_phony_ack_fn *cb);

uint16_t env_conn_handle = 0x0042;
int env_connected;

static uint16_t last_opcode;
static size_t tx_count;
static uint8_t tx_last[512];
static size_t tx_last_len;
static uint32_t rand_ctr;

static const uint8_t pub_addr[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
static const uint8_t peer_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

/* ---- fake controller (transport LL side) ------------------------------ */

int
ble_transport_to_ll_cmd_impl(void *buf)
{
    const uint8_t *b = buf;

    last_opcode = (uint16_t)(b[0] | (b[1] << 8));
    ble_transport_free(buf);
    return 0;
}

int
ble_transport_to_ll_acl_impl(struct os_mbuf *om)
{
    uint16_t len = OS_MBUF_PKTLEN(om);

    tx_count++;
    tx_last_len = len < sizeof tx_last ? len : sizeof tx_last;
    os_mbuf_copydata(om, 0, tx_last_len, tx_last);
    os_mbuf_free_chain(om);
    return 0;
}

int
ble_transport_to_ll_iso_impl(struct os_mbuf *om)
{
    os_mbuf_free_chain(om);
    return 0;
}

void
ble_transport_ll_init(void)
{
}

struct opcode_rsp {
    uint16_t opcode;
    uint8_t len;
};

#define OP(ogf, ocf) BLE_HCI_OP(ogf, ocf)

static int
phony_ack(uint8_t *ack, int ack_buf_len)
{
    uint8_t *rp = ack + 6;
    uint8_t plen = 0;

    memset(rp, 0, 64);

    switch (last_opcode) {
    case OP(BLE_HCI_OGF_INFO_PARAMS, BLE_HCI_OCF_IP_RD_LOCAL_VER):
        rp[0] = 0x09;
        plen = sizeof(struct ble_hci_ip_rd_local_ver_rp);
        break;
    case OP(BLE_HCI_OGF_INFO_PARAMS, BLE_HCI_OCF_IP_RD_LOC_SUPP_CMD): {
        static const uint8_t cmds[64] = {
            0x20, 0x00, 0x80, 0x00, 0x00, 0xc0, 0x00, 0x00,
            0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0x28, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0xf7, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00,
            0x00, 0xf0, 0xf9, 0xff, 0xff, 0xff, 0xff, 0x07,
            0xe0, 0x63, 0xe0, 0x04, 0x02, 0x00, 0x03, 0x00,
        };
        memcpy(rp, cmds, sizeof cmds);
        plen = sizeof(struct ble_hci_ip_rd_loc_supp_cmd_rp);
        break;
    }
    case OP(BLE_HCI_OGF_INFO_PARAMS, BLE_HCI_OCF_IP_RD_LOC_SUPP_FEAT):
        rp[4] = 0x60;
        plen = sizeof(struct ble_hci_ip_rd_loc_supp_feat_rp);
        break;
    case OP(BLE_HCI_OGF_INFO_PARAMS, BLE_HCI_OCF_IP_RD_BUF_SIZE):
        PUT_LE16(rp, 251);
        PUT_LE16(rp + 3, 8);
        plen = sizeof(struct ble_hci_ip_rd_buf_size_rp);
        break;
    case OP(BLE_HCI_OGF_INFO_PARAMS, BLE_HCI_OCF_IP_RD_BD_ADDR):
        memcpy(rp, pub_addr, 6);
        plen = sizeof(struct ble_hci_ip_rd_bd_addr_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RD_BUF_SIZE):
        PUT_LE16(rp, 251);
        rp[2] = 200;
        plen = sizeof(struct ble_hci_le_rd_buf_size_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RD_LOC_SUPP_FEAT):
        plen = sizeof(struct ble_hci_le_rd_loc_supp_feat_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RAND):
        rand_ctr = rand_ctr * 1664525u + 1013904223u;
        memcpy(rp, &rand_ctr, 4);
        memcpy(rp + 4, &rand_ctr, 4);
        plen = sizeof(struct ble_hci_le_rand_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RD_ADV_CHAN_TXPWR):
        plen = sizeof(struct ble_hci_le_rd_adv_chan_txpwr_rp);
        break;
    case OP(BLE_HCI_OGF_STATUS_PARAMS, BLE_HCI_OCF_RD_RSSI):
        PUT_LE16(rp, env_conn_handle);
        plen = sizeof(struct ble_hci_rd_rssi_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_SET_DATA_LEN):
        PUT_LE16(rp, env_conn_handle);
        plen = sizeof(struct ble_hci_le_set_data_len_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RD_SUGG_DEF_DATA_LEN):
        PUT_LE16(rp, 27);
        PUT_LE16(rp + 2, 328);
        plen = sizeof(struct ble_hci_le_rd_sugg_def_data_len_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RD_CHAN_MAP):
        PUT_LE16(rp, env_conn_handle);
        plen = sizeof(struct ble_hci_le_rd_chan_map_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_LT_KEY_REQ_REPLY):
        PUT_LE16(rp, env_conn_handle);
        plen = sizeof(struct ble_hci_le_lt_key_req_reply_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_LT_KEY_REQ_NEG_REPLY):
        PUT_LE16(rp, env_conn_handle);
        plen = sizeof(struct ble_hci_le_lt_key_req_neg_reply_cp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RD_PHY):
        PUT_LE16(rp, env_conn_handle);
        rp[2] = 1;
        rp[3] = 1;
        plen = sizeof(struct ble_hci_le_rd_phy_rp);
        break;
    case OP(BLE_HCI_OGF_LE, BLE_HCI_OCF_LE_RD_WHITE_LIST_SIZE):
        rp[0] = 8;
        plen = sizeof(struct ble_hci_le_rd_white_list_rp);
        break;
    default:
        break;
    }

    /* Command-complete event: evcode, len, num_pkts, opcode, status, params */
    ack[0] = BLE_HCI_EVCODE_COMMAND_COMPLETE;
    ack[1] = (uint8_t)(4 + plen);
    ack[2] = 1;
    PUT_LE16((ack + 3), last_opcode);
    ack[5] = 0;
    (void)ack_buf_len;
    return 0;
}

/* ---- injection helpers ------------------------------------------------- */

void
env_drain(void)
{
    struct ble_npl_eventq *q = nimble_port_get_dflt_eventq();
    struct ble_npl_event *ev;
    int guard = 0;

    while (guard++ < 10000 && (ev = ble_npl_eventq_get(q, 0)) != NULL) {
        ble_npl_event_run(ev);
    }
}

void
env_rx_evt(uint8_t evcode, const uint8_t *params, size_t len)
{
    uint8_t *buf;

    if (evcode == BLE_HCI_EVCODE_COMMAND_COMPLETE ||
        evcode == BLE_HCI_EVCODE_COMMAND_STATUS) {
        return;
    }
    if (len > MYNEWT_VAL(BLE_TRANSPORT_EVT_SIZE) - 2) {
        len = MYNEWT_VAL(BLE_TRANSPORT_EVT_SIZE) - 2;
    }
    buf = ble_transport_alloc_evt(0);
    if (buf == NULL) {
        return;
    }
    buf[0] = evcode;
    buf[1] = (uint8_t)len;
    memcpy(buf + 2, params, len);
    ble_transport_to_hs_evt(buf);
    env_drain();
}

void
env_rx_acl(uint16_t pb, const uint8_t *data, size_t len)
{
    struct os_mbuf *om;
    uint8_t hdr[4];

    if (len > 0xFFFF - 4) {
        len = 0xFFFF - 4;
    }
    om = ble_transport_alloc_acl_from_ll();
    if (om == NULL) {
        return;
    }
    PUT_LE16(hdr, (env_conn_handle & 0x0FFF) | ((pb & 3) << 12));
    PUT_LE16((hdr + 2), len);
    if (os_mbuf_append(om, hdr, 4) != 0 ||
        (len && os_mbuf_append(om, data, len) != 0)) {
        os_mbuf_free_chain(om);
        return;
    }
    ble_transport_to_hs_acl(om);
    env_drain();
}

void
env_rx_l2cap(uint16_t cid, const uint8_t *payload, size_t len)
{
    uint8_t *buf;

    if (len > 0xFFFF - 4) {
        len = 0xFFFF - 4;
    }
    buf = malloc(len + 4);
    PUT_LE16(buf, len);
    PUT_LE16((buf + 2), cid);
    memcpy(buf + 4, payload, len);
    env_rx_acl(0x2, buf, len + 4);
    free(buf);
}

size_t
env_tx_count(void)
{
    return tx_count;
}

size_t
env_tx_last(uint8_t *out, size_t max)
{
    size_t n = tx_last_len < max ? tx_last_len : max;

    memcpy(out, tx_last, n);
    return n;
}

void
env_tx_reset(void)
{
    tx_count = 0;
    tx_last_len = 0;
}

/* ---- connection management --------------------------------------------- */

static int
gap_event(struct ble_gap_event *event, void *arg)
{
    struct ble_sm_io io;

    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_PASSKEY_ACTION:
        memset(&io, 0, sizeof io);
        io.action = event->passkey.params.action;
        switch (io.action) {
        case BLE_SM_IOACT_NUMCMP:
            io.numcmp_accept = 1;
            break;
        case BLE_SM_IOACT_OOB:
            memset(io.oob, 0x5a, sizeof io.oob);
            break;
        default:
            io.passkey = 123456;
            break;
        }
        ble_sm_inject_io(event->passkey.conn_handle, &io);
        break;
    case BLE_GAP_EVENT_REPEAT_PAIRING:
        return BLE_GAP_REPEAT_PAIRING_IGNORE;
    default:
        break;
    }
    return 0;
}

int
env_start_scan(void)
{
    struct ble_gap_disc_params dp;

    memset(&dp, 0, sizeof dp);
    dp.passive = 0;
    dp.filter_duplicates = 0;
    return ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &dp, gap_event,
                        NULL);
}

int
env_start_adv(void)
{
    struct ble_gap_adv_params ap;

    memset(&ap, 0, sizeof ap);
    ap.conn_mode = BLE_GAP_CONN_MODE_UND;
    ap.disc_mode = BLE_GAP_DISC_MODE_GEN;
    return ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER, &ap,
                             gap_event, NULL);
}

int
env_connect(int role)
{
    struct ble_hci_ev_le_subev_conn_complete ev;
    uint8_t evbuf[2 + sizeof ev];
    ble_addr_t peer;
    int rc;

    env_tx_reset();
    memset(&peer, 0, sizeof peer);
    peer.type = BLE_ADDR_PUBLIC;
    memcpy(peer.val, peer_addr, 6);

    if (role == ENV_ROLE_MASTER) {
        rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer, 1000, NULL,
                             gap_event, NULL);
    } else {
        struct ble_gap_adv_params ap;

        memset(&ap, 0, sizeof ap);
        ap.conn_mode = BLE_GAP_CONN_MODE_UND;
        ap.disc_mode = BLE_GAP_DISC_MODE_GEN;
        rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                               &ap, gap_event, NULL);
    }
    if (rc != 0) {
        return rc;
    }

    env_conn_handle = 0x0042;
    memset(&ev, 0, sizeof ev);
    ev.subev_code = BLE_HCI_LE_SUBEV_CONN_COMPLETE;
    ev.status = 0;
    ev.conn_handle = env_conn_handle;
    ev.role = role == ENV_ROLE_MASTER ? 0 : 1;
    ev.peer_addr_type = BLE_ADDR_PUBLIC;
    memcpy(ev.peer_addr, peer_addr, 6);
    ev.conn_itvl = 24;
    ev.conn_latency = 0;
    ev.supervision_timeout = 200;

    evbuf[0] = BLE_HCI_EVCODE_LE_META;
    evbuf[1] = sizeof ev;
    memcpy(evbuf + 2, &ev, sizeof ev);
    env_rx_evt(evbuf[0], evbuf + 2, sizeof ev);

    env_connected = ble_hs_conn_exists(env_conn_handle);
    return env_connected ? 0 : -1;
}

static void
rx_conn_cancelled(void)
{
    struct ble_hci_ev_le_subev_conn_complete ev;

    memset(&ev, 0, sizeof ev);
    ev.subev_code = BLE_HCI_LE_SUBEV_CONN_COMPLETE;
    ev.status = BLE_ERR_UNK_CONN_ID;
    env_rx_evt(BLE_HCI_EVCODE_LE_META, (uint8_t *)&ev, sizeof ev);
}

/* Tear down every connection (an injected event can create ones other than env_conn_handle), a pending
 * connect, advertising, scanning and bonds, so no input leaves host state for the next one. */
void
env_disconnect(void)
{
    struct ble_hci_ev_disconn_cmp ev;
    struct ble_hs_conn *conn;
    uint16_t handle;
    int i;

    for (i = 0; i < 16; i++) {
        ble_hs_lock();
        conn = ble_hs_conn_first();
        handle = conn != NULL ? conn->bhc_handle : 0;
        ble_hs_unlock();
        if (conn == NULL) {
            break;
        }
        memset(&ev, 0, sizeof ev);
        ev.status = 0;
        ev.conn_handle = handle;
        ev.reason = BLE_ERR_REM_USER_CONN_TERM;
        env_rx_evt(BLE_HCI_EVCODE_DISCONN_CMP, (uint8_t *)&ev, sizeof ev);
    }
    env_connected = 0;
    ble_gap_adv_stop();
    ble_gap_disc_cancel();
    if (ble_gap_conn_cancel() == 0) {
        rx_conn_cancelled();
    }
    ble_store_clear();
    env_drain();
}

/* ---- custom GATT service ----------------------------------------------- */

static uint8_t chr_val[64];
static uint16_t chr_val_len = 4;

static int
chr_access(uint16_t conn_handle, uint16_t attr_handle,
           struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t len;

    (void)conn_handle; (void)attr_handle; (void)arg;
    switch (ctxt->op) {
    case BLE_GATT_ACCESS_OP_READ_CHR:
    case BLE_GATT_ACCESS_OP_READ_DSC:
        return os_mbuf_append(ctxt->om, chr_val, chr_val_len) == 0
               ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    case BLE_GATT_ACCESS_OP_WRITE_CHR:
    case BLE_GATT_ACCESS_OP_WRITE_DSC:
        len = OS_MBUF_PKTLEN(ctxt->om);
        if (len > sizeof chr_val) {
            return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        }
        if (ble_hs_mbuf_to_flat(ctxt->om, chr_val, sizeof chr_val,
                                &chr_val_len) != 0) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        return 0;
    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
}

static const ble_uuid128_t svc_uuid =
    BLE_UUID128_INIT(0x2d, 0x71, 0xa2, 0x59, 0xb4, 0x58, 0xc8, 0x12,
                     0x99, 0x99, 0x43, 0x95, 0x12, 0x2f, 0x46, 0x59);
static const ble_uuid128_t chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

static uint16_t notify_handle;

/* ---- per-input reset of state kept outside the host ---------------------- */

#define ANS_NEW_ALERT_BUF 64

static uint16_t lls_level_h, ias_level_h, ans_ctrl_h, ans_new_h, ans_stat_h;

static uint16_t
find_val_handle(uint16_t svc, uint16_t chr)
{
    ble_uuid16_t s = BLE_UUID16_INIT(svc);
    ble_uuid16_t c = BLE_UUID16_INIT(chr);
    uint16_t h = 0;
    int rc;

    rc = ble_gatts_find_chr(&s.u, &c.u, NULL, &h);
    assert(rc == 0);
    return h;
}

static void
local_write(uint16_t handle, const uint8_t *v, size_t len)
{
    struct os_mbuf *om = ble_hs_mbuf_from_flat(v, len);
    int rc;

    assert(om != NULL);
    rc = ble_att_svr_write_local(handle, om);
    assert(rc == 0);
    (void)rc;
}

/* Restore everything an input can change that the host's reset does not: our fake controller's
 * counters, our GATT characteristic and the standard services' values (their statics have no reset
 * API, so they are written back through the service's own access callbacks). The ANS initial
 * categories are 0 (checked below), so "disable all" restores them; its control-point buffer is
 * write-only and rewritten before every use. GAP name and appearance are read-only (write perm -1);
 * the host's available-packet count is returned by the host when a connection ends. */
void
env_begin_input(void)
{
    static const uint8_t zero[ANS_NEW_ALERT_BUF];
    static const uint8_t dis_new[2] = { BLE_SVC_ANS_CMD_DIS_NEW_ALERT_CAT, 0xff };
    static const uint8_t dis_unr[2] = { BLE_SVC_ANS_CMD_DIS_UNR_ALERT_CAT, 0xff };
    struct os_mbuf *om = NULL;
    uint16_t n = 0;

    _Static_assert(MYNEWT_VAL(BLE_SVC_ANS_NEW_ALERT_CAT) == 0 &&
                   MYNEWT_VAL(BLE_SVC_ANS_UNR_ALERT_CAT) == 0, "ANS reset assumes no initial categories");

    rand_ctr = 0;
    env_conn_handle = 0x0042;
    env_connected = 0;
    env_tx_reset();

    memset(chr_val, 0, sizeof chr_val);
    chr_val_len = 4;

    local_write(lls_level_h, zero, 1);
    local_write(ias_level_h, zero, 1);
    local_write(ans_ctrl_h, dis_new, 2);
    local_write(ans_ctrl_h, dis_unr, 2);
    local_write(ans_stat_h, zero, 2);
    if (ble_att_svr_read_local(ans_new_h, &om) == 0) {
        n = OS_MBUF_PKTLEN(om);
        os_mbuf_free_chain(om);
        assert(n <= sizeof zero);
        local_write(ans_new_h, zero, n);
    }
    ble_svc_bas_battery_level_set(0);
}

static const struct ble_gatt_svc_def gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = &chr_uuid.u,
                .access_cb = chr_access,
                .val_handle = &notify_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE |
                         BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY |
                         BLE_GATT_CHR_F_INDICATE,
                .descriptors = (struct ble_gatt_dsc_def[]) {
                    {
                        .uuid = BLE_UUID16_DECLARE(0x2901),
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_WRITE,
                        .access_cb = chr_access,
                    },
                    { 0 }
                },
            },
            {
                .uuid = BLE_UUID16_DECLARE(0xFFF1),
                .access_cb = chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC |
                         BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_AUTHEN,
            },
            { 0 }
        },
    },
    { 0 }
};


/* ---- GATT client / GAP / L2CAP initiators ------------------------------- */

static int
cb_mtu(uint16_t ch, const struct ble_gatt_error *e, uint16_t mtu, void *a)
{
    (void)ch; (void)e; (void)mtu; (void)a;
    return 0;
}

static int
cb_svc(uint16_t ch, const struct ble_gatt_error *e,
       const struct ble_gatt_svc *s, void *a)
{
    (void)ch; (void)e; (void)s; (void)a;
    return 0;
}

static int
cb_chr(uint16_t ch, const struct ble_gatt_error *e,
       const struct ble_gatt_chr *c, void *a)
{
    (void)ch; (void)e; (void)c; (void)a;
    return 0;
}

static int
cb_dsc(uint16_t ch, const struct ble_gatt_error *e, uint16_t chr_def_handle,
       const struct ble_gatt_dsc *d, void *a)
{
    (void)ch; (void)e; (void)chr_def_handle; (void)d; (void)a;
    return 0;
}

static int
cb_attr(uint16_t ch, const struct ble_gatt_error *e,
        struct ble_gatt_attr *attr, void *a)
{
    (void)ch; (void)e; (void)attr; (void)a;
    return 0;
}

static int
l2cap_event(struct ble_l2cap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_L2CAP_EVENT_COC_ACCEPT:
        ble_l2cap_recv_ready(event->accept.chan, ble_hs_mbuf_att_pkt());
        return 0;
    case BLE_L2CAP_EVENT_COC_DATA_RECEIVED:
        os_mbuf_free_chain(event->receive.sdu_rx);
        ble_l2cap_recv_ready(event->receive.chan, ble_hs_mbuf_att_pkt());
        return 0;
    default:
        return 0;
    }
}

void
env_client_op(unsigned op, uint16_t a, uint16_t b, const uint8_t *data,
              size_t len)
{
    uint16_t ch = env_conn_handle;
    uint16_t handles[3] = { a, b, (uint16_t)(a + b) };
    struct ble_gap_upd_params up;
    ble_uuid16_t u16 = BLE_UUID16_INIT(a);
    struct os_mbuf *om;

    if (len > 300) {
        len = 300;
    }
    switch (op) {
    case 1: ble_gattc_exchange_mtu(ch, cb_mtu, NULL); break;
    case 2: ble_gattc_disc_all_svcs(ch, cb_svc, NULL); break;
    case 3: ble_gattc_disc_all_chrs(ch, a, b, cb_chr, NULL); break;
    case 4: ble_gattc_disc_all_dscs(ch, a, b, cb_dsc, NULL); break;
    case 5: ble_gattc_read(ch, a, cb_attr, NULL); break;
    case 6: ble_gattc_read_long(ch, a, b, cb_attr, NULL); break;
    case 7: ble_gattc_write_flat(ch, a, data, len, cb_attr, NULL); break;
    case 8: ble_gattc_write_no_rsp_flat(ch, a, data, len); break;
    case 9:
        om = ble_hs_mbuf_from_flat(data, len);
        if (om != NULL) {
            ble_gattc_write_long(ch, a, b, om, cb_attr, NULL);
        }
        break;
    case 10: ble_gattc_read_by_uuid(ch, a, b, &u16.u, cb_attr, NULL); break;
    case 11: ble_gattc_find_inc_svcs(ch, a, b, cb_svc, NULL); break;
    case 12: ble_gattc_disc_svc_by_uuid(ch, &u16.u, cb_svc, NULL); break;
    case 13: ble_gattc_disc_chrs_by_uuid(ch, a, b, &u16.u, cb_chr, NULL); break;
    case 14: ble_gattc_read_mult(ch, handles, 3, cb_attr, NULL); break;
    case 15: ble_gap_security_initiate(ch); break;
    case 16:
        ble_l2cap_connect(ch, 0x80, 64, ble_hs_mbuf_att_pkt(), l2cap_event, NULL);
        break;
    case 17:
        memset(&up, 0, sizeof up);
        up.itvl_min = 6 + (a & 0xff);
        up.itvl_max = up.itvl_min + 6;
        up.latency = b & 0xf;
        up.supervision_timeout = 100 + (b >> 4);
        ble_gap_update_params(ch, &up);
        break;
    case 18:
        om = ble_hs_mbuf_from_flat(data, len);
        if (om != NULL) {
            ble_gatts_notify_custom(ch, notify_handle, om);
        }
        break;
    case 19:
        om = ble_hs_mbuf_from_flat(data, len);
        if (om != NULL) {
            ble_gatts_indicate_custom(ch, notify_handle, om);
        }
        break;
    case 20: ble_l2cap_sig_update(ch, &(struct ble_l2cap_sig_update_params){
                 .itvl_min = 6, .itvl_max = 12, .slave_latency = 0,
                 .timeout_multiplier = 200 }, NULL, NULL); break;
    default: break;
    }
    env_drain();
}

void
env_init(void)
{
    static int done;
    int rc;

    if (done) {
        return;
    }
    done = 1;

    nimble_port_init();
    ble_hs_hci_set_phony_ack_cb(phony_ack);

    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_ans_init();
    ble_svc_bas_init();
    ble_svc_dis_init();
    ble_svc_ias_init();
    ble_svc_lls_init();
    ble_svc_tps_init();

    rc = ble_gatts_count_cfg(gatt_svcs);
    assert(rc == 0);
    rc = ble_gatts_add_svcs(gatt_svcs);
    assert(rc == 0);

    ble_store_config_init();
    ble_l2cap_create_server(0x80, 64, l2cap_event, NULL);

    ble_hs_cfg.sm_io_cap = BLE_HS_IO_KEYBOARD_DISPLAY;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    env_drain();
    assert(ble_hs_synced());

    lls_level_h = find_val_handle(BLE_SVC_LLS_UUID16, BLE_SVC_LLS_CHR_UUID16_ALERT_LEVEL);
    ias_level_h = find_val_handle(BLE_SVC_IAS_UUID16, BLE_SVC_IAS_CHR_UUID16_ALERT_LEVEL);
    ans_ctrl_h = find_val_handle(BLE_SVC_ANS_UUID16, BLE_SVC_ANS_CHR_UUID16_ALERT_NOT_CTRL_PT);
    ans_new_h = find_val_handle(BLE_SVC_ANS_UUID16, BLE_SVC_ANS_CHR_UUID16_NEW_ALERT);
    ans_stat_h = find_val_handle(BLE_SVC_ANS_UUID16, BLE_SVC_ANS_CHR_UUID16_UNR_ALERT_STAT);
}
