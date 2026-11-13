#ifndef MAYHEM_NIMBLE_ENV_H
#define MAYHEM_NIMBLE_ENV_H

#include <stddef.h>
#include <stdint.h>

/* Single-threaded NimBLE host wired to a fake controller: HCI commands are
 * acknowledged synchronously (BLE_HS_PHONY_HCI_ACKS) and every packet the
 * host transmits is captured instead of sent. */

#define ENV_ROLE_MASTER 0
#define ENV_ROLE_SLAVE  1

extern uint16_t env_conn_handle;
extern int env_connected;

void env_init(void);
/* Reset every piece of state an earlier input could have left behind; call first in each input. */
void env_begin_input(void);
void env_drain(void);

/* Start active scanning / undirected connectable advertising. */
int env_start_scan(void);
int env_start_adv(void);

/* Establish a connection to a fake peer; returns 0 on success. */
int env_connect(int role);
void env_disconnect(void);

/* Start a GATT/GAP/L2CAP procedure from the host side (ops 1..20). */
void env_client_op(unsigned op, uint16_t a, uint16_t b, const uint8_t *data,
                   size_t len);

/* Inject an HCI ACL data packet. `pb` is the packet-boundary flag
 * (0x0 start non-flushable, 0x1 continuation, 0x2 start). */
void env_rx_acl(uint16_t pb, const uint8_t *data, size_t len);
/* Inject one L2CAP SDU on `cid` as a start-of-message ACL packet. */
void env_rx_l2cap(uint16_t cid, const uint8_t *payload, size_t len);
/* Inject a raw HCI event: evcode followed by its parameters. */
void env_rx_evt(uint8_t evcode, const uint8_t *params, size_t len);

/* ACL data the host transmitted since the last env_tx_reset(). */
size_t env_tx_count(void);
size_t env_tx_last(uint8_t *out, size_t max);
void env_tx_reset(void);

#endif
