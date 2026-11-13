/* Over-the-air events delivered by the controller: advertising reports, connection / PHY / data-length /
 * encryption / LTK-request events, number-of-completed-packets, ... parsed by ble_hs_hci_evt_process().
 *
 * Input layout:
 *   byte 0   host state before the events arrive: 0 idle, 1 scanning, 2 connected (central),
 *            3 connected (peripheral), 4 advertising
 *   rest     records  [len][event code][len-1 bytes of event parameters]
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nimble_env.h"

/* A conforming controller only reports Success, Directed Advertising Timeout or Unknown Connection
 * Identifier in a connection-complete event; the host asserts on anything else ("controller is broken"),
 * which no over-the-air peer can provoke. */
static void
sanitize_conn_status(uint8_t evcode, uint8_t *params, size_t len)
{
    if (evcode == 0x3e && len >= 2 && (params[0] == 0x01 || params[0] == 0x0a) &&
        params[1] != 0x00 && params[1] != 0x3c && params[1] != 0x02) {
        params[1] = 0x00;
    }
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    env_init();
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t evt[255];
    size_t off = 1;

    env_begin_input();

    if (size < 1) {
        return 0;
    }
    switch (data[0] % 5) {
    case 1:
        env_start_scan();
        break;
    case 2:
        env_connect(ENV_ROLE_MASTER);
        break;
    case 3:
        env_connect(ENV_ROLE_SLAVE);
        break;
    case 4:
        env_start_adv();
        break;
    default:
        break;
    }

    while (off + 2 <= size) {
        size_t len = data[off];

        off++;
        if (len == 0) {
            continue;
        }
        if (len > size - off) {
            len = size - off;
        }
        memcpy(evt, data + off + 1, len - 1);
        sanitize_conn_status(data[off], evt, len - 1);
        env_rx_evt(data[off], evt, len - 1);
        off += len;
    }

    env_disconnect();
    return 0;
}
