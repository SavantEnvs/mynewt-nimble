/* Over-the-air parsing in the NimBLE host: HCI ACL -> L2CAP reassembly -> ATT / GATT / SM / L2CAP signaling.
 *
 * Input layout:
 *   byte 0   bit 0: role (0 central, 1 peripheral); bits 1-5: host-initiated procedure to start first
 *   byte 1-2 handle/offset argument `a` for the procedure   (little endian)
 *   byte 3-4 argument `b`
 *   rest     records  [selector][len][len bytes]
 *            selector bits 0-2: 0/3 ATT, 1 SMP, 2 L2CAP signaling, 4+ dynamic CoC channel
 *            selector bit 7:    payload is a complete raw L2CAP frame, sent in an ACL packet whose
 *                               packet-boundary flag is selector bits 4-5
 */
#include <stddef.h>
#include <stdint.h>

#include "nimble_env.h"

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
    static const uint16_t cids[8] = { 4, 6, 5, 4, 0x40, 0x41, 0x40, 0x41 };
    uint16_t a, b;
    unsigned op;
    size_t off = 5;

    env_begin_input();

    if (size < 5) {
        return 0;
    }
    if (env_connect(data[0] & 1) != 0) {
        env_disconnect();
        return 0;
    }

    op = (data[0] >> 1) & 0x1f;
    a = (uint16_t)(data[1] | (data[2] << 8));
    b = (uint16_t)(data[3] | (data[4] << 8));
    if (op) {
        env_client_op(op, a, b, data + 5, size - 5 > 20 ? 20 : size - 5);
    }

    while (off + 2 <= size) {
        uint8_t sel = data[off];
        size_t len = data[off + 1];

        off += 2;
        if (len > size - off) {
            len = size - off;
        }
        if (sel & 0x80) {
            env_rx_acl((sel >> 4) & 3, data + off, len);
        } else {
            env_rx_l2cap(cids[sel & 7], data + off, len);
        }
        off += len;
    }

    env_disconnect();
    return 0;
}
