/* Behavioural known-answer tests of the NimBLE host, run against the fake controller of nimble_env.c:
 * each case injects a known over-the-air packet and asserts the exact bytes the host answers with
 * (ATT, SMP), plus advertising-data and UUID known answers. Prints "SELFTEST passed=N failed=M". */
#include <stdio.h>
#include <string.h>

#include "host/ble_hs_adv.h"
#include "host/ble_uuid.h"
#include "nimble_env.h"

static int passed, failed;

static void
check(int ok, const char *what)
{
    if (ok) {
        passed++;
    } else {
        failed++;
        printf("FAIL: %s\n", what);
    }
}

static int
tx_equals(const uint8_t *want, size_t want_len)
{
    uint8_t got[64];
    size_t n = env_tx_last(got, sizeof got);

    if (n != want_len || memcmp(got, want, want_len) != 0) {
        size_t i;

        printf("  got %zu bytes:", n);
        for (i = 0; i < n; i++) {
            printf(" %02x", got[i]);
        }
        printf("\n");
        return 0;
    }
    return 1;
}

static void
test_att(void)
{
    /* ACL(handle 0x0042, len) | L2CAP(len, cid 4) | ATT */
    static const uint8_t mtu_req[] = { 0x02, 0x17, 0x00 };
    static const uint8_t mtu_rsp[] = { 0x42, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x01 };
    static const uint8_t read_req[] = { 0x0a, 0xf0, 0xff };
    static const uint8_t err_rsp[] = { 0x42, 0x00, 0x09, 0x00, 0x05, 0x00, 0x04, 0x00,
                                       0x01, 0x0a, 0xf0, 0xff, 0x01 };
    static const uint8_t bad_req[] = { 0x3f };
    static const uint8_t bad_rsp[] = { 0x42, 0x00, 0x09, 0x00, 0x05, 0x00, 0x04, 0x00,
                                       0x01, 0x3f, 0x00, 0x00, 0x06 };

    check(env_connect(ENV_ROLE_SLAVE) == 0, "peripheral connection established");
    env_tx_reset();
    env_rx_l2cap(4, mtu_req, sizeof mtu_req);
    check(env_tx_count() == 1 && tx_equals(mtu_rsp, sizeof mtu_rsp), "ATT Exchange MTU response");
    env_tx_reset();
    env_rx_l2cap(4, read_req, sizeof read_req);
    check(env_tx_count() == 1 && tx_equals(err_rsp, sizeof err_rsp), "ATT Read of absent handle -> Invalid Handle");
    env_tx_reset();
    env_rx_l2cap(4, bad_req, sizeof bad_req);
    check(env_tx_count() == 1 && tx_equals(bad_rsp, sizeof bad_rsp), "unknown ATT opcode -> Request Not Supported");
    env_disconnect();
}

static void
test_smp(void)
{
    /* Pairing Request: io cap NoInputNoOutput, no OOB, bonding, max key 16, key dist 3/3 */
    static const uint8_t pair_req[] = { 0x01, 0x03, 0x00, 0x01, 0x10, 0x03, 0x03 };
    uint8_t got[64];
    size_t n;

    check(env_connect(ENV_ROLE_SLAVE) == 0, "peripheral connection for SMP");
    env_tx_reset();
    env_rx_l2cap(6, pair_req, sizeof pair_req);
    n = env_tx_last(got, sizeof got);
    /* ACL hdr(4) + L2CAP hdr(4) + opcode 0x02 (Pairing Response), io cap KeyboardDisplay, no OOB */
    check(env_tx_count() >= 1 && n == 4 + 4 + 7 && got[2] == 0x0b && got[6] == 0x06 &&
          got[8] == 0x02 && got[9] == 0x04 && got[10] == 0x00 && got[12] == 0x10,
          "SMP Pairing Response");
    env_disconnect();
}

static void
test_adv(void)
{
    static const uint8_t ad[] = { 0x02, 0x01, 0x06, 0x05, 0x09, 'T', 'e', 's', 't',
                                  0x03, 0x03, 0x0f, 0x18, 0x02, 0x0a, 0xf4 };
    struct ble_hs_adv_fields f;
    uint8_t out[31];
    uint8_t out_len = 0;

    check(ble_hs_adv_parse_fields(&f, ad, sizeof ad) == 0, "AD parse ok");
    check(f.flags == 0x06, "AD flags");
    check(f.name_len == 4 && memcmp(f.name, "Test", 4) == 0 && f.name_is_complete, "AD complete local name");
    check(f.num_uuids16 == 1 && f.uuids16[0].value == 0x180f && f.uuids16_is_complete, "AD service UUID16");
    check(f.tx_pwr_lvl_is_present && f.tx_pwr_lvl == (int8_t)0xf4, "AD tx power");
    check(ble_hs_adv_set_fields(&f, out, &out_len, sizeof out) == 0 && out_len == sizeof ad, "AD serialize length");
    {
        struct ble_hs_adv_fields g;

        check(ble_hs_adv_parse_fields(&g, out, out_len) == 0 && g.flags == 0x06 && g.name_len == 4 &&
              memcmp(g.name, "Test", 4) == 0 && g.num_uuids16 == 1 && g.uuids16[0].value == 0x180f &&
              g.tx_pwr_lvl == f.tx_pwr_lvl, "AD serialize/parse round trip");
    }
    check(ble_hs_adv_parse_fields(&f, (const uint8_t[]){ 0x05, 0x09, 'T' }, 3) != 0, "truncated AD rejected");
}

static void
test_uuid(void)
{
    ble_uuid_any_t u;
    char str[BLE_UUID_STR_LEN];
    static const uint8_t b16[] = { 0x0f, 0x18 };

    check(ble_uuid_from_str(&u, "0x180F") == 0 && u.u.type == BLE_UUID_TYPE_16 && ble_uuid_u16(&u.u) == 0x180f,
          "UUID16 from string");
    check(ble_uuid_init_from_buf(&u, b16, 2) == 0 && ble_uuid_u16(&u.u) == 0x180f, "UUID16 from buffer");
    check(ble_uuid_from_str(&u, "00112233-4455-6677-8899-aabbccddeeff") == 0 && u.u.type == BLE_UUID_TYPE_128 &&
          u.u128.value[0] == 0xff && u.u128.value[15] == 0x00, "UUID128 from string (little endian)");
    ble_uuid_to_str(&u.u, str);
    check(strcmp(str, "00112233-4455-6677-8899-aabbccddeeff") == 0, "UUID128 to string");
    check(ble_uuid_init_from_buf(&u, b16, 3) != 0, "bad-length UUID rejected");
}

int
main(void)
{
    env_init();
    test_att();
    test_smp();
    test_adv();
    test_uuid();
    printf("SELFTEST passed=%d failed=%d\n", passed, failed);
    return failed ? 1 : 0;
}
