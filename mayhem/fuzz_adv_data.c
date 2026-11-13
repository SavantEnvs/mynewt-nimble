/* Advertising / scan-response data (AD structures) as received in advertising reports: field parser,
 * generic TLV walker and the serializer fed with the parsed result. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nimble/hci_common.h"
#include "host/ble_hs_adv.h"

static int
count_fields(const struct ble_hs_adv_field *f, void *arg)
{
    size_t *n = arg;

    *n += f->length;
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct ble_hs_adv_fields fields;
    uint8_t out[BLE_HS_ADV_MAX_SZ];
    uint8_t out_len = 0;
    size_t total = 0;

    if (size > 255) {
        size = 255;
    }
    (void)ble_hs_adv_parse(data, (uint8_t)size, count_fields, &total);
    if (ble_hs_adv_parse_fields(&fields, data, (uint8_t)size) == 0) {
        (void)ble_hs_adv_set_fields(&fields, out, &out_len, sizeof out);
        (void)ble_hs_adv_set_fields(&fields, out, &out_len, 8);
    }
    return 0;
}
