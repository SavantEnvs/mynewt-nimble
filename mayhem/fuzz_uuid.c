/* UUID handling: binary decoding (2/4/16 byte), textual parsing ("xxxxxxxx-xxxx-..." / hex) and printing. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "host/ble_uuid.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ble_uuid_any_t u, c;
    char str[BLE_UUID_STR_LEN];

    if (size < 1) {
        return 0;
    }
    if (data[0] & 1) {
        char *s = malloc(size);

        memcpy(s, data + 1, size - 1);
        s[size - 1] = '\0';
        if (ble_uuid_from_str(&u, s) == 0) {
            ble_uuid_to_str(&u.u, str);
        }
        free(s);
    } else if (ble_uuid_init_from_buf(&u, data + 1, size - 1) == 0) {
        ble_uuid_to_str(&u.u, str);
        ble_uuid_copy(&c, &u.u);
        if (ble_uuid_cmp(&c.u, &u.u) != 0) {
            abort();
        }
        (void)ble_uuid_u16(&u.u);
    }
    return 0;
}
