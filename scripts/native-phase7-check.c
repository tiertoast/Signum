/* Offline component check for the manual Phase7 build; no hardware access. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include "utf8proc.h"
int main(void) {
    FT_Library ft = NULL;
    FT_Int major, minor, patch;
    if (FT_Init_FreeType(&ft)) return 1;
    FT_Library_Version(ft, &major, &minor, &patch);
    FT_Done_FreeType(ft);
    if (major != 2 || minor != 13 || patch != 3) return 2;
    utf8proc_uint8_t *mapped = NULL;
    utf8proc_ssize_t n = utf8proc_map((const utf8proc_uint8_t *)"\xef\xbc\xa1", 3, &mapped,
        UTF8PROC_STABLE | UTF8PROC_COMPOSE | UTF8PROC_COMPAT);
    if (n != 1 || mapped == NULL || mapped[0] != 'A') { free(mapped); return 3; }
    free(mapped); mapped = NULL;
    const utf8proc_uint8_t invalid[] = {0xff};
    n = utf8proc_map(invalid, 1, &mapped, UTF8PROC_STABLE | UTF8PROC_COMPOSE);
    free(mapped);
    if (n != UTF8PROC_ERROR_INVALIDUTF8) return 4;
    puts("native components: 3 passed");
    return 0;
}
