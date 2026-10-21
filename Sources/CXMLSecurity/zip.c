#include "CXAdES.h"
#include <zlib.h>
#include <string.h>
unsigned long signum_zip_crc(const unsigned char *data,size_t size) { return crc32(0,data,(uInt)size); }
int signum_zip_inflate(const unsigned char *data,size_t size,unsigned char *out,size_t expected) {
    if(!size||size>24*1024*1024||!expected||expected>8*1024*1024)return 0;
    z_stream stream;memset(&stream,0,sizeof(stream));
    stream.next_in=(Bytef*)data;stream.avail_in=(uInt)size;stream.next_out=out;stream.avail_out=(uInt)expected;
    if(inflateInit2(&stream,-MAX_WBITS)!=Z_OK)return 0;
    int code=inflate(&stream,Z_FINISH);
    int ok=code==Z_STREAM_END&&stream.total_in==size&&stream.total_out==expected;
    inflateEnd(&stream);return ok;
}
