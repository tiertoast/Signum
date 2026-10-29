/* Public PC/SC reader state only. No card connection, APDU, reset, verify,
 * login, credential input or diagnostic authentication. No arguments accepted. */
#include <PCSC/winscard.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv) {
    (void)argv;if(argc!=1)return 2;
    SCARDCONTEXT context;int32_t result=SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&context);
    if(result!=SCARD_S_SUCCESS)return 2;
    uint32_t length=0;result=SCardListReaders(context,NULL,NULL,&length);
    if(result!=SCARD_S_SUCCESS||length<2||length>16384){SCardReleaseContext(context);return 2;}
    char *names=calloc(length,1);if(!names){SCardReleaseContext(context);return 2;}
    result=SCardListReaders(context,NULL,names,&length);int status=0;
    if(result!=SCARD_S_SUCCESS){status=2;goto done;}
    for(size_t offset=0;offset<length&&names[offset];) {
        size_t n=strnlen(names+offset,length-offset);if(n==length-offset||n>256){status=2;break;}
        SCARD_READERSTATE state;memset(&state,0,sizeof(state));state.szReader=names+offset;
        result=SCardGetStatusChange(context,0,&state,1);
        printf("reader=");for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)names[offset+i];putchar(c>=32&&c<=126?c:'?');}
        printf(" status=%s present=%d atr=",result==SCARD_S_SUCCESS?"observed":"unavailable",(state.dwEventState&SCARD_STATE_PRESENT)!=0);
        if(result==SCARD_S_SUCCESS&&state.cbAtr<=sizeof(state.rgbAtr))for(uint32_t i=0;i<state.cbAtr;i++)printf("%02X",state.rgbAtr[i]);
        putchar('\n');offset+=n+1;
    }
done:free(names);SCardReleaseContext(context);return status;
}
