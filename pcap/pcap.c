/*************************************************************************
	> File Name:    pcap.c
	> Author:       spider
	> Mail:         13953028063@139.com
	> Created Time: 2018年11月18日 星期日 21时27分03秒
 ************************************************************************/

#include <stdio.h>
#include <pcap/pcap.h>
#include <time.h>
#include <stdlib.h>

int main(void)
{
    char errBuff[PCAP_ERRBUF_SIZE],*devstr;
    devstr = pcap_lookupdev(errBuff);
    if (devstr)
    {
        printf("success:device:%s\n",devstr);
    }
    else
    {
        printf("error:%s\n",errBuff);
    }

    pcap_t* device = pcap_open_live(devstr,65535,1,0,errBuff);
    if (!device)
    {
        printf("error:pcap_open_live():%s\n",errBuff);
        exit(1);
    }

    struct pcap_pkthdr packet;
    const u_char *pktstr = pcap_next(device,&packet);

    if (!pktstr)
    {
        printf("did not capture a packet!\n");
        exit(1);
    }
    printf("packet length:%d\n",packet.len);
    printf("Number of tytes:%d\n",packet.caplen);
    printf("Recieved time:%s\n",ctime((const time_t*)&packet.ts.tv_sec));
    
    pcap_close(device);
    return 0;
}
