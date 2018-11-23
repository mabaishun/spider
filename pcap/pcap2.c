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

void getPacket(u_char *arg,const struct pcap_pkthdr *pkthdr,const u_char *packet)
{
    int *id = (int *)arg;

    printf("id:%d\n",++(*id));
    printf("packet length:%d\n",pkthdr->len);
    printf("Number of bytes:%d\n",pkthdr->caplen);
    printf("Recieved time:%s",ctime((const time_t *)&pkthdr->ts.tv_sec));

    for (int i = 0;i < pkthdr->len;++i)
    {
        printf(" %02x",packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n\n");
}

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

    
    int id = 0;
    pcap_loop(device,-1,getPacket,(u_char*)&id);
    pcap_close(device);
    return 0;
}
