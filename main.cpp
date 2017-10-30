#include <arpa/inet.h>//ip -> bin
#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <radiotap.h>
#include <netinet/in.h>
#include <map>
#include <string.h>
#include <unistd.h>
#include "80211header.h"
#include "wlan_key_value.h"
#include "mac.h"

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

struct pcap_pkthdr *pkt_header;
struct ieee80211_radiotap_header *irh;  //ieee802.11 radiotap
struct Type_Subtype *ts;
struct Beacon_frame *bf;
struct Data *data;
struct QosData41 *qdata41;
struct QosData42 *qdata42;
struct taged_parameter *tag;
struct taged_parameter *p_tag;
struct ProbeRequest *pr;
struct beacon_info_value nbiv;
struct bssid_station_value bsv;
struct ap_info *ai;

using namespace std;

char errbuf[PCAP_ERRBUF_SIZE];

uint8_t mac_changer(const char *ipm,uint8_t *opm) //ipm = inputmac, opm = outputmac
{
   return sscanf(ipm,"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&opm[0],&opm[1],&opm[2],&opm[3],&opm[4],&opm[5]);    //%x cause an error, fix to %2hhx
}
int main(int argc, char *argv[])
{
    char *dev =  argv[1];
    uint8_t ap_mac[6];
    mac_changer(argv[2],ap_mac);

    map<Mac,beacon_info_value>beacon_info;
    map<Mac,beacon_info_value>::iterator iter;

    map<Mac,bssid_station_value>station_info;
    map<Mac,bssid_station_value>::iterator iter2;

    Mac bssid;
    Mac station;

    if(argc < 3)
    {
        printf("Input argument error!\n");
        if (dev == NULL)
        {
            printf("Input your <dev><AP_Mac_Address>\n");
            printf("EX : Wlan1 AA:BB:CC:DD:EE:FF");
            exit(1);
        }
    }
    else
    {
        printf("DEV : %s\n", dev);
        printf("AP_MAC : %s\n",argv[2]);

        const u_char *pkt_data;
        int res;
        int pkt_length;

        pcap_t *fp;

        if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
        {
            fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
        }
        while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
        {
            if(res == 0)continue;
            pkt_length = pkt_header->len;
            irh = (struct ieee80211_radiotap_header*)pkt_data;
            pkt_data += irh->it_len;        //jump to subtype pointer
            pkt_length -= irh->it_len;

            ts = (struct Type_Subtype*)pkt_data;
            switch(ts->fc)
            {
            case 0x80:
                pkt_data += 4;  //type_subtype length
                pkt_length -= 4;
                bf = (struct Beacon_frame*)pkt_data;
                if(memcmp(bf->bssid,ap_mac,6) == 0)
                {
                    memcpy(bssid.mac_address, bf->bssid, 6);
                    if((iter = beacon_info.find(bssid)) != beacon_info.end()) {
                      break;
                    }
                    else
                    {
                        nbiv.ch = 0;
                        nbiv.ESSID_Len = 0;
                        memset(nbiv.ESSID,0x00,32);
                    }
                    pkt_data +=32;  //jump to tag 20 + 12
                    pkt_length -=32;
                    while(pkt_length>0)
                    {
                        tag = (struct taged_parameter*)pkt_data;
                        switch(tag->tag_number)
                        case 0x00:
                            tag = (struct taged_parameter*)pkt_data;
                            if((iter = beacon_info.find(bssid)) == beacon_info.end())       //해당되는 키와 값이 있을 경우 ESSID를 갱신
                            {
                                memcpy(nbiv.ESSID,tag->tag_value,tag->tag_length);
                                nbiv.ESSID_Len = tag->tag_length;
                            }

                            pkt_data += (2+tag->tag_length);    //total tag's length
                            pkt_length -= (2+tag->tag_length);
                        case 0x01:
                            tag = (struct taged_parameter*)pkt_data;

                            pkt_data += 2+tag->tag_length;
                            pkt_length -= 2+tag->tag_length;
                        case 0x03:
                            tag = (struct taged_parameter*)pkt_data;
                            memcpy(&nbiv.ch,tag->tag_value,tag->tag_length);
                            beacon_info.insert(pair<Mac, beacon_info_value>(bssid,nbiv));

                            pkt_data += 2+tag->tag_length;
                            pkt_length -= 2+tag->tag_length;
                            break;  //97 line's tag switch case break
                    }
                    break;  //82 line's subtype switch case break
                }
                else
                    break;  //82 line's subtype switch case break
            case 0x0040:
                //ProbeRequest Packet
                pkt_data += 4;  //type_subtype length
                pkt_length -= 4;

                pr = (struct ProbeRequest*)pkt_data;

                memcpy(station.mac_address, pr->sa,6);
                memcpy(bsv.SSID, pr->bssid,6);
                if((iter2 = station_info.find(station)) != station_info.end()) {
                    //decrypt packet?
                }
                else
                {
                    memset(bsv.SSID,0x00,32);
                    bsv.SSID_Len = 0;
                }
                pkt_data += 20;  //jump to tag 20
                pkt_length -= 20;

                p_tag = (struct taged_parameter*)pkt_data;

                if(p_tag->tag_number == 0 && p_tag->tag_length > 0)
                {
                    memcpy(bsv.SSID,p_tag->tag_value,p_tag->tag_length);
                    bsv.SSID_Len = p_tag->tag_length;
                }
                if(memcmp(bsv.SSID,iter->second.ESSID,bsv.SSID_Len)==0)
                    station_info.insert(pair<Mac, bssid_station_value>(station,bsv));

                break;  //138 line's switch case break
            }
            int i;
            system("clear");
            cout<<"AP ADDR\t\t\tCH\tESSID"<<endl;
            for(iter = beacon_info.begin(); iter!=beacon_info.end(); advance(iter,1))
            {
                for(i=0;i<5;i++)
                    printf("%02x:",iter->first.mac_address[i]); //beacon info key(bssid)
                printf("%02x\t",iter->first.mac_address[5]);
                printf("%d\t",iter->second.ch);
                for(i=0;i<iter->second.ESSID_Len;i++)
                    printf("%c",iter->second.ESSID[i]);
                cout<<endl;
            }
            cout<<"Connect Devices"<<endl;
            for(iter2 = station_info.begin(); iter2!=station_info.end(); advance(iter2,1))
            {
                for(i=0;i<5;i++)
                    printf("%02x:",iter2->first.mac_address[i]); //station key(station address)
                printf("%02x\t",iter2->first.mac_address[5]);
                cout<<endl;
            }
        }
    }
    return 0;
}
