#ifndef WLAN_KEY_VALUE_H
#define WLAN_KEY_VALUE_H
#include <string>

using namespace std;
#pragma pack(push,1)
/********************Beacon info Key & value*******************/
struct beacon_info_value{
    int ch;
    u_int8_t ESSID[33];
    int ESSID_Len;
};
struct bssid_station_value{
    u_int8_t SSID[33];
    int SSID_Len;
};
#pragma pack(pop)
#endif // WLAN_KEY_VALUE_H

