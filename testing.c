#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <pcap.h>

typedef struct {
    char protocol[16];
    char system_name[128];
    char port_id[128];
    uint16_t vlan_id;
    uint16_t voice_vlan_id;
    char vlan_name[64];
    char system_desc[256];
} net_info_t;

void parse_packet(const u_char *packet, int cap_len) {
    if (cap_len <= 14) return;

    net_info_t info = {0};
    strcpy(info.protocol, "UNKNOWN");

    // Check Destination MAC for CDP (01:00:0c:cc:cc:cc)
    int is_cdp = (packet[0] == 0x01 && packet[1] == 0x00 && packet[2] == 0x0C &&
                  packet[3] == 0xCC && packet[4] == 0xCC && packet[5] == 0xCC);

    // Check EtherType for LLDP (0x88cc)
    int is_lldp = (packet[12] == 0x88 && packet[13] == 0xCC);

    if (is_lldp) {
        strcpy(info.protocol, "LLDP");
        const u_char *ptr = packet + 14;
        int remaining = cap_len - 14;

        while (remaining > 2) {
            uint16_t tlv_header = (ptr[0] << 8) | ptr[1];
            int tlv_type = (tlv_header >> 9) & 0x7F;
            int tlv_len = tlv_header & 0x1FF;

            ptr += 2;
            remaining -= 2;
            if (tlv_len > remaining || tlv_type == 0) break;

            if (tlv_type == 2) { // Port ID
                int len = (tlv_len > 1) ? tlv_len - 1 : 0;
                if (len >= sizeof(info.port_id)) len = sizeof(info.port_id) - 1;
                memcpy(info.port_id, ptr + 1, len);
                info.port_id[len] = '\0';
            } 
            else if (tlv_type == 5) { // System Name
                int len = (tlv_len < sizeof(info.system_name)) ? tlv_len : sizeof(info.system_name) - 1;
                memcpy(info.system_name, ptr, len);
                info.system_name[len] = '\0';
            } 
            else if (tlv_type == 6) { // System Description
                int len = (tlv_len < sizeof(info.system_desc)) ? tlv_len : sizeof(info.system_desc) - 1;
                memcpy(info.system_desc, ptr, len);
                info.system_desc[len] = '\0';
            }
            else if (tlv_type == 127) { // Org Specific (IEEE 802.1 or LLDP-MED)
                if (tlv_len >= 4) {
                    uint32_t oui = (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
                    uint8_t subtype = ptr[3];
                    
                    if (oui == 0x0080C2) { // IEEE 802.1 (Data VLAN)
                        if (subtype == 1 && tlv_len >= 6) {
                            info.vlan_id = (ptr[4] << 8) | ptr[5];
                        } else if (subtype == 3 && tlv_len >= 7) {
                            info.vlan_id = (ptr[4] << 8) | ptr[5];
                            int name_len = tlv_len - 6;
                            if (name_len > 0 && name_len < sizeof(info.vlan_name)) {
                                memcpy(info.vlan_name, ptr + 6, name_len);
                                info.vlan_name[name_len] = '\0';
                            }
                        }
                    }
                    else if (oui == 0x0012BB) { // TIA LLDP-MED (Voice VLAN via Network Policy)
                        if (subtype == 2 && tlv_len >= 7) {
                            info.voice_vlan_id = ((ptr[5] & 0x01) << 8) | ptr[6];
                        }
                    }
                }
            }

            ptr += tlv_len;
            remaining -= tlv_len;
        }
    } 
    else if (is_cdp) {
        strcpy(info.protocol, "CDP");
        // CDP skips Ethernet (14) + LLC/SNAP (8) + CDP Header (4) = 26 bytes
        if (cap_len <= 26) return;
        const u_char *ptr = packet + 26;
        int remaining = cap_len - 26;

        while (remaining >= 4) {
            uint16_t tlv_type = (ptr[0] << 8) | ptr[1];
            uint16_t tlv_len = (ptr[2] << 8) | ptr[3];

            if (tlv_len < 4 || tlv_len > remaining) break;

            const u_char *val = ptr + 4;
            int val_len = tlv_len - 4;

            if (tlv_type == 0x0001) { // Device ID (System Name)
                int len = val_len < sizeof(info.system_name) ? val_len : sizeof(info.system_name) - 1;
                memcpy(info.system_name, val, len);
                info.system_name[len] = '\0';
            }
            else if (tlv_type == 0x0003) { // Port ID
                int len = val_len < sizeof(info.port_id) ? val_len : sizeof(info.port_id) - 1;
                memcpy(info.port_id, val, len);
                info.port_id[len] = '\0';
            }
            else if (tlv_type == 0x0005) { // Software Version / Desc
                int len = val_len < sizeof(info.system_desc) ? val_len : sizeof(info.system_desc) - 1;
                memcpy(info.system_desc, val, len);
                info.system_desc[len] = '\0';
            }
            else if (tlv_type == 0x000A) { // Native VLAN
                if (val_len >= 2) {
                    info.vlan_id = (val[0] << 8) | val[1];
                }
            }
            else if (tlv_type == 0x000E) { // Appliance ID / Voice VLAN
                if (val_len >= 3) {
                    info.voice_vlan_id = (val[val_len - 2] << 8) | val[val_len - 1];
                }
            }

            ptr += tlv_len;
            remaining -= tlv_len;
        }
    } else {
        return;
    }

    // Output strict JSON to stdout
    printf("{\n");
    printf("  \"protocol\": \"%s\",\n", info.protocol);
    printf("  \"system_name\": \"%s\",\n", strlen(info.system_name) > 0 ? info.system_name : "Unknown");
    printf("  \"port_id\": \"%s\",\n", strlen(info.port_id) > 0 ? info.port_id : "Unknown");
    printf("  \"vlan_id\": %d,\n", info.vlan_id);
    printf("  \"voice_vlan_id\": %d,\n", info.voice_vlan_id);
    printf("  \"vlan_name\": \"%s\",\n", strlen(info.vlan_name) > 0 ? info.vlan_name : "None");
    printf("  \"system_desc\": \"%s\"\n", strlen(info.system_desc) > 0 ? info.system_desc : "Unknown");
    printf("}\n");
}

void my_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    parse_packet(bytes, h->len);
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    pcap_if_t *target_device = NULL;
    char target_guid[256] = {0};

    DWORD retVal = 0;
    ULONG outBufLen = 15000;
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
    
    if (pAddresses && GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *pCurrAddresses = pAddresses;
        for (; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next) {
            if (pCurrAddresses->OperStatus == IfOperStatusUp && 
                pCurrAddresses->FirstUnicastAddress != NULL &&
                pCurrAddresses->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
                strncpy(target_guid, pCurrAddresses->AdapterName, sizeof(target_guid) - 1);
                break;
            }
        }
    }
    free(pAddresses);

    if (strlen(target_guid) == 0) return 1;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;
    for (d = alldevs; d != NULL; d = d->next) {
        if (strstr(d->name, target_guid) != NULL) {
            target_device = d;
            break;
        }
    }
    if (!target_device) target_device = alldevs;

    pcap_t *handle = pcap_open_live(target_device->name, 65536, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);
    if (!handle) return 1;

    // BPF Filter to match BOTH LLDP (0x88cc) and CDP multicast destination MAC
    struct bpf_program fp;
    char filter_exp[] = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        pcap_close(handle);
        return 1;
    }

    fprintf(stderr, "[*] Listening for LLDP or Cisco CDP broadcast...\n");
    
    // Captures the first match (either protocol), prints JSON, and terminates
    pcap_loop(handle, 1, my_packet_handler, NULL);

    pcap_close(handle);
    return 0;
}