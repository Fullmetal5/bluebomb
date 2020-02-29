/*  Copyright 2020  Dexter Gerig  <dexgerig@gmail.com>
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#include "libminibt.h"

#include "stream_macros.h"

static inline void hci_filter_clear(struct hci_filter *f)
{
	memset(f, 0, sizeof(*f));
}
static inline void hci_filter_all_ptypes(struct hci_filter *f)
{
	memset((void *) &f->type_mask, 0xff, sizeof(f->type_mask));
}
static inline void hci_filter_all_events(struct hci_filter *f)
{
	memset((void *) f->event_mask, 0xff, sizeof(f->event_mask));
}

int hci_open_raw_dev(int dev_id)
{
	struct sockaddr_hci a;
	int dd, err;

	/* Check for valid device id */
	if (dev_id < 0) {
		errno = ENODEV;
		return -1;
	}

	/* Create HCI socket */
	dd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (dd < 0)
		return dd;
	
	/* Set filters */
	struct hci_filter flt;
	hci_filter_clear(&flt);
	hci_filter_all_ptypes(&flt);
	hci_filter_all_events(&flt);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		printf("Can't set filter\n");
		goto failed;
	}

	/* Bind socket to the HCI device */
	memset(&a, 0, sizeof(a));
	a.hci_family = AF_BLUETOOTH;
	a.hci_dev = dev_id;
	if (bind(dd, (struct sockaddr *) &a, sizeof(a)) < 0) {
		printf("Can't bind to socket\n");
		goto failed;
	}

	return dd;

failed:
	err = errno;
	close(dd);
	errno = err;

	return -1;
}

int hci_open_control_dev(int dev_id)
{
	struct sockaddr_hci a;
	int dd, err;

	/* Check for valid device id */
	if (dev_id < 0) {
		errno = ENODEV;
		return -1;
	}

	/* Create HCI socket */
	dd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (dd < 0)
		return dd;

	/* Bind socket to the HCI device */
	memset(&a, 0, sizeof(a));
	a.hci_family = AF_BLUETOOTH;
	a.hci_dev = HCI_DEV_NONE;
	a.hci_channel = HCI_CHANNEL_CONTROL;
	if (bind(dd, (struct sockaddr *) &a, sizeof(a)) < 0) {
		err = errno;
		printf("Can't bind to socket\n");
		errno = err;
		goto failed;
	}

	return dd;

failed:
	err = errno;
	close(dd);
	errno = err;

	return -1;
}

int get_device_handle(int raw_sock)
{
	uint8_t *buf = malloc(HCI_MAX_FRAME_SIZE);
	ssize_t err = 0;
	
	while (1) {
		while ((err = recv(raw_sock, buf, HCI_MAX_FRAME_SIZE, 0)) < 0 && (errno == EINTR || errno == EAGAIN))
			;
		
		if (err < 0) {
			err = errno;
			printf("recv failed: %s\n", strerror(errno));
			free(buf);
			errno = err;
			return -1;
		}
		
		if (buf[0] != HCI_EVENT_PKT)
			continue;
		
		if (buf[1] != 0x03) // HCI_CONNECTION_COMPLETE_EVENT
			continue;
		
		int handle = (buf[5] * 0x100) | buf[4];
		free(buf);
		return handle;
	}
}

int hci_send_mgmt_cmd(int ctrl_sock, uint16_t cmd, uint16_t hci_dev, void *param, uint16_t len)
{
	struct mgmt_cmd a;
	struct iovec iv[2];
	int ivn;

	a.cmd = htole16(cmd);
	a.hci_dev = htole16(hci_dev);
	a.len = htole16(len);

	iv[0].iov_base = &a;
	iv[0].iov_len  = sizeof(a);
	ivn = 1;

	if (len) {
		iv[1].iov_base = param;
		iv[1].iov_len  = len;
		ivn = 2;
	}

	while (writev(ctrl_sock, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, void *param, uint8_t plen)
{
	uint8_t type = HCI_COMMAND_PKT;
	hci_command_hdr hc;
	struct iovec iv[3];
	int ivn;

	hc.opcode = htobs(cmd_opcode_pack(ogf, ocf));
	hc.plen = plen;

	iv[0].iov_base = &type;
	iv[0].iov_len  = 1;
	iv[1].iov_base = &hc;
	iv[1].iov_len  = HCI_COMMAND_HDR_SIZE;
	ivn = 2;

	if (plen) {
		iv[2].iov_base = param;
		iv[2].iov_len  = plen;
		ivn = 3;
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

#define MTU 0x00F0 // Just to be on the safe side

int hci_send_acl(int dd, uint16_t handle, uint8_t pb_bc, void *param, uint16_t dlen)
{
	if (dlen > MTU) {
		printf("hci_send_acl: dlen bigger than MTU\n");
		return -1;
	}
	
	uint8_t type = HCI_ACLDATA_PKT;
	hci_acl_hdr ha;
	struct iovec iv[3];
	int ivn;

	ha.handle = htobs(acl_handle_pack(handle, pb_bc));
	ha.dlen = htobs(dlen);

	iv[0].iov_base = &type;
	iv[0].iov_len  = 1;
	iv[1].iov_base = &ha;
	iv[1].iov_len  = HCI_ACL_HDR_SIZE;
	ivn = 2;

	if (dlen) {
		iv[2].iov_base = param;
		iv[2].iov_len  = dlen;
		ivn = 3;
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int send_acl_packet(int dd, uint16_t handle, void* param, int len)
{
	int ret = 0;
	
	if (dd < 0) {
		printf("send_acl_packet: Invalid socket\n");
		return -1;
	}
	
	if (param == NULL || len == 0) {
		printf("send_acl_packet: No data to send\n");
		return -1;
	}
	
	if (len < 0 || len > 0xFFFF) {
		printf("send_acl_packet: Invalid length\n");
		return -1;
	}
	
	if (len <= MTU) {
		return hci_send_acl(dd, handle, ACL_START, param, len);
	}
	
	ret = hci_send_acl(dd, handle, ACL_START, param, MTU);
	param += MTU;
	if (ret)
		return ret;
	
	int rem = len - MTU;
	while (rem > MTU) {
		int ret = hci_send_acl(dd, handle, ACL_CONT, param, MTU);
		if (ret)
			return ret;
		rem -= MTU;
		param += MTU;
	}
	
	if (rem)
		ret = hci_send_acl(dd, handle, ACL_CONT, param, rem);
	
	return ret;
}

int await_mgmt_response(int ctrl_sock, int hci_dev, void** ret_buf, int* ret_size)
{
	struct mgmt_evt* evt = malloc(sizeof(struct mgmt_evt) + 0x1000);
	memset(evt, 0x00, sizeof(struct mgmt_evt) + 0x1000);
	ssize_t err = 0;
	
	if (ret_buf)
		*ret_buf = NULL;
	if (ret_size)
		*ret_size = 0;
	
	while (1) {
		while ((err = recv(ctrl_sock, evt, sizeof(struct mgmt_evt) + 0x1000, 0)) < 0 && (errno == EINTR || errno == EAGAIN))
			;
		
		if (err < 0) {
			err = errno;
			printf("recv failed: %s\n", strerror(errno));
			free(evt);
			errno = err;
			return -1;
		}
		
		if (htole16(evt->hci_dev) == hci_dev)
			break;
	}
	
	int evt_code = htole16(evt->evt);
	if ((ret_buf != NULL) && ret_size && htole16(evt->len)) {
		*ret_size = htole16(evt->len);
		*ret_buf = malloc(*ret_size);
		memcpy(*ret_buf, evt->param, *ret_size);
	}
	free(evt);
	
	return evt_code;
}

#define HCI_WRITE_SCAN_ENABLE_COMMAND 0x0C1A
#define HCI_WRITE_CURRENT_IAC_LAP_COMMAND 0x0C3A

int await_command_complete(int raw_sock, uint16_t ogf, uint16_t ocf, void** ret_buf, int* ret_size)
{
	uint8_t *buf = malloc(HCI_MAX_FRAME_SIZE);
	ssize_t err = 0;
	uint16_t opcode = htobs(cmd_opcode_pack(ogf, ocf));
	
	if (ret_buf)
		*ret_buf = NULL;
	if (ret_size)
		*ret_size = 0;
	
	while (1) {
		while ((err = recv(raw_sock, buf, HCI_MAX_FRAME_SIZE, 0)) < 0 && (errno == EINTR || errno == EAGAIN))
			;
		
		if (err < 0) {
			err = errno;
			printf("recv failed: %s\n", strerror(errno));
			free(buf);
			errno = err;
			return -1;
		}
		
		if (buf[0] != HCI_EVENT_PKT || buf[1] != 0x0E)
			continue;
		
		if (buf[2] != 0x04) //TODO: Remove later
			continue;
		
		if (((buf[5] * 0x100) | buf[4]) != opcode)
			continue;
		
		switch (opcode) {
			case HCI_WRITE_SCAN_ENABLE_COMMAND:
				printf("HCI_WRITE_SCAN_ENABLE_COMMAND received\n");
				if (buf[6] == 0) {
					free(buf);
					return 0;
				} else {
					err = buf[6];
					free(buf);
					return err;
				}
				break;
			
			case HCI_WRITE_CURRENT_IAC_LAP_COMMAND:
				printf("HCI_WRITE_CURRENT_IAC_LAP_COMMAND received\n");
				if (buf[6] == 0) {
					free(buf);
					return 0;
				} else {
					err = buf[6];
					free(buf);
					return err;
				}
				break;
			
			default:
				printf("Unsupported opcode 0x%04X\n", opcode);
				free(buf);
				return -1;
		}
		
		free(buf);
		return 0;
	}
}

int await_response(int raw_sock, uint16_t await_msg)
{
	uint8_t *buf = malloc(HCI_MAX_FRAME_SIZE);
	ssize_t err = 0;
	
	while (1) {
		while ((err = recv(raw_sock, buf, HCI_MAX_FRAME_SIZE, 0)) < 0 && (errno == EINTR || errno == EAGAIN))
			;
		
		if (err < 0) {
			err = errno;
			printf("recv failed: %s\n", strerror(errno));
			free(buf);
			errno = err;
			return -1;
		}
		
		if (buf[0] != HCI_ACLDATA_PKT)
			continue;
		
		//TODO: These blindly trust packet lengths, refactor to not do that.
		hci_acl_hdr *hdr = (hci_acl_hdr*)&buf[1];
		int size_left = btohs(hdr->dlen);
		uint8_t *l2_head = &buf[1 + sizeof(hci_acl_hdr)];
		while (size_left > 0) {
			struct l2cap_packet *pkt = (struct l2cap_packet*)l2_head;
			int pkt_len = L2CAP_HEADER_LENGTH + le16toh(pkt->length);
			size_left -= pkt_len;
			l2_head += pkt_len;
			
			uint8_t *payload_head = (uint8_t*)&pkt->payload;
			while (pkt_len > 0) {
				struct l2cap_payload *payload = (struct l2cap_payload*)payload_head;
				int payload_len = L2CAP_PAYLOAD_LENGTH + le16toh(payload->length);
				pkt_len -= payload_len;
				payload_head += payload_len;
				
				if (payload->opcode != 0x03) // L2CAP_CONNECTION_RESPONSE
					continue;
				
				uint8_t *conn_response = payload->data;
				uint16_t dest_cid;
				uint16_t src_cid;
				uint16_t result;
				uint16_t status;
				
				STREAM_TO_UINT16(dest_cid, conn_response);
				STREAM_TO_UINT16(src_cid, conn_response);
				STREAM_TO_UINT16(result, conn_response);
				STREAM_TO_UINT16(status, conn_response);
				
				// shutup gcc
				(void)dest_cid;
				(void)src_cid;
				(void)result;
				(void)status;
				
				if (result != await_msg)
					continue;
				
				free(buf);
				return 0;
			}
		}
	}
}

// Get ready for copy-pasta

int mgmt_power_device(int ctrl_sock, int hci_dev, int power) {
	if (ctrl_sock < 0) {
		printf("Invalid file handle\n");
		return -1;
	}
	
	if (power != 0 && power != 1) {
		printf("Invalid power setting: %d\n", power);
		return -1;
	}
	
	uint8_t pwr = power;
	if (hci_send_mgmt_cmd(ctrl_sock, 0x0005, hci_dev, &pwr, 1) < 0) {
		printf("Failed to send mgmt command\n");
		return -1;
	}
	
	uint8_t* ret_buf = NULL;
	int ret_size = 0;
	int evt_code = await_mgmt_response(ctrl_sock, hci_dev, (void**)&ret_buf, &ret_size);
	int err = errno;
	if (ret_size < 3) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (evt_code != 1) {
		printf("Got bad event: %d\n", evt_code);
		printf("Status: 0x%X\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (htole16(*(uint16_t*)&ret_buf[0]) != 0x0005) {
		printf("Got event for wrong opcode: 0x%04X\n", htole16(*(uint16_t*)&ret_buf[0]));
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_size != 3 + 4) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_buf[2] != 0x00) {
		printf("Got bad event status: %d\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	
	free(ret_buf);
	return 0;
}

int mgmt_set_connectable(int ctrl_sock, int hci_dev, int connectable)
{
	if (ctrl_sock < 0) {
		printf("Invalid file handle\n");
		return -1;
	}
	
	if (connectable != 0 && connectable != 1) {
		printf("Invalid connectable setting: %d\n", connectable);
		return -1;
	}
	
	uint8_t cnt = connectable;
	if (hci_send_mgmt_cmd(ctrl_sock, 0x0007, hci_dev, &cnt, 1) < 0) {
		printf("Failed to send mgmt command\n");
		return -1;
	}
	
	uint8_t* ret_buf = NULL;
	int ret_size = 0;
	int evt_code = await_mgmt_response(ctrl_sock, hci_dev, (void**)&ret_buf, &ret_size);
	int err = errno;
	if (ret_size < 3) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (evt_code != 1) {
		printf("Got bad event: %d\n", evt_code);
		printf("Status: 0x%X\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (htole16(*(uint16_t*)&ret_buf[0]) != 0x0007) {
		printf("Got event for wrong opcode: 0x%04X\n", htole16(*(uint16_t*)&ret_buf[0]));
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_size != 3 + 4) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_buf[2] != 0x00) {
		printf("Got bad event status: %d\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	
	free(ret_buf);
	return 0;
}

int mgmt_set_bondable(int ctrl_sock, int hci_dev, int bondable)
{
	if (ctrl_sock < 0) {
		printf("Invalid file handle\n");
		return -1;
	}
	
	if (bondable != 0 && bondable != 1) {
		printf("Invalid bondable setting: %d\n", bondable);
		return -1;
	}
	
	uint8_t bnd = bondable;
	if (hci_send_mgmt_cmd(ctrl_sock, 0x0009, hci_dev, &bnd, 1) < 0) {
		printf("Failed to send mgmt command\n");
		return -1;
	}
	
	uint8_t* ret_buf = NULL;
	int ret_size = 0;
	int evt_code = await_mgmt_response(ctrl_sock, hci_dev, (void**)&ret_buf, &ret_size);
	int err = errno;
	if (ret_size < 3) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (evt_code != 1) {
		printf("Got bad event: %d\n", evt_code);
		printf("Status: 0x%X\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (htole16(*(uint16_t*)&ret_buf[0]) != 0x0009) {
		printf("Got event for wrong opcode: 0x%04X\n", htole16(*(uint16_t*)&ret_buf[0]));
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_size != 3 + 4) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_buf[2] != 0x00) {
		printf("Got bad event status: %d\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	
	free(ret_buf);
	return 0;
}

int mgmt_set_discoverable(int ctrl_sock, int hci_dev, int discoverable, uint16_t timeout)
{
	if (ctrl_sock < 0) {
		printf("Invalid file handle\n");
		return -1;
	}
	
	if (discoverable != 0 && discoverable != 1 && discoverable != 2) {
		printf("Invalid discoverable setting: %d\n", discoverable);
		return -1;
	}
	
	struct {
		uint8_t discoverable;
		uint16_t timeout;
	} __attribute__((packed)) dsc;
	dsc.discoverable = discoverable;
	dsc.timeout = htole32(timeout);
	if (hci_send_mgmt_cmd(ctrl_sock, 0x0006, hci_dev, &dsc, sizeof(dsc)) < 0) {
		printf("Failed to send mgmt command\n");
		return -1;
	}
	
	uint8_t* ret_buf = NULL;
	int ret_size = 0;
	int evt_code = await_mgmt_response(ctrl_sock, hci_dev, (void**)&ret_buf, &ret_size);
	int err = errno;
	if (ret_size < 3) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (evt_code != 1) {
		printf("Got bad event: %d\n", evt_code);
		printf("Status: 0x%X\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (htole16(*(uint16_t*)&ret_buf[0]) != 0x0006) {
		printf("Got event for wrong opcode: 0x%04X\n", htole16(*(uint16_t*)&ret_buf[0]));
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_size != 3 + 4) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_buf[2] != 0x00) {
		printf("Got bad event status: %d\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	
	free(ret_buf);
	return 0;
}

int mgmt_set_local_name(int ctrl_sock, int hci_dev, char* name)
{
	if (ctrl_sock < 0) {
		printf("Invalid file handle\n");
		return -1;
	}
	
	int name_len = strlen(name) + 1;
	
	if (name_len > 248) {
		printf("Device name too long\n");
		return -1;
	}
	
	char padded_local_name[249 + 11] = {0}; // Plus 11 for the short name, we don't even use it.
	memcpy(padded_local_name, name, name_len);
	if (hci_send_mgmt_cmd(ctrl_sock, 0x000F, hci_dev, padded_local_name, 249 + 11) < 0) {
		printf("Failed to send mgmt command\n");
		return -1;
	}
	
	uint8_t* ret_buf = NULL;
	int ret_size = 0;
	int evt_code = await_mgmt_response(ctrl_sock, hci_dev, (void**)&ret_buf, &ret_size);
	int err = errno;
	if (ret_size < 3) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (evt_code != 1) {
		printf("Got bad event: %d\n", evt_code);
		printf("Status: 0x%X\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (htole16(*(uint16_t*)&ret_buf[0]) != 0x000F) {
		printf("Got event for wrong opcode: 0x%04X\n", htole16(*(uint16_t*)&ret_buf[0]));
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_size != 3 + 249 + 11) {
		printf("Got bad event size: %d\n", ret_size);
		free(ret_buf);
		errno = err;
		return -1;
	}
	if (ret_buf[2] != 0x00) {
		printf("Got bad event status: %d\n", ret_buf[2]);
		free(ret_buf);
		errno = err;
		return -1;
	}
	
	free(ret_buf);
	return 0;
}

int bt_set_device_scan(int fd, int status)
{
	if (fd < 0) {
		printf("Invalid file handle\n");
		return -1;
	}
	
	if (status != 0 && status != 1 && status != 2 && status != 3) {
		printf("Invalid scan status\n");
		return -1;
	}
	
	uint8_t stat = status;
	
	if (hci_send_cmd(fd, 0x0003, 0x001a, &stat, 1) < 0) { // HCI_Write_Scan_Enable
		printf("Failed to send command\n");
		return -1;
	}
	
	return await_command_complete(fd, 0x0003, 0x001a, NULL, 0);
}

int bt_set_iac_lap(int fd, uint8_t Num_Current_IAC, uint32_t* IAC_LAP)
{
	int err = 0;
	if (fd < 0) {
		printf("Invalid file handle\n");
		return -1;
	}
	
	if (Num_Current_IAC == 0) {
		printf("Can't have zero IACs\n");
		return -1;
	}
	
	if (IAC_LAP == NULL) {
		printf("No IAC_LAP buffer passed\n");
		return -1;
	}
	
	for (int i = 0; i < Num_Current_IAC; i++) {
		uint32_t a = IAC_LAP[i] - 0x9E8B00;
		if (a > 0x3f) {
			printf("Invalid IAC_LAP: 0x%X at index %d\n", IAC_LAP[i], i);
			return -1;
		}
	}
	
	uint8_t* buf = malloc(1 + (Num_Current_IAC * 3));
	buf[0] = Num_Current_IAC;
	for (int i = 0; i < Num_Current_IAC; i++) {
		uint32_t converted_lap = htole32(IAC_LAP[i]);
		memcpy(buf + (i * 3) + 1, ((uint8_t*)&converted_lap), 3);
	}
	
	if (hci_send_cmd(fd, 0x0003, 0x003a, buf, 1 + (Num_Current_IAC * 3)) < 0) { // HCI_Write_Current_IAC_LAP
		err = errno;
		printf("Failed to send command\n");
		free(buf);
		errno = err;
		return -1;
	}
	
	free(buf);
	return await_command_complete(fd, 0x0003, 0x003a, NULL, 0);
}
