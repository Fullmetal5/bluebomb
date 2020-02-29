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

struct mgmt_cmd {
	uint16_t cmd;
	uint16_t hci_dev;
	uint16_t len;
	uint8_t param[];
};

struct mgmt_evt {
	uint16_t evt;
	uint16_t hci_dev;
	uint16_t len;
	uint8_t param[];
};

int hci_open_raw_dev(int dev_id);
int hci_open_control_dev(int dev_id);
int get_device_handle(int raw_sock);
int hci_send_mgmt_cmd(int ctrl_sock, uint16_t cmd, uint16_t hci_dev, void *param, uint16_t len);
int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, void *param, uint8_t plen);
int hci_send_acl(int dd, uint16_t handle, uint8_t pb_bc, void *param, uint16_t dlen);
int send_acl_packet(int dd, uint16_t handle, void* param, int len);
int await_mgmt_response(int ctrl_sock, int hci_dev, void** ret_buf, int* ret_size);
int await_command_complete(int raw_sock, uint16_t ogf, uint16_t ocf, void** ret_buf, int* ret_size);
int await_response(int raw_sock, uint16_t await_msg);



// power: 0 == off, 1 == on
int mgmt_power_device(int ctrl_sock, int hci_dev, int power);
// connectable: 0 == off, 1 == on
int mgmt_set_connectable(int ctrl_sock, int hci_dev, int connectable);
// bondable: 0 == off, 1 == on
int mgmt_set_bondable(int ctrl_sock, int hci_dev, int bondable);
// discoverable: 0 == off, 1 == on
// timeout: time in seconds before timeout
int mgmt_set_discoverable(int ctrl_sock, int hci_dev, int discoverable, uint16_t timeout);
// name: name of the device, max 248 character counting null byte.
int mgmt_set_local_name(int ctrl_sock, int hci_dev, char* name);



// Not sure how to do this with the mgmt api so we do it manually.
int bt_set_device_scan(int fd, int status);
int bt_set_iac_lap(int fd, uint8_t Num_Currect_IAC, uint32_t* IAC_LAP);
