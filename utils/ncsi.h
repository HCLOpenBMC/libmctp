#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <linux/ncsi.h>

#define BIT(_x) (1UL << (_x))

#define LINK_SPEED_10BASE_T_HALF_DUPLEX  	(1 << 1)
#define LINK_SPEED_10BASE_T_FULL_DUPLEX 	(2 << 1)
#define LINK_SPEED_100BASE_TX_HALF_DUPLEX 	(3 << 1)
#define LINK_SPEED_100BASE_T4 			(4 << 1)
#define LINK_SPEED_100BASE_TX_FULL_DUPLEX 	(5 << 1)
#define LINK_SPEED_1000BASE_T_HALF_DUPLEX 	(6 << 1)
#define LINK_SPEED_1000BASE_T_FULL_DUPLEX 	(7 << 1)
#define LINK_SPEED_10GBASE_T		 	(8 << 1)

char *ncsi_data;
int data_len;

const char* link_speeds[15] = {
	"10BASE-T half-duplex",
	"10BASE-T full-duplex",
	"100BASE-TX half-duplex",
	"100BASE-T4",
	"100BASE-TX full-duplex",
	"1000BASE-T half-duplex",
	"1000BASE-T full-duplex",
	"10G-BASE-T support",
	"speed unknown (0x9)",
	"speed unknown (0xa)",
	"speed unknown (0xb)",
	"speed unknown (0xc)",
	"speed unknown (0xd)",
	"speed unknown (0xe)",
	"speed unknown (0xf)"
};

static void ncsi_show_link_state(unsigned int status)
{
	printf("\t\t  Link %s ", status & BIT(0) ? "up" : "down");

	printf("%s\n", link_speeds[(status >> 1) & 0xf]);

	printf("\t\t  Auto negoiation %s\n", status & BIT(5) ? "enabled" : "disabled");
	printf("\t\t  Auto negoiation %s\n", status & BIT(6) ? "complete" : "not complete");
	printf("\t\t  Parallel detection %s\n", status & BIT(7) ? "used" : "not used");

	printf("\t\t  TX flow control %s\n", status & BIT(16) ? "enabled" : "disabled");
	printf("\t\t  RX flow control %s\n", status & BIT(17) ? "enabled" : "disabled");
	printf("\t\t  SerDes Link %s\n", status & BIT(20) ? "used" : "not used");
	printf("\t\t  OEM link speed %s\n", status & BIT(21) ? "valid" : "invalid");
}

struct ncsi_pkt_hdr {
	unsigned char mc_id;        /* Management controller ID */
	unsigned char revision;     /* NCSI version - 0x01      */
	unsigned char reserved;     /* Reserved                 */
	unsigned char id;           /* Packet sequence number   */
	unsigned char type;         /* Packet type              */
	unsigned char channel;      /* Network controller ID    */
	__be16        length;       /* Payload length           */
	__be32        reserved1[2]; /* Reserved                 */
};

struct ncsi_msg {
	struct nl_sock	*sk;
	struct nl_msg	*msg;
	struct nlmsghdr	*hdr;
	int ret;
};

static void free_ncsi_msg(struct ncsi_msg *msg)
{
	//if (msg->msg)
	//	nlmsg_free(msg->msg);
	//if (msg->sk)
//		nl_socket_free(msg->sk);
}

int setup_ncsi_message(struct ncsi_msg *msg, int cmd, int flags)
{
	int rc, id;

	if (!msg)
		return -1;

	memset(msg, 0, sizeof(*msg));
	errno = 0;

	msg->sk = nl_socket_alloc();
	if (!msg->sk) {
		fprintf(stderr, "Could not alloc socket\n");
		return -1;
	}

	rc = genl_connect(msg->sk);
	if (rc) {
		fprintf(stderr, "genl_connect() failed\n");
		goto out;
	}

	id = genl_ctrl_resolve(msg->sk, "NCSI");
	if (id < 0) {
		fprintf(stderr, "Could not resolve NCSI\n");
		rc = id;
		goto out;
	}

	msg->msg = nlmsg_alloc();
	if (!msg->msg) {
		fprintf(stderr, "Failed to allocate message\n");
		rc = -1;
		goto out;
	};

	msg->hdr = genlmsg_put(msg->msg, NL_AUTO_PORT, NL_AUTO_SEQ, id, 0,
			flags, cmd, 0);

	if (!msg->hdr) {
		fprintf(stderr, "Failed to create header\n");
		rc = -1;
		goto out;
	}
	msg->ret = 1;

	return 0;
out:
	if (errno)
		fprintf(stderr, "\t%m\n");
	free_ncsi_msg(msg);
	return rc;
}

static int info_cb(struct nl_msg *msg,
		void *arg __attribute__((unused)))
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct nlattr *tb[NCSI_ATTR_MAX + 1] = {0};
	struct nlattr *ptb[NCSI_PKG_ATTR_MAX + 1] = {0};
	struct nlattr *ctb[NCSI_CHANNEL_ATTR_MAX + 1] = {0};
	struct nlattr *pattr, *cattr;
	int rc, rem, crem;

	struct nla_policy ncsi_policy[NCSI_ATTR_MAX + 1] = {
		[NCSI_ATTR_UNSPEC] = { .type = NLA_UNSPEC },
		[NCSI_ATTR_IFINDEX] = { .type = NLA_U32 },
		[NCSI_ATTR_PACKAGE_LIST] = { .type = NLA_NESTED },
		[NCSI_ATTR_PACKAGE_ID] = { .type = NLA_U32 },
		[NCSI_ATTR_CHANNEL_ID] = { .type = NLA_U32 },
	};

	struct nla_policy  package_policy[NCSI_PKG_ATTR_MAX + 1] =
	{
		[NCSI_PKG_ATTR_UNSPEC] = { .type = NLA_UNSPEC },
		[NCSI_PKG_ATTR] = { .type = NLA_NESTED },
		[NCSI_PKG_ATTR_ID] = { .type = NLA_U32 },
		[NCSI_PKG_ATTR_FORCED] = { .type = NLA_FLAG },
		[NCSI_PKG_ATTR_CHANNEL_LIST] = { .type = NLA_NESTED },
	};

	struct nla_policy  channel_policy[NCSI_CHANNEL_ATTR_MAX + 1] =
	{
		[NCSI_CHANNEL_ATTR_UNSPEC] = { .type = NLA_UNSPEC },
		[NCSI_CHANNEL_ATTR] = { .type = NLA_NESTED },
		[NCSI_CHANNEL_ATTR_ID] = { .type = NLA_U32 },
		[NCSI_CHANNEL_ATTR_VERSION_MAJOR] = { .type = NLA_U32 },
		[NCSI_CHANNEL_ATTR_VERSION_MINOR] = { .type = NLA_U32 },
		[NCSI_CHANNEL_ATTR_VERSION_STR] = { .type = NLA_STRING },
		[NCSI_CHANNEL_ATTR_LINK_STATE] = { .type = NLA_U32 },
		[NCSI_CHANNEL_ATTR_ACTIVE] = { .type = NLA_FLAG },
		[NCSI_CHANNEL_ATTR_FORCED] = { .type = NLA_FLAG },
		[NCSI_CHANNEL_ATTR_VLAN_LIST] = { .type = NLA_NESTED },
		[NCSI_CHANNEL_ATTR_VLAN_ID] = { .type = NLA_U32 },
	};

	rc = genlmsg_parse(hdr, 0, tb, NCSI_ATTR_MAX, ncsi_policy);
	if (rc) {
		fprintf(stderr, "Failed to parse ncsi info callback\n");
		return rc;
	}

	if (!tb[NCSI_ATTR_PACKAGE_LIST]) {
		fprintf(stderr, "Info response does not contain a package list\n");
		return -1;
	}

	rem = nla_len(tb[NCSI_ATTR_PACKAGE_LIST]);
	nla_for_each_nested(pattr, tb[NCSI_ATTR_PACKAGE_LIST], rem) {
		rc = nla_parse_nested(ptb, NCSI_PKG_ATTR_MAX, pattr,
				package_policy);
		if (rc) {
			fprintf(stderr, "Failed to parse package, %m\n");
			continue;
		}

		printf("package 0x%x\n", nla_get_u32(ptb[NCSI_PKG_ATTR_ID]));
		if (ptb[NCSI_PKG_ATTR_FORCED])
			printf("package is forced\n");

		crem = nla_len(ptb[NCSI_PKG_ATTR_CHANNEL_LIST]);
		nla_for_each_nested(cattr, ptb[NCSI_PKG_ATTR_CHANNEL_LIST],
				crem) {
			rc = nla_parse_nested(ctb, NCSI_CHANNEL_ATTR_MAX,
					cattr, channel_policy);
			if (rc) {
				fprintf(stderr, "Failed to parse channel, %m\n");
				continue;
			}

			printf("\tchannel 0x%x\n",
					nla_get_u32(ctb[NCSI_CHANNEL_ATTR_ID]));
			printf("\t\tversion %x.%x, %s\n",
					nla_get_u32(ctb[NCSI_CHANNEL_ATTR_VERSION_MAJOR]),
					nla_get_u32(ctb[NCSI_CHANNEL_ATTR_VERSION_MINOR]),
					nla_get_string(ctb[NCSI_CHANNEL_ATTR_VERSION_STR]));
			printf("\t\tlink state 0x%.08x\n",
					nla_get_u32(ctb[NCSI_CHANNEL_ATTR_LINK_STATE]));
			ncsi_show_link_state(nla_get_u32(ctb[NCSI_CHANNEL_ATTR_LINK_STATE]));
			printf("\t\tchannel is %sactive\n",
					ctb[NCSI_CHANNEL_ATTR_ACTIVE] ? "" : "in");
			if (ctb[NCSI_CHANNEL_ATTR_FORCED])
				printf("\t\tchannel is forced\n");
			// TODO vids list
		}

		printf("-----------\n");
	}

	return 0;
}

static int run_command_info(int ifindex, int package)
{
	struct ncsi_msg msg;
	int rc, flags;

	flags = package < 0 ? NLM_F_DUMP : 0;
	rc = setup_ncsi_message(&msg, NCSI_CMD_PKG_INFO, flags);
	if (rc)
		return -1;

	printf("info cmd, ifindex %d, package %d, flags 0x%x\n",
			ifindex, package, flags);

	rc = nla_put_u32(msg.msg, NCSI_ATTR_IFINDEX, ifindex);
	if (rc) {
		fprintf(stderr, "Failed to add ifindex, %m\n");
		goto out;
	}

	if (package >= 0) {
		rc = nla_put_u32(msg.msg, NCSI_ATTR_PACKAGE_ID, package);
		if (rc) {
			fprintf(stderr, "Failed to add package id, %m\n");
			goto out;
		}
	}

	rc = nl_socket_modify_cb(msg.sk, NL_CB_VALID, NL_CB_CUSTOM, info_cb,
			NULL);
	if (rc) {
		fprintf(stderr, "Failed to modify callback function, %m\n");
		goto out;
	}

	rc = nl_send_auto(msg.sk, msg.msg);
	if (rc < 0) {
		fprintf(stderr, "Failed to send message, %m\n");
		goto out;
	}

	rc = nl_recvmsgs_default(msg.sk);
	if (rc) {
		fprintf(stderr, "Failed to receive message, %m\n");
		goto out;
	}

out:
	free_ncsi_msg(&msg);
	return rc;
}
static int run_command_set(int ifindex, int package, int channel)
{
	struct ncsi_msg msg;
	int rc;

	rc = setup_ncsi_message(&msg, NCSI_CMD_SET_INTERFACE, 0);
	if (rc)
		return -1;

	printf("set cmd, ifindex %d, package %d, channel %d\n",
			ifindex, package, channel);

	rc = nla_put_u32(msg.msg, NCSI_ATTR_IFINDEX, ifindex);
	if (rc) {
		fprintf(stderr, "Failed to add ifindex, %m\n");
		goto out;
	}

	rc = nla_put_u32(msg.msg, NCSI_ATTR_PACKAGE_ID, package);
	if (rc) {
		fprintf(stderr, "Failed to add package id, %m\n");
		goto out;
	}

	if (channel >= 0) {
		rc = nla_put_u32(msg.msg, NCSI_ATTR_CHANNEL_ID, channel);
		if (rc) {
			fprintf(stderr, "Failed to add channel id, %m\n");
			goto out;
		}
	}

	rc = nl_send_auto(msg.sk, msg.msg);
	if (rc < 0) {
		fprintf(stderr, "Failed to send message, %m\n");
		goto out;
	}

	rc = nl_recvmsgs_default(msg.sk);
	if (rc) {
		fprintf(stderr, "Failed to receive message, %m\n");
		goto out;
	}

out:
	free_ncsi_msg(&msg);
	return rc;
}

static int run_command_clear(int ifindex)
{
	struct ncsi_msg msg;
	int rc;

	rc = setup_ncsi_message(&msg, NCSI_CMD_CLEAR_INTERFACE, 0);
	if (rc)
		return -1;

	printf("clear cmd, ifindex %d\n", ifindex);

	rc = nla_put_u32(msg.msg, NCSI_ATTR_IFINDEX, ifindex);
	if (rc) {
		fprintf(stderr, "Failed to add ifindex, %m\n");
		goto out;
	}

	rc = nl_send_auto(msg.sk, msg.msg);
	if (rc < 0) {
		fprintf(stderr, "Failed to send message, %m\n");
		goto out;
	}

	rc = nl_recvmsgs_default(msg.sk);
	if (rc) {
		fprintf(stderr, "Failed to receive message, %m\n");
		goto out;
	}

out:
	free_ncsi_msg(&msg);
	return rc;
}

static int send_cb(struct nl_msg *msg, void *arg)
{
#define ETHERNET_HEADER_SIZE 16

	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct nlattr *tb[NCSI_ATTR_MAX + 1] = {0};
	int rc, i;
	int *ret = arg;
	static struct nla_policy ncsi_genl_policy[NCSI_ATTR_MAX + 1] = {
		[NCSI_ATTR_IFINDEX] =		{ .type = NLA_U32 },
		[NCSI_ATTR_PACKAGE_LIST] =	{ .type = NLA_NESTED },
		[NCSI_ATTR_PACKAGE_ID] =	{ .type = NLA_U32 },
		[NCSI_ATTR_CHANNEL_ID] =	{ .type = NLA_U32 },
		[NCSI_ATTR_DATA] =		{ .type = NLA_BINARY  },
		[NCSI_ATTR_MULTI_FLAG] =	{ .type = NLA_FLAG },
		[NCSI_ATTR_PACKAGE_MASK] =	{ .type = NLA_U32 },
		[NCSI_ATTR_CHANNEL_MASK] =	{ .type = NLA_U32 },
	};


	rc = genlmsg_parse(hdr, 0, tb, NCSI_ATTR_MAX, ncsi_genl_policy);
	if (rc) {
		fprintf(stderr, "Failed to parse ncsi cmd callback\n");
		return rc;
	}

	data_len = nla_len(tb[NCSI_ATTR_DATA]) - ETHERNET_HEADER_SIZE;
	ncsi_data = nla_data(tb[NCSI_ATTR_DATA]) + ETHERNET_HEADER_SIZE;

	printf("NC-SI Response Payload length = %d\n", data_len);
	printf("Response Payload:\n");
	for (i = 0; i < data_len; ++i) {
		if (i && !(i%4))
			printf("\n%d: ", 16+i);
		printf("0x%02x ", *(ncsi_data+i));
	}
	printf("\n");

	// indicating call back has been completed
	*ret = 0;
	return 0;
}

static int run_command_send(int ifindex, int package, int channel,	uint8_t type, short payload_len, uint8_t *payload)
{
	struct ncsi_msg msg;
	struct ncsi_pkt_hdr *hdr;
	int rc;
	uint8_t *pData, *pCtrlPktPayload;

	// allocate a  contiguous buffer space to hold ncsi message
	//  (header + Control Packet payload)
	pData = calloc(1, sizeof(struct ncsi_pkt_hdr) + payload_len);
	if (!pData) {
		fprintf(stderr, "Failed to allocate buffer for ctrl pkt, %m\n");
		goto out;
	}
	// prepare buffer to be copied to netlink msg
	hdr = (void *)pData;
	pCtrlPktPayload = pData + sizeof(struct ncsi_pkt_hdr);
	memcpy(pCtrlPktPayload, payload, payload_len);

	rc = setup_ncsi_message(&msg, NCSI_CMD_SEND_CMD, 0);
	if (rc)
		return -1;

	printf("send cmd, ifindex %d, package %d, channel %d, type 0x%x\n",
			ifindex, package, channel, type);

	rc = nla_put_u32(msg.msg, NCSI_ATTR_IFINDEX, ifindex);
	if (rc) {
		fprintf(stderr, "Failed to add ifindex, %m\n");
		goto out;
	}

	if (package >= 0) {
		rc = nla_put_u32(msg.msg, NCSI_ATTR_PACKAGE_ID, package);
		if (rc) {
			fprintf(stderr, "Failed to add package id, %m\n");
			goto out;
		}
	}

	rc = nla_put_u32(msg.msg, NCSI_ATTR_CHANNEL_ID, channel);
	if (rc)
		fprintf(stderr, "Failed to add channel, %m\n");

	hdr->type = type;   // NC-SI command
	hdr->length = htons(payload_len);  // NC-SI command payload length
	rc = nla_put(msg.msg, NCSI_ATTR_DATA,
				sizeof(struct ncsi_pkt_hdr)+payload_len,
				(void *)pData);
	if (rc)
		fprintf(stderr, "Failed to add netlink header, %m\n");

	nl_socket_disable_seq_check(msg.sk);
	rc = nl_socket_modify_cb(msg.sk, NL_CB_VALID, NL_CB_CUSTOM, send_cb,
			&(msg.ret));

	rc = nl_send_auto(msg.sk, msg.msg);
	if (rc < 0) {
		fprintf(stderr, "Failed to send message, %m\n");
		goto out;
	}

	while (msg.ret == 1) {
		rc = nl_recvmsgs_default(msg.sk);
		if (rc) {
			fprintf(stderr, "Failed to rcv msg, rc=%d %m\n", rc);
			goto out;
		}
	}

out:
	free_ncsi_msg(&msg);
	return rc;
}

