/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * RDMA-based Disaggregated Persistent Memory Pool Implementation
 *
 * The memory pool supports:
 * (1) Memory READ/WRITE/ATOMIC interfaces
 * (2) RPC interfaces
 * (3) On-device memory allocation
 *
 * Hohai University
 */

#include <infiniband/verbs.h>
#include <syslog.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <list.h>

#include "ethane.h"
#include "debug.h"
#include "dmpool.h"
#include "dmm.h"
#include "coro.h"
#include "ethanefs.h"
#include "trace.h"

#define IB_MTU     IBV_MTU_1024
#define IB_DEV     "mlx5_0"
#define IB_PORT    1
#define IB_SL      0
#define IB_GID_IDX 0

#define MAX_INLINE_DATA    64

/* MN/CLIENT id should (strict) < MAX_MN/cli_id */
#define MAX_MN_ID   4096
#define MAX_CLI_ID  4096

#define MAX_QP_SR   128
#define MAX_QP_RR   128

#define MAX_OUTSTANDING_RD_ATOM     16

#define MAX_NESTED_MARKS    4

#define RPC_RV_BUF_SZ   1024
#define RPC_PR_BUF_SZ   1024

#define MAX_NR_CQE      1024

#define WAIT_TIMEOUT_US 8000000

struct net_iface {
    /* Address Handle */
    uint32_t      qpn;
    uint32_t      lid;
#ifdef DMPOOL_GLOBAL
    union ibv_gid gid;
#endif

    /* Memory Pool Address (only for memory nodes) */
    struct {
        uint32_t rkey;
        uint64_t raddr;
    } mem_bufs[DM_NR_MR_TYPES];
};

/* Global RDMA Network Context (per node) */

struct net_context {
    struct ibv_context *ibv_ctx;
    struct ibv_pd      *pd;

    struct ibv_port_attr   port_attr;
    struct ibv_device_attr dev_attr;
};

/* Compute Node Context */

struct cn_context {
    struct net_context *net_ctx;
    zhandle_t          *zh;

    int *mn_ids;
    int nr_mns;

    int id;
};

/* Client Context */

struct cli_wr_list {
    struct ibv_send_wr *head, *tail;
};

struct cli_context {
    struct cn_context *cn_ctx;

    int id;

    struct ibv_qp   **local_qps;
    struct net_iface *remote_ifaces;

    /* Operand buffer (for one-sided RDMA verbs), LOCAL */
    struct ibv_mr *op_buf_mr;
    struct ibv_mr *op_buf_mr_default;
    void          *op_buf;
    size_t         op_buf_size;
    size_t         op_buf_used;
    size_t         op_buf_mark[MAX_NESTED_MARKS];
    int            op_buf_mark_cnt;

    /* RPC return value buffer, REMOTE */
    struct ibv_mr *rv_buf_mr;
    void          *rv_buf;

    struct ibv_cq *mem_cq;
    struct ibv_cq *rpc_cq;

    struct cli_wr_list wr_list[MAX_NR_MNS];
};

/* Memory Node Context */

struct mn_context {
    struct net_context *net_ctx;

    int id;

    struct ibv_qp   **local_qps;
    struct net_iface *remote_ifaces;

    /* Memory buffers (for one-sided RDMA verbs), REMOTE */
    struct {
        struct ibv_mr *mr;
        char *buf;
        size_t size;
    } mem_bufs[DM_NR_MR_TYPES];

    /* per-client RPC parameters buffers, LOCAL */
    struct ibv_mr *pr_bufs_mr;
    char          *pr_bufs;

    /* RPC return value buffer, LOCAL */
    struct ibv_mr *rv_buf_mr;
    char          *rv_buf;

    struct ibv_cq *mem_cq;
    struct ibv_cq *rpc_cq;
};

struct dmpool {
    struct cn_context cn_ctx;
};

struct dmcontext {
    struct cli_context cli_ctx;
};

static inline void *huge_page_alloc(size_t size) {
    void *addr = mmap(NULL, size,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    return addr != MAP_FAILED ? addr : NULL;
}

static inline void post_send(struct ibv_qp *qp, struct ibv_mr *mr, void *buf, size_t size, unsigned int imm) {
    struct ibv_send_wr wr = { 0 }, *bad_wr = NULL;
    struct ibv_sge sge = { 0 };
    if (size) {
        sge.addr = (uintptr_t) buf;
        sge.length = size;
        sge.lkey = mr->lkey;
        wr.num_sge = 1;
    } else {
        wr.num_sge = 0;
    }
    wr.sg_list = &sge;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.imm_data = imm;
    if (ibv_post_send(qp, &wr, &bad_wr)) {
        pr_err("failed to post send");
        exit(-1);
    }
}

static inline void post_recv(struct ibv_qp *qp, struct ibv_mr *mr, void *buf, size_t size) {
    struct ibv_recv_wr wr = { 0 }, *bad_wr = NULL;
    struct ibv_sge sge = { 0 };
    sge.addr = (uintptr_t) buf;
    sge.length = size;
    sge.lkey = mr->lkey;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    if (ibv_post_recv(qp, &wr, &bad_wr)) {
        pr_err("failed to post recv");
        exit(-1);
    }
}

static struct ibv_device *find_dev() {
    struct ibv_device **dev_list = NULL;
    struct ibv_device *dev = NULL;
    int nr = 0, i;

    /* get device list */
    dev_list = ibv_get_device_list(&nr);
    if (!dev_list) {
        pr_err("failed to get IB device list");
        goto out;
    }

    /* find IB device */
    for (i = 0; i < nr; i++) {
        if (!strcmp(dev_list[i]->name, IB_DEV)) {
            dev = dev_list[i];
            break;
        }
    }

out:
    return dev;
}

static int init_net_context(struct net_context *ctx) {
    struct ibv_device *dev;
    int ret = 0;

    /* find IB device */
    dev = find_dev();
    if (!dev) {
        pr_err("failed to find IB device");
        ret = -ENODEV;
        goto out;
    }

    /* create IB context */
    ctx->ibv_ctx = ibv_open_device(dev);
    if (!ctx->ibv_ctx) {
        pr_err("failed to open IB device");
        ret = -ENODEV;
        goto out;
    }

    /* allocate protection domain */
    ctx->pd = ibv_alloc_pd(ctx->ibv_ctx);
    if (!ctx->pd) {
        pr_err("failed to allocate protection domain");
        ret = -ENOMEM;
        goto out;
    }

    /* query port properties */
    if (ibv_query_port(ctx->ibv_ctx, 1, &ctx->port_attr)) {
        pr_err("failed to query IB port status");
        ret = -EINVAL;
        goto out;
    }

    /* query device properties */
    if (ibv_query_device(ctx->ibv_ctx, &ctx->dev_attr)) {
        pr_err("failed to query IB device properties");
        ret = -EINVAL;
        goto out;
    }

out:
    return ret;
}

static inline struct ibv_mr *alloc_cmem_mr(struct mn_context *ctx, size_t size) {
#ifndef INFINIBAND_VERBS_EXP_H
    struct ibv_alloc_dm_attr dm_attr = { 0 };
    struct ibv_mr *mr;
    struct ibv_dm *dm;
    char *buf;

    dm_attr.length = size;

    dm = ibv_alloc_dm(ctx->net_ctx->ibv_ctx, &dm_attr);
    if (!dm) {
        pr_err("failed to allocate on-chip memory");
        return ERR_PTR(-ENOMEM);
    }

    mr = ibv_reg_dm_mr(ctx->net_ctx->pd, dm, 0, size, IBV_ACCESS_LOCAL_WRITE |
                                                      IBV_ACCESS_REMOTE_WRITE |
                                                      IBV_ACCESS_REMOTE_READ |
                                                      IBV_ACCESS_REMOTE_ATOMIC |
                                                      IBV_ACCESS_ZERO_BASED);
    if (!mr) {
        pr_err("failed to register on-chip memory MR");
        ibv_free_dm(dm);
        return ERR_PTR(-ENOMEM);
    }

    buf = calloc(1, size);
    ibv_memcpy_to_dm(dm, 0, buf, size);
    free(buf);

    return mr;
#else
    struct ibv_exp_memcpy_dm_attr cpy_attr = { 0 };
    struct ibv_exp_alloc_dm_attr dm_attr = { 0 };
    struct ibv_exp_reg_mr_in mr_in = { 0 };
    struct ibv_exp_dm *dm;
    struct ibv_mr *mr;
    char *buf;

    dm_attr.length = size;

    dm = ibv_exp_alloc_dm(ctx->net_ctx->ibv_ctx, &dm_attr);
    if (!dm) {
        pr_err("failed to allocate on-chip memory");
        return ERR_PTR(-ENOMEM);
    }

    mr_in.pd = ctx->net_ctx->pd;
    mr_in.addr = (void *) 0;
    mr_in.length = size;
    mr_in.exp_access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
                       IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;
    mr_in.create_flags = 0;
    mr_in.dm = dm;
    mr_in.comp_mask = IBV_EXP_REG_MR_DM;
    mr = ibv_exp_reg_mr(&mr_in);
    if (!mr) {
        pr_err("failed to register on-chip memory MR");
        return ERR_PTR(-ENOMEM);
    }

    buf = calloc(1, size);

    cpy_attr.memcpy_dir = IBV_EXP_DM_CPY_TO_DEVICE;
    cpy_attr.host_addr = buf;
    cpy_attr.length = size;
    cpy_attr.dm_offset = 0;
    ibv_exp_memcpy_dm(dm, &cpy_attr);

    free(buf);

    return mr;
#endif
}

static int init_mn_context(struct mn_context *ctx,
                           struct net_context *net_ctx, int id, void *mem_buf, size_t size, size_t cmem_size) {
    void *pr_buf, *rv_buf;
    int ret = 0;

    ctx->net_ctx = net_ctx;

    ctx->id = id;

    ctx->local_qps = calloc(1, MAX_CLI_ID * sizeof(*ctx->local_qps));
    ctx->remote_ifaces = calloc(1, MAX_CLI_ID * sizeof(*ctx->remote_ifaces));

    /* init pmem buffer */
    ctx->mem_bufs[DM_PMEM_MR].mr = ibv_reg_mr(ctx->net_ctx->pd, mem_buf, size, IBV_ACCESS_LOCAL_WRITE |
                                                                               IBV_ACCESS_REMOTE_WRITE |
                                                                               IBV_ACCESS_REMOTE_READ |
                                                                               IBV_ACCESS_REMOTE_ATOMIC);
    if (unlikely(!ctx->mem_bufs[DM_PMEM_MR].mr)) {
        pr_err("failed to register persistent memory buffer MR for MN: %d", errno);
        ret = -ENOMEM;
        goto out;
    }
    ctx->mem_bufs[DM_PMEM_MR].buf = mem_buf;
    ctx->mem_bufs[DM_PMEM_MR].size = size;

    /* init cmem buffer */
    ctx->mem_bufs[DM_CMEM_MR].mr = alloc_cmem_mr(ctx, cmem_size);
    if (unlikely(IS_ERR(ctx->mem_bufs[DM_CMEM_MR].mr))) {
        pr_err("failed to register on-chip memory buffer MR for MN");
        ret = PTR_ERR(ctx->mem_bufs[DM_CMEM_MR].mr);
        goto out;
    }
    ctx->mem_bufs[DM_CMEM_MR].buf = NULL;
    ctx->mem_bufs[DM_CMEM_MR].size = cmem_size;

    pr_buf = huge_page_alloc(RPC_PR_BUF_SZ * MAX_NR_CLIS);
    ctx->pr_bufs_mr = ibv_reg_mr(ctx->net_ctx->pd, pr_buf, RPC_PR_BUF_SZ * MAX_NR_CLIS, IBV_ACCESS_LOCAL_WRITE);
    if (!ctx->pr_bufs_mr) {
        pr_err("failed to register RPC parameter buffers MR for MN");
        ret = -ENOMEM;
        goto out;
    }
    ctx->pr_bufs = pr_buf;

    rv_buf = huge_page_alloc(RPC_RV_BUF_SZ);
    ctx->rv_buf_mr = ibv_reg_mr(ctx->net_ctx->pd, rv_buf, RPC_RV_BUF_SZ, IBV_ACCESS_LOCAL_WRITE);
    if (!ctx->rv_buf_mr) {
        pr_err("failed to register RPC return value buffer MR for MN");
        ret = -ENOMEM;
        goto out;
    }
    ctx->rv_buf = rv_buf;

    ctx->mem_cq = ibv_create_cq(ctx->net_ctx->ibv_ctx, MAX_NR_CQE, NULL, NULL, 0);
    if (!ctx->mem_cq) {
        pr_err("failed to create MEM CQ for MN");
        ret = -ENOMEM;
    }

    ctx->rpc_cq = ibv_create_cq(ctx->net_ctx->ibv_ctx, MAX_NR_CQE, NULL, NULL, 0);
    if (!ctx->rpc_cq) {
        pr_err("failed to create RPC CQ for MN");
        ret = -ENOMEM;
    }

out:
    return ret;
}

static int init_cn_context(struct cn_context *ctx, struct net_context *net_ctx, zhandle_t *zh,
                           int nr_mns, int *mn_ids, int id) {
    ctx->net_ctx = net_ctx;
    ctx->zh = zh;

    ctx->nr_mns = nr_mns;
    ctx->mn_ids = mn_ids;

    ctx->id = id;

    return 0;
}

static int init_cli_context(struct cli_context *ctx, struct cn_context *cn_ctx, int id, size_t local_buf_size) {
    int ret = 0;

    ctx->cn_ctx = cn_ctx;

    ctx->id = id;

    ctx->local_qps = calloc(1, MAX_MN_ID * sizeof(*ctx->local_qps));
    ctx->remote_ifaces = calloc(1, MAX_MN_ID * sizeof(*ctx->remote_ifaces));

    ctx->op_buf = huge_page_alloc(local_buf_size);
    ctx->op_buf_used = 0;
    ctx->op_buf_mark_cnt = 0;
    ctx->op_buf_size = local_buf_size;
    ctx->op_buf_mr = ibv_reg_mr(ctx->cn_ctx->net_ctx->pd, ctx->op_buf, local_buf_size, IBV_ACCESS_LOCAL_WRITE);
    if (!ctx->op_buf_mr) {
        pr_err("failed to register operand buffer MR for CLIENT thread");
        ret = -ENOMEM;
        goto out;
    }
    ctx->op_buf_mr_default = ctx->op_buf_mr;

    ctx->rv_buf = huge_page_alloc(RPC_RV_BUF_SZ);
    ctx->rv_buf_mr = ibv_reg_mr(ctx->cn_ctx->net_ctx->pd, ctx->rv_buf, RPC_RV_BUF_SZ, IBV_ACCESS_LOCAL_WRITE);
    if (!ctx->rv_buf_mr) {
        pr_err("failed to register RPC return value buffer MR for CLIENT thread");
        ret = -ENOMEM;
        goto out;
    }

    ctx->mem_cq = ibv_create_cq(ctx->cn_ctx->net_ctx->ibv_ctx, MAX_NR_CQE, NULL, NULL, 0);
    if (!ctx->mem_cq) {
        pr_err("failed to create MEM CQ for CLIENT thread");
        ret = -ENOMEM;
        goto out;
    }

    ctx->rpc_cq = ibv_create_cq(ctx->cn_ctx->net_ctx->ibv_ctx, MAX_NR_CQE, NULL, NULL, 0);
    if (!ctx->rpc_cq) {
        pr_err("failed to create RPC CQ for CLIENT thread");
        ret = -ENOMEM;
        goto out;
    }

    memset(ctx->wr_list, 0, sizeof(ctx->wr_list));

out:
    return ret;
}

static inline struct ibv_qp *create_qp(struct net_context *net_ctx, struct ibv_cq *send_cq, struct ibv_cq *recv_cq) {
    struct ibv_qp_init_attr attr = { 0 };
    attr.send_cq = send_cq;
    attr.recv_cq = recv_cq;
    attr.cap.max_send_wr = MAX_QP_SR;
    attr.cap.max_recv_wr = MAX_QP_RR;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.cap.max_inline_data = MAX_INLINE_DATA;
    attr.qp_type = IBV_QPT_RC;
    return ibv_create_qp(net_ctx->pd, &attr);
}

static inline void fill_ah(struct ibv_ah_attr *ah_attr, struct net_iface *iface) {
#ifdef DMPOOL_GLOBAL
    ah_attr->is_global = 1;
    ah_attr->grh.dgid = iface->gid;
    ah_attr->grh.sgid_index = IB_GID_IDX;
    ah_attr->grh.hop_limit = 0xff;
    ah_attr->grh.traffic_class = 0;
    ah_attr->grh.flow_label = 0;
#else
    ah_attr->is_global = 0;
#endif
    ah_attr->dlid = iface->lid;
    ah_attr->sl = IB_SL;
    ah_attr->src_path_bits = 0;
    ah_attr->port_num = IB_PORT;
}

static int connect_qp(struct ibv_qp *src_qp, struct net_iface *dst_iface) {
    struct ibv_qp_attr attr;
    int ret;

    /* modify QP to INIT */
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = IB_PORT;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
                           IBV_ACCESS_REMOTE_WRITE |
                           IBV_ACCESS_REMOTE_READ |
                           IBV_ACCESS_REMOTE_ATOMIC;
    ret = ibv_modify_qp(src_qp, &attr, IBV_QP_STATE |
                                        IBV_QP_PKEY_INDEX |
                                        IBV_QP_PORT |
                                        IBV_QP_ACCESS_FLAGS);
    if (ret) {
        pr_err("change QP state QP->INIT failed: %d", ret);
        goto out;
    }

    /* modify QP to RTR */
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IB_MTU;
    attr.dest_qp_num = dst_iface->qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = MAX_OUTSTANDING_RD_ATOM;
    attr.min_rnr_timer = 12;
    fill_ah(&attr.ah_attr, dst_iface);
    ret = ibv_modify_qp(src_qp, &attr, IBV_QP_STATE |
                                        IBV_QP_AV |
                                        IBV_QP_PATH_MTU |
                                        IBV_QP_DEST_QPN |
                                        IBV_QP_RQ_PSN |
                                        IBV_QP_MAX_DEST_RD_ATOMIC |
                                        IBV_QP_MIN_RNR_TIMER);
    if (ret) {
        pr_err("change QP state QP->RTR failed: %d", ret);
        goto out;
    }

    /* modify QP to RTS */
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = 0;
    attr.max_rd_atomic = MAX_OUTSTANDING_RD_ATOM;
    ret = ibv_modify_qp(src_qp, &attr, IBV_QP_STATE |
                                        IBV_QP_TIMEOUT |
                                        IBV_QP_RETRY_CNT |
                                        IBV_QP_RNR_RETRY |
                                        IBV_QP_SQ_PSN |
                                        IBV_QP_MAX_QP_RD_ATOMIC);
    if (ret) {
        pr_err("change QP state QP->RTS failed: %d", ret);
        goto out;
    }

out:
    return ret;
}

static inline void get_cn_iface(struct net_iface *iface, struct cli_context *ctx, struct ibv_qp *qp) {
    int i;
#ifdef DMPOOL_GLOBAL
    ibv_query_gid(ctx->cn_ctx->net_ctx->ibv_ctx, IB_PORT, IB_GID_IDX, &iface->gid);
#endif
    iface->lid = ctx->cn_ctx->net_ctx->port_attr.lid;
    iface->qpn = qp->qp_num;
    for (i = 0; i < DM_NR_MR_TYPES; i++) {
        iface->mem_bufs[i].rkey = -1;
        iface->mem_bufs[i].raddr = 0;
    }
}

static inline void get_mn_iface(struct net_iface *iface, struct mn_context *ctx, struct ibv_qp *qp) {
    int i;
#ifdef DMPOOL_GLOBAL
    ibv_query_gid(ctx->net_ctx->ibv_ctx, IB_PORT, IB_GID_IDX, &iface->gid);
#endif
    iface->lid = ctx->net_ctx->port_attr.lid;
    iface->qpn = qp->qp_num;
    for (i = 0; i < DM_NR_MR_TYPES; i++) {
        iface->mem_bufs[i].rkey = ctx->mem_bufs[i].mr->rkey;
        iface->mem_bufs[i].raddr = (unsigned long) ctx->mem_bufs[i].buf;
    }
}

static struct ibv_qp *connect_cn_with_mn(struct net_iface *cn_iface,
                                         struct cli_context *ctx, struct net_iface *mn_iface) {
    struct ibv_qp *qp;
    int ret;

    qp = create_qp(ctx->cn_ctx->net_ctx, ctx->mem_cq, ctx->rpc_cq);
    if (!qp) {
        pr_err("create CLIENT QP failed: %d", errno);
        goto out;
    }

    if ((ret = connect_qp(qp, mn_iface))) {
        pr_err("failed to connect CLIENT QP with MN QP: %d", ret);
        qp = NULL;
        goto out;
    }

    get_cn_iface(cn_iface, ctx, qp);

out:
    return qp;
}

static struct ibv_qp *connect_mn_with_cn(struct net_iface *mn_iface,
                                         struct mn_context *ctx, struct net_iface *cn_iface) {
    struct ibv_qp *qp;
    int ret;

    qp = create_qp(ctx->net_ctx, ctx->mem_cq, ctx->rpc_cq);
    if (!qp) {
        pr_err("create MN QP failed: %d", errno);
        goto out;
    }

    if ((ret = connect_qp(qp, cn_iface))) {
        pr_err("failed to connect MN QP with CLIENT QP: %d", ret);
        qp = NULL;
        goto out;
    }

    get_mn_iface(mn_iface, ctx, qp);

out:
    return qp;
}

static void cn_watcher(zhandle_t *zh, int type, int state, const char *path, void *ctx) {
    char full_path[256], conn_path[256];
    struct net_iface cn_iface, mn_iface;
    int ret, i, j, len, mn_id, cli_id;
    struct mn_context *mn_ctx = ctx;
    struct String_vector children;
    struct ibv_qp *qp;

    mn_id = mn_ctx->id;

    /* get all possible CNs which want to connect with this MN */
    ret = zoo_wget_children(zh, path, cn_watcher, ctx, &children);
    if (ret != ZOK) {
        pr_err("failed to get zookeeper child nodes in cn_watcher");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < children.count; i++) {
        cli_id = atoi(children.data[i] + strlen("client"));
        sprintf(conn_path, DM_ZK_PREFIX "memory_nodes/mn%010d/mn_ifaces/client%010d", mn_id, cli_id);

        /* filter out those already connected */
        ret = zoo_exists(zh, conn_path, 0, NULL);
        if (ret == ZOK) {
            continue;
        }

        /* get CLIENT iface */
        sprintf(full_path, DM_ZK_PREFIX "memory_nodes/mn%010d/cn_ifaces/client%010d", mn_id, cli_id);
        len = sizeof(cn_iface);
        ret = zoo_get(zh, full_path, 0, (char *) &cn_iface, &len, NULL);
        if (ret != ZOK) {
            pr_err("failed to get CLIENT iface: %s: %d", full_path, ret);
            exit(EXIT_FAILURE);
        }
        if (len != sizeof(cn_iface)) {
            pr_err("get CLIENT iface returned invalid data");
            exit(EXIT_FAILURE);
        }

        /* create connection MN->CLIENT */
        qp = connect_mn_with_cn(&mn_iface, mn_ctx, &cn_iface);
        if (!qp) {
            pr_err("failed to connect MN with CLIENT: mn%010d->client%010d", mn_id, cli_id);
            exit(EXIT_FAILURE);
        }
        mn_ctx->local_qps[cli_id] = qp;
        mn_ctx->remote_ifaces[cli_id] = cn_iface;

        /* create RPC initial RR */
        post_recv(qp, mn_ctx->pr_bufs_mr, mn_ctx->pr_bufs + cli_id * RPC_PR_BUF_SZ, RPC_PR_BUF_SZ);

        /* create zoo node and wait for CLIENT->MN connection */
        zoo_create(zh, conn_path, (const char *) &mn_iface, sizeof(mn_iface),
                   &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0);

        pr_info("conn mn%d->client%d", mn_id, cli_id);
    }
}

static inline int do_wait_ack(struct ibv_cq *cq, int nr, unsigned int *imm,
                              const char* file, const char* func, int line, bool hurry) {
    struct ibv_wc wc = { 0 };
    struct bench_timer timer;
    int total = 0, curr;

    if (hurry) {
        bench_timer_start(&timer);
    }

    do {
        curr = ibv_poll_cq(cq, 1, &wc);

        if (curr < 0) {
            pr_err("failed to poll CQ");
            return -EINVAL;
        }

        if (wc.status != IBV_WC_SUCCESS) {
            pr_err("work request failed: %s (wr_id: %lu)", ibv_wc_status_str(wc.status), wc.wr_id);
            return -EINVAL;
        }

        total += curr;

        if (hurry && bench_timer_end(&timer) > WAIT_TIMEOUT_US * 1000ul) {
            pr_err("wait for ACK too long (exceeding %lf secs), %d/%d",
                   WAIT_TIMEOUT_US / 1000000.0, total, nr);
            dump_stack();
            bench_timer_start(&timer);
        }

        if (total < nr && coro_current()) {
            coro_yield_(file, func, line);
        }
    } while (total < nr);

    if (imm) {
        *imm = wc.imm_data;
    }

    return 0;
}

static int rpc_return(struct mn_context *ctx, size_t rv_len, int cli_id) {
    struct ibv_qp *qp = ctx->local_qps[cli_id];
    struct ibv_mr *rv_buf_mr = ctx->rv_buf_mr;
    void *rv_buf = ctx->rv_buf;
    int ret;

    if (rv_len > RPC_RV_BUF_SZ) {
        pr_err("RPC return value too large: %lu", rv_len);
        return -EINVAL;
    }

    post_send(qp, rv_buf_mr, rv_buf, rv_len, 0);

    ret = do_wait_ack(ctx->mem_cq, 1, NULL, 0, 0, 0, true);
    if (ret) {
        pr_err("failed to wait for RPC return value ACK");
        return ret;
    }

    return 0;
}

static void process_rpc(struct mn_context *ctx, dmcallback_t cb, void *aux) {
    unsigned int cli_id;
    size_t rv_size;
    void *pr_buf;

    if (do_wait_ack(ctx->rpc_cq, 1, &cli_id, 0, 0, 0, false) != 0) {
        pr_err("failed to wait for RPC request");
        exit(EXIT_FAILURE);
    }

    pr_buf = ctx->pr_bufs + cli_id * RPC_PR_BUF_SZ;

    /* FIXME: error detection */
    rv_size = cb(ctx, ctx->rv_buf, pr_buf, aux);
    if (IS_ERR(rv_size)) {
        pr_err("RPC return error: %s", strerror(-((int) rv_size)));
        rv_size = 0;
    }

    post_recv(ctx->local_qps[cli_id], ctx->pr_bufs_mr, pr_buf, RPC_PR_BUF_SZ);

    rpc_return(ctx, rv_size, (int) cli_id);
}

/*
 * Memory Node Daemon
 */
_Noreturn void dm_daemon(zhandle_t *zh, void *mem_buf, size_t size, size_t cmem_size, dmcallback_t cb, void *aux) {
    struct net_context net_ctx;
    struct mn_context mn_ctx;
    char path[256];
    int ret, id;

    bench_timer_init_freq();

    ret = init_net_context(&net_ctx);
    if (ret) {
        pr_err("failed to initialize global network context");
        exit(EXIT_FAILURE);
    }

    sprintf(path, DM_ZK_PREFIX "memory_nodes/mn");
    ret = zoo_create(zh, path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, ZOO_SEQUENCE, path, sizeof(path));
    if (ret != ZOK) {
        pr_err("failed to create %s: %d", path, ret);
        exit(EXIT_FAILURE);
    }

    id = atoi(path + strlen(DM_ZK_PREFIX "memory_nodes/mn"));

    ret = init_mn_context(&mn_ctx, &net_ctx, id, mem_buf, size, cmem_size);
    if (ret) {
        pr_err("failed to initialize memory node context");
        exit(EXIT_FAILURE);
    }

    sprintf(path, DM_ZK_PREFIX "memory_nodes/mn%010d/mn_ifaces", id);
    ret = zoo_create(zh, path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
    if (ret != ZOK) {
        pr_err("failed to create %s: %d", path, ret);
        exit(EXIT_FAILURE);
    }
    sprintf(path, DM_ZK_PREFIX "memory_nodes/mn%010d/cn_ifaces", id);
    ret = zoo_create(zh, path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
    if (ret != ZOK) {
        pr_err("failed to create %s: %d", path, ret);
        exit(EXIT_FAILURE);
    }

    ret = zoo_wget_children(zh, path, cn_watcher, &mn_ctx, NULL);
    if (ret != ZOK) {
        pr_err("failed to register zookeeper watcher at %s", path);
        exit(EXIT_FAILURE);
    }

    pr_info("mn %d created", id);

    ethanefs_post_ready(zh);

    for (;;) {
        process_rpc(&mn_ctx, cb, aux);
    }
}

void *dm_get_ptr(void *ctx, dmptr_t remote_addr) {
    int mn_id = DMPTR_MN_ID(remote_addr);
    size_t off = DMPTR_OFF(remote_addr);
    struct mn_context *mn_ctx = ctx;

    if (!remote_addr || DMPTR_MR_TYPE(remote_addr) == DM_CMEM_MR || mn_id != mn_ctx->id) {
        return NULL;
    }

    return mn_ctx->mem_bufs[DMPTR_MR_TYPE(remote_addr)].buf + off;
}

static int mn_id_cmp(const void *a, const void *b) {
    return *(int *) a - *(int *) b;
}

/*
 * Compute Node
 */

dmpool_t *dm_init(zhandle_t *zh) {
    struct String_vector children;
    struct net_context *net_ctx;
    struct cn_context *cn_ctx;
    int nr_mns, *mn_ids;
    char path[256];
    dmpool_t *pool;
    int ret, i, id;

    sprintf(path, DM_ZK_PREFIX "compute_nodes/cn");
    ret = zoo_create(zh, path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL | ZOO_SEQUENCE, path, sizeof(path));
    if (ret != ZOK) {
        pr_err("failed to create %s: %d", path, ret);
        exit(EXIT_FAILURE);
    }

    id = atoi(path + strlen(DM_ZK_PREFIX "compute_nodes/cn"));

    bench_timer_init_freq();

    net_ctx = malloc(sizeof(*net_ctx));
    if (!net_ctx) {
        pr_err("failed to allocate memory for global network context");
        exit(EXIT_FAILURE);
    }

    pool = malloc(sizeof(*pool));
    if (!pool) {
        pr_err("failed to allocate memory for dmpool");
        exit(EXIT_FAILURE);
    }
    cn_ctx = &pool->cn_ctx;

    ret = init_net_context(net_ctx);
    if (ret) {
        pr_err("failed to initialize global network context");
        exit(EXIT_FAILURE);
    }

    ret = zoo_get_children(zh, DM_ZK_PREFIX "memory_nodes", 0, &children);
    if (ret != ZOK) {
        pr_err("failed to get memory node names");
        exit(EXIT_FAILURE);
    }
    nr_mns = children.count;
    mn_ids = malloc(sizeof(*mn_ids) * nr_mns);
    for (i = 0; i < nr_mns; i++) {
        mn_ids[i] = atoi(children.data[i] + strlen("mn"));
    }
    qsort(mn_ids, nr_mns, sizeof(*mn_ids), mn_id_cmp);

    ret = init_cn_context(cn_ctx, net_ctx, zh, nr_mns, mn_ids, id);
    if (ret) {
        pr_err("failed to initialize compute node context");
        exit(EXIT_FAILURE);
    }

    return pool;
}

dmcontext_t *dm_create_context(dmpool_t *pool, size_t local_buf_size) {
    struct cn_context *cn_ctx = &pool->cn_ctx;
    struct cli_context *cli_ctx;
    int ret, i, len, mn_id, id;
    struct net_iface iface;
    struct ibv_qp *qp;
    dmcontext_t *ctx;
    char path[256];
    bool done;

    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        pr_err("failed to allocate memory for per-thread compute context");
        exit(EXIT_FAILURE);
    }
    cli_ctx = &ctx->cli_ctx;

    sprintf(path, DM_ZK_PREFIX "clients/cli");
    ret = zoo_create(cn_ctx->zh, path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL | ZOO_SEQUENCE, path, sizeof(path));
    if (ret != ZOK) {
        pr_err("failed to create %s: %d", path, ret);
        exit(EXIT_FAILURE);
    }

    id = atoi(path + strlen(DM_ZK_PREFIX "clients/cli"));

    ret = init_cli_context(cli_ctx, cn_ctx, id, local_buf_size);
    if (ret) {
        pr_err("failed to initialize thread context");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < cn_ctx->nr_mns; i++) {
        mn_id = cn_ctx->mn_ids[i];

        qp = create_qp(cn_ctx->net_ctx, cli_ctx->mem_cq, cli_ctx->rpc_cq);
        if (!qp) {
            pr_err("failed to create QP (to mn%010d)", mn_id);
            exit(EXIT_FAILURE);
        }
        cli_ctx->local_qps[mn_id] = qp;

        sprintf(path, DM_ZK_PREFIX "memory_nodes/mn%010d/cn_ifaces/client%010d", mn_id, id);
        get_cn_iface(&iface, cli_ctx, qp);
        zoo_create(cn_ctx->zh, path, (const char *) &iface, sizeof(iface),
                   &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0);
    }

    do {
        done = true;

        usleep(1000);

        for (i = 0; i < cn_ctx->nr_mns; i++) {
            mn_id = cn_ctx->mn_ids[i];

            if (cli_ctx->remote_ifaces[mn_id].qpn) {
                continue;
            }

            sprintf(path, DM_ZK_PREFIX "memory_nodes/mn%010d/mn_ifaces/client%010d", mn_id, id);
            len = sizeof(iface);
            ret = zoo_get(cn_ctx->zh, path, 0, (char *) &iface, &len, NULL);
            if (ret == ZNONODE) {
                done = false;
                continue;
            } else if (ret != ZOK) {
                pr_err("failed to get remote iface from mn%010d (path: %s)", mn_id, path);
                exit(EXIT_FAILURE);
            }
            if (len != sizeof(iface)) {
                pr_err("iface size mismatch");
                exit(EXIT_FAILURE);
            }

            ret = connect_qp(cli_ctx->local_qps[mn_id], &iface);
            if (ret) {
                pr_err("failed to connect to remote iface (CLIENT->MN)");
                exit(EXIT_FAILURE);
            }

            pr_info("connected: client%d->mn%d", id, mn_id);
            cli_ctx->remote_ifaces[mn_id] = iface;
        }
    } while (!done);

    return ctx;
}

int dm_destroy_context(dmcontext_t *ctx) {
    // FIXME: TBD
    return 0;
}

void dm_local_buf_switch_default(dmcontext_t *ctx) {
    ctx->cli_ctx.op_buf_mr = ctx->cli_ctx.op_buf_mr_default;
}

void dm_local_buf_switch(dmcontext_t *ctx, void *mr) {
    ctx->cli_ctx.op_buf_mr = mr;
}

void *dm_reg_local_buf(dmcontext_t *ctx, void *buf, size_t size) {
    struct ibv_mr *mr;
    mr = ibv_reg_mr(ctx->cli_ctx.cn_ctx->net_ctx->pd, buf, size, IBV_ACCESS_LOCAL_WRITE);
    if (!mr) {
        pr_err("failed to register local buffer MR: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return mr;
}

void *dm_push(dmcontext_t *ctx, const void *data, size_t size) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    void *ptr = NULL;

    cli_ctx->op_buf_used = ALIGN_UP(cli_ctx->op_buf_used, CACHELINE_SIZE);

    if (cli_ctx->op_buf_used + size > cli_ctx->op_buf_size) {
        pr_err("local buffer overflow");
        goto out;
    }

    ptr = cli_ctx->op_buf + cli_ctx->op_buf_used;
    if (data) {
        memcpy(ptr, data, size);
    }
    cli_ctx->op_buf_used += size;

out:
    return ptr;
}

void dm_mark(dmcontext_t *ctx) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    ethane_assert(cli_ctx->op_buf_mark_cnt < MAX_NESTED_MARKS);
    cli_ctx->op_buf_mark[cli_ctx->op_buf_mark_cnt++] = cli_ctx->op_buf_used;
}

void dm_pop(dmcontext_t *ctx) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    ethane_assert(cli_ctx->op_buf_mark_cnt > 0);
    cli_ctx->op_buf_used = cli_ctx->op_buf_mark[--cli_ctx->op_buf_mark_cnt];
}

static uint64_t get_wr_id() {
    return (uint64_t) coro_current();
}

static inline void insert_into_wr_list(dmcontext_t *ctx, int mn_id, struct ibv_send_wr *wr) {
    struct cli_wr_list *wr_list = &ctx->cli_ctx.wr_list[mn_id];
    ethane_assert(mn_id < MAX_NR_MNS);
    if (!wr_list->head) {
        wr_list->head = wr;
    } else {
        wr_list->tail->next = wr;
    }
    ethane_assert(!wr->next);
    wr_list->tail = wr;
}

int dm_copy_from_remote(dmcontext_t *ctx, void *dst, dmptr_t src, size_t size, dmflag_t flag) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    struct net_iface *remote_iface;
    int ret = 0, mn_id, type;
    struct ibv_send_wr *wr;
    struct ibv_sge *sge;
    unsigned long off;

    if (size == 0) {
        pr_err("data size is zero");
        ret = -EINVAL;
        goto out;
    }

    type = DMPTR_MR_TYPE(src);
    mn_id = DMPTR_MN_ID(src);
    off = DMPTR_OFF(src);

    tracepoint_sample(ethane, rdma_read, ctx->cli_ctx.id, mn_id, off, (unsigned long) dst, size);

    ethane_assert(mn_id < MAX_NR_MNS);

    remote_iface = &cli_ctx->remote_ifaces[mn_id];

    wr = calloc(1, sizeof(*wr) + sizeof(*sge));
    if (!wr) {
        pr_err("failed to allocate memory for work request");
        ret = -ENOMEM;
        goto out;
    }
    sge = (struct ibv_sge *) (wr + 1);
    
    wr->wr_id = get_wr_id();
    wr->sg_list = sge;
    wr->num_sge = 1;

    memset(sge, 0, sizeof(*sge));
    sge->addr = (unsigned long) dst;
    sge->length = size;
    sge->lkey = cli_ctx->op_buf_mr->lkey;

    wr->opcode = IBV_WR_RDMA_READ;

    if (flag & DMFLAG_ACK) {
        wr->send_flags |= IBV_SEND_SIGNALED;
    }
    if (flag & DMFLAG_FENCE) {
        wr->send_flags |= IBV_SEND_FENCE;
    }

    wr->wr.rdma.remote_addr = remote_iface->mem_bufs[type].raddr + off;
    wr->wr.rdma.rkey = remote_iface->mem_bufs[type].rkey;

    insert_into_wr_list(ctx, mn_id, wr);

out:
    return ret;
}

int dm_copy_to_remote(dmcontext_t *ctx, dmptr_t dst, const void *src, size_t size, dmflag_t flag) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    struct net_iface *remote_iface;
    int ret = 0, mn_id, type;
    struct ibv_send_wr *wr;
    struct ibv_sge *sge;
    unsigned long off;

    if (size == 0) {
        pr_err("data size is zero");
        ret = -EINVAL;
        goto out;
    }

    type = DMPTR_MR_TYPE(dst);
    mn_id = DMPTR_MN_ID(dst);
    off = DMPTR_OFF(dst);

    tracepoint_sample(ethane, rdma_write, ctx->cli_ctx.id, mn_id, off, (unsigned long) src, size, src);

    ethane_assert(mn_id < MAX_NR_MNS);

    remote_iface = &cli_ctx->remote_ifaces[mn_id];

    wr = calloc(1, sizeof(*wr) + sizeof(*sge));
    if (!wr) {
        pr_err("failed to allocate memory for work request");
        ret = -ENOMEM;
        goto out;
    }
    sge = (struct ibv_sge *) (wr + 1);
    
    wr->wr_id = get_wr_id();
    wr->sg_list = sge;
    wr->num_sge = 1;

    memset(sge, 0, sizeof(*sge));
    sge->addr = (unsigned long) src;
    sge->length = size;
    sge->lkey = cli_ctx->op_buf_mr->lkey;

    wr->opcode = IBV_WR_RDMA_WRITE;

    if (flag & DMFLAG_ACK) {
        wr->send_flags |= IBV_SEND_SIGNALED;
    }
    if (flag & DMFLAG_FENCE) {
        wr->send_flags |= IBV_SEND_FENCE;
    }

    if (size <= MAX_INLINE_DATA) {
        wr->send_flags |= IBV_SEND_INLINE;
    } else if (flag & DMFLAG_INLINE) {
        pr_err("data size exceeds MAX_INLINE_DATA");
        ret = -EINVAL;
        goto out;
    }

    wr->wr.rdma.remote_addr = remote_iface->mem_bufs[type].raddr + off;
    wr->wr.rdma.rkey = remote_iface->mem_bufs[type].rkey;

    insert_into_wr_list(ctx, mn_id, wr);

out:
    return ret;
}

/* TODO: This only marks WR list tail. Ordering between posted/non-posted ops are not considered */
int dm_set_ack_all(dmcontext_t *ctx) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    int mn_id, nr_acks = 0;

    for (mn_id = 0; mn_id < ctx->cli_ctx.cn_ctx->nr_mns; mn_id++) {
        if (!cli_ctx->wr_list[mn_id].tail) {
            continue;
        }
        cli_ctx->wr_list[mn_id].tail->send_flags |= IBV_SEND_SIGNALED;
        nr_acks++;
    }

    return nr_acks;
}

int dm_barrier(dmcontext_t *ctx) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    struct ibv_send_wr *bad, *wr, *tmp;
    struct cli_wr_list *wr_list;
    int mn_id, ret = 0;

    struct bench_timer timer;

    bench_timer_start(&timer);

    for (mn_id = 0; mn_id < ctx->cli_ctx.cn_ctx->nr_mns; mn_id++) {
        wr_list = &cli_ctx->wr_list[mn_id];
        if (!wr_list->head) {
            continue;
        }

        /* This enables doorbell batching. */
        if (ibv_post_send(cli_ctx->local_qps[mn_id], wr_list->head, &bad)) {
            pr_err("failed to post work request");
            ret = -EINVAL;
            goto out;
        }

        /* Free list nodes */
        for (wr = wr_list->head; wr; wr = tmp) {
            tmp = wr->next;
            free(wr);
        }

        wr_list->head = wr_list->tail = NULL;
    }

out:
    return ret;
}

int dm_wait_ack_(dmcontext_t *ctx, int nr, const char *file, const char *func, int line) {
    int ret = 0;

    if (unlikely(nr == 0)) {
        goto out;
    }

    if (unlikely(ret = dm_barrier(ctx))) {
        goto out;
    }

    ret = do_wait_ack(ctx->cli_ctx.mem_cq, nr, NULL, file, func, line, true);

out:
    return ret;
}

coro_t *dm_get_ack_coro(dmcontext_t *ctx) {
    struct ibv_wc wc = { 0 };
    int curr;

    curr = ibv_poll_cq(ctx->cli_ctx.mem_cq, 1, &wc);

    if (curr < 0) {
        pr_err("failed to poll CQ");
        return ERR_PTR(-EINVAL);
    } else if (wc.status != IBV_WC_SUCCESS) {
        pr_err("work request failed: %s (wr_id: %lu)", ibv_wc_status_str(wc.status), wc.wr_id);
        return ERR_PTR(-EINVAL);
    }

    return (coro_t *) wc.wr_id;
}

int dm_cas(dmcontext_t *ctx, dmptr_t dst, void *src, void *old, size_t size, dmflag_t flag) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    struct net_iface *remote_iface;
    int ret = 0, mn_id, type;
    struct ibv_send_wr *wr;
    struct ibv_sge *sge;
    unsigned long off;

    if (size != sizeof(uint64_t)) {
        pr_err("invalid size for CAS");
        ret = -EINVAL;
        goto out;
    }

    type = DMPTR_MR_TYPE(dst);
    mn_id = DMPTR_MN_ID(dst);
    off = DMPTR_OFF(dst);

    remote_iface = &cli_ctx->remote_ifaces[mn_id];
    
    wr = calloc(1, sizeof(*wr) + sizeof(*sge));
    if (!wr) {
        pr_err("failed to allocate memory for work request");
        ret = -ENOMEM;
        goto out;
    }
    sge = (struct ibv_sge *) (wr + 1);
    
    wr->wr_id = get_wr_id();
    wr->sg_list = sge;
    wr->num_sge = 1;

    memset(sge, 0, sizeof(*sge));
    sge->addr = (unsigned long) old;
    sge->length = size;
    sge->lkey = cli_ctx->op_buf_mr->lkey;

    wr->opcode = IBV_WR_ATOMIC_CMP_AND_SWP;

    if (flag & DMFLAG_ACK) {
        wr->send_flags |= IBV_SEND_SIGNALED;
    }
    if (flag & DMFLAG_FENCE) {
        wr->send_flags |= IBV_SEND_FENCE;
    }

    wr->wr.atomic.remote_addr = remote_iface->mem_bufs[type].raddr + off;
    wr->wr.atomic.rkey = remote_iface->mem_bufs[type].rkey;
    wr->wr.atomic.compare_add = *(uint64_t *) old;
    wr->wr.atomic.swap = *(uint64_t *) src;

    insert_into_wr_list(ctx, mn_id, wr);

out:
    return ret;
}

int dm_faa(dmcontext_t *ctx, dmptr_t ptr, void *add_old, size_t size, dmflag_t flag) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    struct net_iface *remote_iface;
    int ret = 0, mn_id, type;
    struct ibv_send_wr *wr;
    struct ibv_sge *sge;
    unsigned long off;

    if (size != sizeof(uint64_t)) {
        pr_err("invalid size for FAA");
        ret = -EINVAL;
        goto out;
    }

    type = DMPTR_MR_TYPE(ptr);
    mn_id = DMPTR_MN_ID(ptr);
    off = DMPTR_OFF(ptr);

    remote_iface = &cli_ctx->remote_ifaces[mn_id];
    
    wr = calloc(1, sizeof(*wr) + sizeof(*sge));
    if (!wr) {
        pr_err("failed to allocate memory for work request");
        ret = -ENOMEM;
        goto out;
    }
    sge = (struct ibv_sge *) (wr + 1);
    
    wr->wr_id = get_wr_id();
    wr->sg_list = sge;
    wr->num_sge = 1;
    
    memset(sge, 0, sizeof(*sge));
    sge->addr = (unsigned long) add_old;
    sge->length = size;
    sge->lkey = cli_ctx->op_buf_mr->lkey;

    wr->opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;

    if (flag & DMFLAG_ACK) {
        wr->send_flags |= IBV_SEND_SIGNALED;
    }
    if (flag & DMFLAG_FENCE) {
        wr->send_flags |= IBV_SEND_FENCE;
    }

    wr->wr.atomic.remote_addr = remote_iface->mem_bufs[type].raddr + off;
    wr->wr.atomic.rkey = remote_iface->mem_bufs[type].rkey;
    wr->wr.atomic.compare_add = *(uint64_t *) add_old;

    insert_into_wr_list(ctx, mn_id, wr);

out:
    return ret;
}

int dm_flush(dmcontext_t *ctx, dmptr_t addr, dmflag_t flag) {
    void *buf;
    buf = dm_push(ctx, NULL, 1);
    return dm_copy_from_remote(ctx, buf, DMPTR_DUMMY(DMPTR_MN_ID(addr)), 1, flag);
}

int dm_rpc(dmcontext_t *ctx, dmptr_t addr, void *data, size_t size) {
    struct cli_context *cli_ctx = &ctx->cli_ctx;
    struct ibv_qp *qp;
    int ret = 0, mn;

    pr_debug("rpc addr=%lx data=%p size=%lu [%s]", addr, data, size, get_hex_str(data, size));

    mn = DMPTR_MN_ID(addr);

    qp = cli_ctx->local_qps[mn];

    post_recv(qp, cli_ctx->rv_buf_mr, cli_ctx->rv_buf, RPC_RV_BUF_SZ);

    post_send(qp, cli_ctx->op_buf_mr, data, size, ctx->cli_ctx.id);

    if (do_wait_ack(cli_ctx->mem_cq, 1, NULL, 0, 0, 0, true) < 0) {
        pr_err("failed to send RPC request");
        ret = -EINVAL;
        goto out;
    }

    if (do_wait_ack(cli_ctx->rpc_cq, 1, NULL, 0, 0, 0, true) < 0) {
        pr_err("failed to receive RPC response");
        ret = -EINVAL;
        goto out;
    }

out:
    return ret;
}

const void *dm_get_rv(dmcontext_t *ctx) {
    return ctx->cli_ctx.rv_buf;
}

int dm_get_nr_mns(dmpool_t *pool) {
    return pool->cn_ctx.nr_mns;
}

void dm_get_mns(dmpool_t *pool, int *ids) {
    int nr = pool->cn_ctx.nr_mns;
    memcpy(ids, pool->cn_ctx.mn_ids, nr * sizeof(int));
}

int dm_get_cli_id(dmcontext_t *ctx) {
    return ctx->cli_ctx.id;
}

int dm_get_cn_id(dmcontext_t *ctx) {
    return ctx->cli_ctx.cn_ctx->id;
}

dmpool_t *dm_get_pool(dmcontext_t *ctx) {
    return container_of(ctx->cli_ctx.cn_ctx, dmpool_t, cn_ctx);
}
