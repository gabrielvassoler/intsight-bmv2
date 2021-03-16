/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

////////////////////////////////////////////////////////////////
////////               HEADER DEFINITIONS               ////////
////////////////////////////////////////////////////////////////

const bit<8> TYPE_PATH_SRC       = 0x1;
const bit<8> TYPE_PATH_LENGTH    = 0x2;
const bit<8> TYPE_PATH_CODE      = 0x3;
const bit<8> TYPE_CONTENTION_PTS = 0x4;
const bit<8> TYPE_SUSPICION_PTS  = 0x5;
const bit<8> TYPE_E2E_DELAY      = 0x6;
const bit<8> TYPE_INGRESS_PCKTS  = 0x7;
const bit<8> TYPE_INGRESS_BYTES  = 0x8;
const bit<8> TYPE_BLOOM_FILTER   = 0x9;
const bit<8> TYPE_LOOP_DETECTED  = 0x10;

#define ETHERNET_HS 14  // bytes
header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header arp_h {
    bit<16> hardware_type;
    bit<16> protocol_type;
    bit<8>  hardware_length;
    bit<8>  protocol_length;
    bit<16> op;
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}

#define IPV4_HS 20  // bytes
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> total_length;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragment_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> header_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

#define TELEMETRY_HS 53  // bytes
header intsight_telemetry_h {
    bit<32> epoch;
    bit<10> path_src;
    bit<6>  path_length;
    bit<16> path_code;
    bit<48> contention_points;
    bit<48> suspicion_points;
    bit<32> e2e_delay;
    bit<32> ingress_packets;
    bit<32> ingress_bytes;
    bit<8> next_header;
}

header intsight_telemetry_h1{
    bit<32> epoch;
    bit<8>  next_header;
    bit<8>  h_len;
}

header path_src_h{
    bit<8>  type;
    bit<10> path_src;
}

header path_length_h{
    bit<8>  type;
    bit<6>  path_length;
}
header path_code_h{
    bit<8>  type;
    bit<16> path_code;
}

header contention_points_h{
    bit<8>  type;
    bit<48> contention_points;
}

header suspicion_points_h{
    bit<8>  type;
    bit<48> suspicion_points;
}

header e2e_delay_h{
    bit<8>  type;
    bit<32> e2e_delay;
}

header ingress_packets_h{
    bit<8>  type;
    bit<32> ingress_packets;
}

header ingress_bytes_h{
    bit<8>  type;
    bit<32> ingress_bytes;
}

header bloom_filter_h{
    bit<8>  type;
    bit<64> vector;
}

header loop_detected_h{
    bit<8>  type;
    bit<8>  detect;
}

#define REPORT_HS 54  // bytes
header intsight_report_h {
    bit<32> epoch;
    bit<32> egress_epoch;
    bit<32> flow_ID;
    // path_src, path_length, and path_code form the path ID
    bit<10> path_src;
    bit<6>  path_length;
    bit<16> path_code;
    bit<48> contention_points;
    bit<48> suspicion_points;
    bit<16> path_dst;
    bit<32> high_delays;
    bit<32> drops;
    bit<32> ingress_packets;
    bit<32> ingress_bytes;
    bit<32> egress_packets;
    bit<32> egress_bytes;
}

#define LOOP_REPORT_HS 21  // bytes
header loop_report_h {
    bit<32> epoch;
    bit<32> flow_ID;
    // path_src, path_length, and path_code form the path ID
    bit<10> path_src;
    bit<6>  path_length;
    bit<16> path_code;
    bit<8>  node_ID;
    bit<64> bloom_filter;
}

struct headers {
    ethernet_h            ethernet;
    arp_h                 arp;
    ipv4_h                ipv4;
    intsight_report_h     report;
    intsight_telemetry_h1 telemetry;
    path_src_h            path_src;
    path_length_h         path_length;
    path_code_h           path_code;
    contention_points_h   contention_points;
    suspicion_points_h    suspicion_points;
    e2e_delay_h           e2e_delay;
    ingress_packets_h     ingress_pckts;
    ingress_bytes_h       ingress_bytes;
    bloom_filter_h        bloom_filter;
    loop_detected_h       loop_detected;
    loop_report_h         loop_report;
}

struct custom_metadata_t {
    bit<1>   is_ingress_node;
    bit<1>   is_egress_node;
    bit<32>  flow_ID;
    bit<10>  node_ID;
    bit<32>  current_epoch;
    
    bit<32>  i_last_epoch;
    bit<32>  i_ingress_packets;
    bit<32>  i_ingress_bytes;
    
    bit<32>  qt_timedelta;
    bit<19>  qt_depth;
    bit<32>  qt_bitrate;

    bit<32>  e_epoch;
    bit<32>  e_egress_epoch;
    bit<32>  e_new_egress_epoch;
    bit<10>  e_path_src;
    bit<6>   e_path_length;
    bit<16>  e_path_code;
    bit<48>  e_contention_points;
    bit<48>  e_suspicion_points;
    bit<32>  e_high_delays;
    bit<32>  e_drops;
    bit<32>  e_ingress_packets;
    bit<32>  e_ingress_bytes;
    bit<32>  e_egress_packets;
    bit<32>  e_egress_bytes;
    bit<32>  e_egress_bytes_ths;

    bit<1>   e_check_e2e_delay;
    bit<32>  e_e2e_delay_threshold;
    bit<1>   e_high_e2e_delay;
    bit<1>   e_check_high_delays;
    bit<32>  e_high_delays_threshold;
    bit<1>   e_check_bandwidth_and_drops;
    bit<32>  e_bandwidth_threshold;
    bit<32>  e_drops_threshold;
    bit<1>   e_report;
    bit<32>  e_node_IP_addr;
    bit<32>  e_analyzer_IP_addr;
    bit<8>   len;
    bit<8>   hash1;
    bit<8>   hash2;
    bit<64>  cmp1;
    bit<64>  cmp2;
    bit<32>  nbase;
    bit<8>   loop;
    bit<64>  e_bloom_filter;
    bit<1>   report_type; //set to 0 for end of epoch report, and set to 1 to loop report
}

////////////////////////////////////////////////////////////////
////////               PARSER DEFINITIONS               ////////
////////////////////////////////////////////////////////////////

#define ET_IPV4 0x0800
#define PROTOCOL_INTSIGHT_TELEMETRY 223
#define PROTOCOL_INTSIGHT_REPORT 224
#define PROTOCOL_LOOP_REPORT 225
// 20 = 1,048,576 microseconds ~= 1 second
// 19 =   524,288 microseconds
// 18 =   262,144 microseconds
// 17 =   131,072 microseconds
// 16 =    65,536 microseconds
// 15 =    32,768 microseconds
// 14 =    16,384 microseconds
// 13 =     8,192 microseconds
// 10 =     1,024 microseconds ~= 1 millisecond
#define EPOCH_SHIFT 16

#define IN_DELAY 20
#define PN_DELAY 110
#define EN_DELAY 60

parser ParserImpl(packet_in pkt, out headers hdrs, inout custom_metadata_t cmd, 
                  inout standard_metadata_t smd) {
    state start {
        pkt.extract(hdrs.ethernet);
        transition select(hdrs.ethernet.ether_type) {
            0x0806: parse_arp;
            ET_IPV4: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_arp {
        pkt.extract(hdrs.arp);
        transition select(hdrs.arp.protocol_type) {
            ET_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdrs.ipv4);
        transition select(hdrs.ipv4.protocol) {
            PROTOCOL_INTSIGHT_TELEMETRY: parse_intsight_telemetry;
            PROTOCOL_INTSIGHT_REPORT: parse_intsight_report;
            default: accept;
        }
    }

    state parse_next_telemetry {
        transition select(hdrs.telemetry.next_header) {
            PROTOCOL_INTSIGHT_REPORT: parse_intsight_report;
            default: accept;
        }
    }

    state parse_intsight_telemetry {
        pkt.extract(hdrs.telemetry);
        cmd.len = hdrs.telemetry.h_len;
        transition select(cmd.len) {
            0x0: parse_next_telemetry;
            default: parse_hdrs;
        }
    }

    state parse_hdrs {
        cmd.len = cmd.len - 0x1;

        bit<8> nh = pkt.lookahead<bit<8>>();
        transition select(nh){
            TYPE_PATH_SRC : parse_path_src;
            TYPE_PATH_LENGTH : parse_path_length;
            TYPE_PATH_CODE : parse_path_code;
            TYPE_CONTENTION_PTS : parse_contention_pts;
            TYPE_SUSPICION_PTS : parse_suspicion_pts;
            TYPE_E2E_DELAY : parse_e2e_delay;
            TYPE_INGRESS_PCKTS : parse_ingress_pckts;
            TYPE_INGRESS_BYTES : parse_ingress_bytes;
            TYPE_BLOOM_FILTER : parse_bloom_filter;
            TYPE_LOOP_DETECTED : parse_loop_detected;
            default : accept;
        }
    }

    state parse_hdrs_aux {
        transition select(cmd.len){
            0x0 : parse_next_telemetry;
            default : parse_hdrs;
        }
    }

    state parse_path_src{
        pkt.extract(hdrs.path_src);

        transition parse_hdrs_aux;
    }

    state parse_path_length{
        pkt.extract(hdrs.path_length);

        transition parse_hdrs_aux;
    }

    state parse_path_code{
        pkt.extract(hdrs.path_code);

        transition parse_hdrs_aux;
    }

    state parse_contention_pts{
        pkt.extract(hdrs.contention_points);

        transition parse_hdrs_aux;
    }

    state parse_suspicion_pts{
        pkt.extract(hdrs.suspicion_points);

        transition parse_hdrs_aux;
    }

    state parse_e2e_delay{
        pkt.extract(hdrs.e2e_delay);

        transition parse_hdrs_aux;
    }

    state parse_ingress_pckts{
        pkt.extract(hdrs.ingress_pckts);

        transition parse_hdrs_aux;
    }

    state parse_ingress_bytes{
        pkt.extract(hdrs.ingress_bytes);

        transition parse_hdrs_aux;
    }

    state parse_bloom_filter{
        pkt.extract(hdrs.bloom_filter);

        transition parse_hdrs_aux;
    }

    state parse_loop_detected{
        pkt.extract(hdrs.loop_detected);

        transition parse_hdrs_aux;
    }

    state parse_intsight_report {
        pkt.extract(hdrs.report);
        transition accept;
    }
}

////////////////////////////////////////////////////////////////
////////                   PIPELINES                    ////////
////////////////////////////////////////////////////////////////

#define NORMAL_PACKET 0
#define CLONE_PACKET  2
#define INTSIGHT_MIRROR_SESSION 42

#define REGWID 100  // Number of registers to store flow statistics/metadata

control verifyChecksum(inout headers hdrs, inout custom_metadata_t cmd) {
    apply {
        verify_checksum(
            hdrs.ipv4.isValid(),
            {
                hdrs.ipv4.version,
                hdrs.ipv4.ihl,
                hdrs.ipv4.dscp,
                hdrs.ipv4.ecn,
                hdrs.ipv4.total_length,
                hdrs.ipv4.identification,
                hdrs.ipv4.flags,
                hdrs.ipv4.fragment_offset,
                hdrs.ipv4.ttl,
                hdrs.ipv4.protocol,
                hdrs.ipv4.src_addr,
                hdrs.ipv4.dst_addr
            },
            hdrs.ipv4.header_checksum, 
            HashAlgorithm.csum16
        );
    }
}

control ingress(inout headers hdrs, inout custom_metadata_t cmd, 
                inout standard_metadata_t smd) {

    register<bit<10>>(1) node_ID;

    // Registers in network ingress nodes
    register<bit<32>>(REGWID)  i_epoch;
    register<bit<32>>(REGWID)  i_ingress_packets;
    register<bit<32>>(REGWID)  i_ingress_bytes;
    
    action drop() {
        mark_to_drop();
        // mark_to_drop(smd);
    }
    
    action ipv4_forward(bit<9> port) {
        smd.egress_spec = port;
        hdrs.ipv4.ttl = hdrs.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdrs.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        default_action = drop();
    }

    action set_flow_ID(bit<32> flow_ID) {
        cmd.flow_ID = flow_ID;
    }

    table flow_ID {
        key = {
            hdrs.ipv4.src_addr: exact;
            hdrs.ipv4.dst_addr: exact;
            // hdrs.ipv4.protocol: exact;
        }
        actions = {
            set_flow_ID;
        }
        default_action = set_flow_ID(REGWID - 1);
    }
    
    ///////////////////////////////////////////////////////////////
    ////////          INGRESS PIPELINE APPLY BLOCK         ////////
    ///////////////////////////////////////////////////////////////
    apply {
        if (hdrs.ipv4.isValid()) {
            ipv4_lpm.apply();

            if(smd.egress_spec != 0 && !hdrs.report.isValid()) {
                if(smd.ingress_port <= 2) {
                    cmd.is_ingress_node = 1;
                }
                if(smd.egress_spec <= 2) {
                    // implicit that it is greater than 0 by the outer if
                    cmd.is_egress_node = 1;
                }

                if(cmd.is_ingress_node == 1 || cmd.is_egress_node == 1) {
                    node_ID.read(cmd.node_ID, 0);
                    flow_ID.apply();
                    cmd.current_epoch = \
                        (bit<32>) (smd.ingress_global_timestamp >> EPOCH_SHIFT);
                }

                ///////////////////////////////////////////////////////////
                ////////          INGRESS NODE PROCESSING          ////////
                ///////////////////////////////////////////////////////////
                if(!hdrs.telemetry.isValid() && cmd.is_ingress_node == 1) {
                    // UPDATE FLOW REGISTERS
                    i_epoch.read(cmd.i_last_epoch, cmd.flow_ID);
                    i_epoch.write(cmd.flow_ID, cmd.current_epoch);
                    if(cmd.i_last_epoch == cmd.current_epoch) {
                        i_ingress_packets.read(cmd.i_ingress_packets,
                                                cmd.flow_ID);
                        cmd.i_ingress_packets = cmd.i_ingress_packets + 1;
                        
                        i_ingress_bytes.read(cmd.i_ingress_bytes,
                                                cmd.flow_ID);
                        cmd.i_ingress_bytes = \
                                cmd.i_ingress_bytes + smd.packet_length;
                    } else {
                        cmd.i_ingress_packets = 1;
                        cmd.i_ingress_bytes = smd.packet_length;
                    }
                    i_ingress_packets.write(cmd.flow_ID,
                                            cmd.i_ingress_packets);
                    i_ingress_bytes.write(cmd.flow_ID, cmd.i_ingress_bytes);
                }
            }
        } else if(hdrs.arp.isValid()) {
            smd.egress_spec = smd.ingress_port;
        } else {
            mark_to_drop();
        }
    }
}

control egress(inout headers hdrs, inout custom_metadata_t cmd, 
               inout standard_metadata_t smd) {

    // Registers in network egress nodes
    register<bit<32>>(REGWID)  e_epoch;
    register<bit<32>>(REGWID)  e_egress_epoch;
    register<bit<10>>(REGWID)  e_path_src;
    register<bit<6>>(REGWID)   e_path_length;
    register<bit<16>>(REGWID)  e_path_code;
    register<bit<48>>(REGWID)  e_contention_points;
    register<bit<48>>(REGWID)  e_suspicion_points;
    register<bit<32>>(REGWID)  e_high_delays;
    register<bit<32>>(REGWID)  e_ingress_packets;
    register<bit<32>>(REGWID)  e_ingress_bytes;
    register<bit<32>>(REGWID)  e_egress_packets;
    register<bit<32>>(REGWID)  e_egress_bytes;

    action rewrite_mac_addrs(bit<48> src, bit<48> dst) {
        hdrs.ethernet.src_addr = src;
        hdrs.ethernet.dst_addr = dst;
        if(hdrs.arp.isValid()) {
            hdrs.arp.op = 2;
            hdrs.arp.sender_hw_addr = src;
            bit<48> hw = hdrs.arp.sender_hw_addr;
            bit<32> proto = hdrs.arp.sender_proto_addr;
            hdrs.arp.sender_hw_addr = src;
            hdrs.arp.target_hw_addr = hw;
            hdrs.arp.sender_proto_addr = hdrs.arp.target_proto_addr;
            hdrs.arp.target_proto_addr = proto;

        }
    }

    table mac_addrs {
        key = {
            smd.egress_port: exact;
        }
        actions = {
            NoAction;
            rewrite_mac_addrs;
        }
        default_action = NoAction();
    }

    action set_contention_thresholds(bit<32> timedelta, bit<19> depth) {
        cmd.qt_timedelta = timedelta;
        cmd.qt_depth = depth;
    }

    table contention_thresholds {
        key = {
            smd.egress_port: exact;
        }
        actions = {
            set_contention_thresholds;
        }
        default_action = set_contention_thresholds(0, 0);
    }

    action set_suspicion_thresholds(bit<32> bitrate) {
        cmd.qt_bitrate = bitrate;
    }

    table suspicion_thresholds {
        key = {
            smd.egress_port: exact;
        }
        actions = {
            set_suspicion_thresholds;
        }
        default_action = set_suspicion_thresholds(0);
    }

    action set_path_ID(bit<16> new_path_code) {
        hdrs.path_code.path_code = new_path_code;
    }

    table update_path_ID {
        key = {
            hdrs.path_src.path_src: exact;
            hdrs.path_length.path_length: exact;
            hdrs.path_code.path_code: exact;
            smd.egress_port: exact;
        }
        actions = {
            set_path_ID;
            NoAction;
        }
        default_action = NoAction();
    }

    action set_e2e_delay_threshold(bit<32> threshold) {
        cmd.e_check_e2e_delay = 1;
        cmd.e_e2e_delay_threshold = threshold;
    }

    table e2e_delay_threshold {
        key = {
            cmd.flow_ID: exact;
        }
        actions = {
            set_e2e_delay_threshold;
            NoAction;
        }
        default_action = NoAction();
    }

    action set_high_delays_threshold(bit<32> threshold) {
        cmd.e_check_high_delays = 1;
        cmd.e_high_delays_threshold = threshold;
    }

    table high_delays_threshold {
        key = {
            cmd.flow_ID: exact;
        }
        actions = {
            set_high_delays_threshold;
            NoAction;
        }
        default_action = NoAction();
    }

    action set_bandwidth_thresholds(bit<32> bandwidth, bit<32> drops) {
        cmd.e_check_bandwidth_and_drops = 1;
        cmd.e_bandwidth_threshold = bandwidth;
        cmd.e_drops_threshold = drops;
    }

    table bandwidth_thresholds {
        key = {
            cmd.flow_ID: exact;
        }
        actions = {
            set_bandwidth_thresholds;
            NoAction;
        }
        default_action = NoAction();
    }

    action set_node_and_analyzer_IP_addr(bit<32> node, bit<32> analyzer) {
        cmd.e_node_IP_addr = node;
        cmd.e_analyzer_IP_addr = analyzer;
    }

    table node_and_analyzer_IP_addr {
        actions = {
            set_node_and_analyzer_IP_addr;
            NoAction;
        }
        default_action = NoAction();
    }

    ///////////////////////////////////////////////////////////////
    ////////          EGRESS PIPELINE APPLY BLOCK          ////////
    ///////////////////////////////////////////////////////////////
    apply {
        if(smd.egress_port != 0) {
            mac_addrs.apply();

            // if(hdrs.ipv4.protocol == 0) {  // Only for testing purposes
            if(smd.instance_type == NORMAL_PACKET && !hdrs.report.isValid()
                    && !hdrs.arp.isValid()) {
                ////////////////////////////////////////////////////////////////
                ////////        INGRESS NODE PROCESSING (PART 2)        ////////
                ////////////////////////////////////////////////////////////////
                if(!hdrs.telemetry.isValid() && cmd.is_ingress_node == 1) {
                    // CREATE TELEMETRY FIELDS
                    /*hdrs.telemetry.setValid();
                    hdrs.telemetry.epoch = cmd.current_epoch;
                    hdrs.telemetry.path_src = cmd.node_ID;
                    hdrs.telemetry.path_length = 0;
                    hdrs.telemetry.path_code = 0;
                    hdrs.telemetry.e2e_delay = IN_DELAY;
                    hdrs.telemetry.ingress_packets = cmd.i_ingress_packets;
                    hdrs.telemetry.ingress_bytes = cmd.i_ingress_bytes;
                    hdrs.telemetry.contention_points = 0;
                    hdrs.telemetry.next_header = hdrs.ipv4.protocol;*/

                    hdrs.telemetry.setValid();
                    hdrs.telemetry.next_header = hdrs.ipv4.protocol;
                    hdrs.telemetry.epoch = cmd.current_epoch;
                    hdrs.telemetry.h_len = 0x11;

                    hdrs.path_src.setValid();
                    hdrs.path_src.type = TYPE_PATH_SRC;
                    hdrs.path_src.path_src = cmd.node_ID;

                    hdrs.path_length.setValid();
                    hdrs.path_length.type = TYPE_PATH_LENGTH;
                    hdrs.path_length.path_length = 0;

                    hdrs.path_code.setValid();
                    hdrs.path_code.type = TYPE_PATH_CODE;
                    hdrs.path_code.path_code = 0;

                    hdrs.e2e_delay.setValid();
                    hdrs.e2e_delay.type = TYPE_E2E_DELAY;
                    hdrs.e2e_delay.e2e_delay = IN_DELAY;  // 120

                    hdrs.ingress_pckts.setValid();
                    hdrs.ingress_pckts.type = TYPE_INGRESS_PCKTS;
                    hdrs.ingress_pckts.ingress_packets = cmd.i_ingress_packets;

                    hdrs.ingress_bytes.setValid();
                    hdrs.ingress_bytes.type = TYPE_INGRESS_BYTES;
                    hdrs.ingress_bytes.ingress_bytes = cmd.i_ingress_bytes;

                    hdrs.contention_points.setValid();
                    hdrs.contention_points.type = TYPE_CONTENTION_PTS;
                    hdrs.contention_points.contention_points = 0;

                    hdrs.suspicion_points.setValid();
                    hdrs.suspicion_points.type = TYPE_SUSPICION_PTS;
                    hdrs.suspicion_points.suspicion_points = 0;

                    hdrs.bloom_filter.setValid();
                    hdrs.bloom_filter.type = TYPE_BLOOM_FILTER;
                    hdrs.bloom_filter.vector = 0;
                    hash(cmd.hash1, HashAlgorithm.crc32, cmd.nbase,  {cmd.node_ID}, (bit<8>) 64); 
                    hash(cmd.hash2, HashAlgorithm.xor16, cmd.nbase,  {cmd.node_ID}, (bit<8>) 64);
                    hdrs.bloom_filter.vector = hdrs.bloom_filter.vector | ((bit<64>) 1 << cmd.hash1);
                    hdrs.bloom_filter.vector = hdrs.bloom_filter.vector | ((bit<64>) 1 << cmd.hash2);

                    hdrs.loop_detected.setValid();
                    hdrs.loop_detected.type = TYPE_LOOP_DETECTED;
                    hdrs.loop_detected.detect = 0;

                    hdrs.ipv4.protocol = PROTOCOL_INTSIGHT_TELEMETRY;
                    hdrs.ipv4.total_length = hdrs.ipv4.total_length
                                             + TELEMETRY_HS;
                }

                ////////////////////////////////////////////////////////////////
                ////////             PROCESSING ON ALL NODES            ////////
                ////////////////////////////////////////////////////////////////
                if(hdrs.telemetry.isValid()) {
                    // INCREMENT FIELD: END-TO-END DELAY
                    hdrs.e2e_delay.e2e_delay = \
                        hdrs.e2e_delay.e2e_delay
                        + PN_DELAY
                        + (smd.deq_timedelta);
                    // CONTENTION?
                    contention_thresholds.apply();
                    if(smd.deq_timedelta >= cmd.qt_timedelta 
                            || smd.enq_qdepth >= cmd.qt_depth) {
                        // MARK FIELD: CONTENTION POINTS
                        hdrs.contention_points.contention_points = \
                            hdrs.contention_points.contention_points
                            | ((bit<48>) 1) << hdrs.path_length.path_length;
                    }
                    // SUSPICION?
                    suspicion_thresholds.apply();
                    if(hdrs.ingress_bytes.ingress_bytes >= cmd.qt_bitrate) {
                        // MARK FIELD: SUSPICION POINTS
                        hdrs.suspicion_points.suspicion_points = \
                            hdrs.suspicion_points.suspicion_points
                            | ((bit<48>) 1) << hdrs.path_length.path_length;
                    }
                    //LOOP?
                    if(hdrs.bloom_filter.isValid()){
                        hash(cmd.hash1, HashAlgorithm.crc32, cmd.nbase,  {cmd.node_ID}, (bit<8>) 64); 
                        hash(cmd.hash2, HashAlgorithm.xor16, cmd.nbase,  {cmd.node_ID}, (bit<8>) 64);
                        
                        cmd.cmp1 = hdrs.bloom_filter.vector | ((bit<64>) 1 << cmd.hash1);
                        cmd.cmp2 = cmd.cmp1 | ((bit<64>) 1 << cmd.hash2);
                        
                        if(hdrs.bloom_filter.vector == cmd.cmp2){
                            hdrs.loop_detected.detect = 0x1;
                            cmd.report_type = 0x1;
                            cmd.e_bloom_filter = hdrs.bloom_filter.vector;
                            clone3(CloneType.E2E, INTSIGHT_MIRROR_SESSION, {cmd});
                        }
                    }
                    // UPDATE FIELD: PATH ID
                    update_path_ID.apply();
                    hdrs.path_length.path_length =
                        hdrs.path_length.path_length + 1;
                }

                ////////////////////////////////////////////////////////////////
                ////////             EGRESS NODE PROCESSING             ////////
                ////////////////////////////////////////////////////////////////
                if(hdrs.telemetry.isValid() && cmd.is_egress_node == 1) {
                    
                    hdrs.e2e_delay.e2e_delay = hdrs.e2e_delay.e2e_delay + EN_DELAY;

                    // if(cmd.is_egress_node == 1) {
                    //     hdrs.e2e_delay.e2e_delay =
                    //         hdrs.e2e_delay.e2e_delay + 130;
                    // } else {
                    //     hdrs.e2e_delay.e2e_delay =
                    //         hdrs.e2e_delay.e2e_delay + 190;
                    // }

                    // HIGH END-TO-END DELAY?
                    e2e_delay_threshold.apply();
                    if(cmd.e_check_e2e_delay == 1
                        && (hdrs.e2e_delay.e2e_delay
                            >= cmd.e_e2e_delay_threshold)) {
                        cmd.e_high_e2e_delay = 1;
                    } else {
                        cmd.e_high_e2e_delay = 0;
                    }

                    // UPDATE REGISTERS
                    // ================
                    // EPOCH: Store the last epoch in cmd.e_epoch and update 
                    // the register value to the newly received one.
                    e_epoch.read(cmd.e_epoch, cmd.flow_ID);
                    e_epoch.write(cmd.flow_ID, hdrs.telemetry.epoch);

                    // EGRESS EPOCH
                    e_egress_epoch.read(cmd.e_egress_epoch, cmd.flow_ID);
                    cmd.e_new_egress_epoch = (bit<32>) ((smd.ingress_global_timestamp + (bit<48>) smd.deq_timedelta + PN_DELAY + EN_DELAY) >> EPOCH_SHIFT);
                    e_egress_epoch.write(cmd.flow_ID, cmd.e_new_egress_epoch);

                    // PATH ID: Store the last path in cmd.e_path_src,length,
                    // code and update the registers to the newly received one.
                    e_path_src.read(cmd.e_path_src, cmd.flow_ID);
                    e_path_src.write(cmd.flow_ID, hdrs.path_src.path_src);
                    e_path_length.read(cmd.e_path_length, cmd.flow_ID);
                    e_path_length.write(cmd.flow_ID,
                                        hdrs.path_length.path_length);
                    e_path_code.read(cmd.e_path_code, cmd.flow_ID);
                    e_path_code.write(cmd.flow_ID, hdrs.path_code.path_code);
                    
                    // HIGH DELAYS
                    e_high_delays.read(cmd.e_high_delays, cmd.flow_ID);
                    if(hdrs.telemetry.epoch != cmd.e_epoch) {
                        // Reset counter in the case of a new epoch. The 
                        // counter is set to 0 or 1 depending if the current 
                        // packet observed a high end-to-end delay.
                        e_high_delays.write(cmd.flow_ID,
                                            (bit<32>) cmd.e_high_e2e_delay);
                    } else if(cmd.e_high_e2e_delay == 1) {
                        // Increment by one the counter if we are in the same 
                        // epoch and the current packet observed a high 
                        // end-to-end delay.
                        e_high_delays.write(cmd.flow_ID, cmd.e_high_delays + 1);
                    }

                    // INGRESS PACKETS AND BYTES: Store the last counter values
                    // in cmd.e_ingress_packets,bytes and update the registers
                    // to the newly received values.
                    e_ingress_packets.read(cmd.e_ingress_packets, cmd.flow_ID);
                    e_ingress_packets.write(cmd.flow_ID, 
                                            hdrs.ingress_pckts.ingress_packets);
                    e_ingress_bytes.read(cmd.e_ingress_bytes, cmd.flow_ID);
                    e_ingress_bytes.write(cmd.flow_ID,
                                            hdrs.ingress_bytes.ingress_bytes);

                    // EGRESS PACKETS AND BYTES
                    e_egress_packets.read(cmd.e_egress_packets, cmd.flow_ID);
                    if(hdrs.telemetry.epoch != cmd.e_epoch) {
                        // Reset counters in the case of a new epoch.
                        e_egress_packets.write(cmd.flow_ID, 1);
                    } else {
                        // Increment counters in the case of same epoch.
                        e_egress_packets.write(cmd.flow_ID,
                                                cmd.e_egress_packets + 1);
                    }

                    e_egress_bytes.read(cmd.e_egress_bytes, cmd.flow_ID);
                    if(cmd.is_ingress_node == 1) {
                        cmd.e_egress_bytes_ths = 0;
                    } else {
                        cmd.e_egress_bytes_ths = TELEMETRY_HS;
                    }
                    // cmd.e_egress_bytes_ths = TELEMETRY_HS;
                    if(hdrs.telemetry.epoch != cmd.e_epoch) {
                        // Reset counters in the case of a new epoch.
                        e_egress_bytes.write(cmd.flow_ID,
                                             smd.packet_length
                                             - cmd.e_egress_bytes_ths);
                    } else {
                        // Increment counters in the case of same epoch.
                        e_egress_bytes.write(cmd.flow_ID,
                                             cmd.e_egress_bytes \
                                             + smd.packet_length \
                                             - cmd.e_egress_bytes_ths);
                    }

                    // CONTENTION POINTS
                    // Store the last contention points in
                    // cmd.e_contention_points..
                    e_contention_points.read(cmd.e_contention_points,
                                            cmd.flow_ID);
                    if(hdrs.telemetry.epoch != cmd.e_epoch) {
                        // and update the registers to the newly received ones
                        // in the case of a new epoch.
                        e_contention_points.write(
                            cmd.flow_ID,
                            hdrs.contention_points.contention_points
                        );
                    } else {
                        // and update the register with the newly identified
                        // points.
                        e_contention_points.write(
                            cmd.flow_ID,
                            (cmd.e_contention_points
                            | hdrs.contention_points.contention_points)
                        );
                    }

                    // SUSPICION POINTS
                    // Store the last suspicion points in
                    // cmd.e_suspicion_points..
                    e_suspicion_points.read(cmd.e_suspicion_points,
                                            cmd.flow_ID);
                    if(hdrs.telemetry.epoch != cmd.e_epoch) {
                        // and update the registers to the newly received ones
                        // in the case of a new epoch.
                        e_suspicion_points.write(
                            cmd.flow_ID,
                            hdrs.suspicion_points.suspicion_points
                        );
                    } else {
                        // and update the register with the newly identified
                        // points.
                        e_suspicion_points.write(
                            cmd.flow_ID,
                            (cmd.e_suspicion_points
                            | hdrs.suspicion_points.suspicion_points)
                        );
                    }
                    // END OF UPDATE REGISTERS
                    // =======================

                    // HAS A NEW EPOCH JUST STARTED?
                    if(hdrs.telemetry.epoch
                        != cmd.e_epoch && cmd.e_epoch > 0) {
                        cmd.e_report = 1;

                        // TOO MANY HIGH DELAYS?
                        high_delays_threshold.apply();
                        if(cmd.e_check_high_delays == 1
                            && (cmd.e_high_delays
                                >= cmd.e_high_delays_threshold)) {
                            cmd.e_report = 1;
                        }

                        // LOW BANDWIDTH OR TOO MANY DROPS?
                        bandwidth_thresholds.apply();
                        cmd.e_drops = cmd.e_ingress_packets \
                                    - cmd.e_egress_packets;
                        if(cmd.e_check_bandwidth_and_drops == 1
                                && ((cmd.e_egress_bytes
                                    < cmd.e_bandwidth_threshold)
                                    || cmd.e_drops >= cmd.e_drops_threshold)) {
                            cmd.e_report = 1;
                        }

                        // CONTENTIONS?
                        if(cmd.e_contention_points > 0) {
                            cmd.e_report = 1;
                        }

                        // SUSPICIONS?
                        if(cmd.e_suspicion_points > 0) {
                            cmd.e_report = 1;
                        }

                        // REPORT VIOLATIONS OR PROBLEMS
                        if(cmd.e_report == 1) {
                            // Create report packet by cloning the current
                            // packet.
                            clone3(CloneType.E2E, INTSIGHT_MIRROR_SESSION, {cmd});
                        }
                    }

                    // Remove telmetry fields from the packet.
                    hdrs.ipv4.protocol = hdrs.telemetry.next_header;
                    hdrs.ipv4.total_length = 
                        hdrs.ipv4.total_length - TELEMETRY_HS;
                    hdrs.telemetry.setInvalid();
                    hdrs.path_src.setInvalid();
                    hdrs.path_length.setInvalid();
                    hdrs.path_code.setInvalid();
                    hdrs.contention_points.setInvalid();
                    hdrs.suspicion_points.setInvalid();
                    hdrs.e2e_delay.setInvalid();
                    hdrs.ingress_pckts.setInvalid();
                    hdrs.ingress_bytes.setInvalid();
                    hdrs.bloom_filter.setInvalid();
                    hdrs.loop_detected.setInvalid();
                }
            } else if(smd.instance_type == CLONE_PACKET) {

                 if(cmd.report_type == 0x0){
                    // Create IntSight report header.
                    hdrs.report.setValid();
                    hdrs.report.epoch = cmd.e_epoch;
                    hdrs.report.egress_epoch = cmd.e_egress_epoch;
                    hdrs.report.flow_ID = cmd.flow_ID;
                    hdrs.report.path_src = cmd.e_path_src;
                    hdrs.report.path_length = cmd.e_path_length;
                    hdrs.report.path_code = cmd.e_path_code;
                    hdrs.report.contention_points = cmd.e_contention_points;
                    hdrs.report.suspicion_points = cmd.e_suspicion_points;
                    hdrs.report.path_dst = (bit<16>) cmd.node_ID;
                    hdrs.report.high_delays = cmd.e_high_delays;
                    hdrs.report.drops = cmd.e_drops;
                    hdrs.report.ingress_packets = cmd.e_ingress_packets;
                    hdrs.report.ingress_bytes = cmd.e_ingress_bytes;
                    hdrs.report.egress_packets = cmd.e_egress_packets;
                    hdrs.report.egress_bytes = cmd.e_egress_bytes;

                    // Rewrite IPv4 header to transform packet into a report.
                    hdrs.ipv4.ihl = 5;
                    hdrs.ipv4.dscp = 42;
                    hdrs.ipv4.ecn = 0;
                    hdrs.ipv4.total_length = IPV4_HS + REPORT_HS;
                    hdrs.ipv4.identification = 1;
                    hdrs.ipv4.flags = 0;
                    hdrs.ipv4.fragment_offset = 0;
                    hdrs.ipv4.ttl = 64;
                    hdrs.ipv4.protocol = PROTOCOL_INTSIGHT_REPORT;
                    hdrs.ipv4.header_checksum = 0;  // Will be set on actual egress
                    
                }else{
                    hdrs.loop_report.setValid();
                    hdrs.loop_report.epoch = cmd.e_epoch;
                    hdrs.loop_report.flow_ID = cmd.flow_ID;
                    hdrs.loop_report.path_src = cmd.e_path_src;
                    hdrs.loop_report.path_length = cmd.e_path_length;
                    hdrs.loop_report.path_code = cmd.e_path_code;
                    hdrs.loop_report.node_ID = (bit<8>) cmd.node_ID;
                    hdrs.loop_report.bloom_filter = cmd.e_bloom_filter;

                    // Rewrite IPv4 header to transform packet into a report.
                    hdrs.ipv4.ihl = 5;
                    hdrs.ipv4.dscp = 42;
                    hdrs.ipv4.ecn = 0;
                    hdrs.ipv4.total_length = IPV4_HS + LOOP_REPORT_HS;
                    hdrs.ipv4.identification = 1;
                    hdrs.ipv4.flags = 0;
                    hdrs.ipv4.fragment_offset = 0;
                    hdrs.ipv4.ttl = 64;
                    hdrs.ipv4.protocol = PROTOCOL_LOOP_REPORT;
                    hdrs.ipv4.header_checksum = 0;  // Will be set on actual egress
                }

                node_and_analyzer_IP_addr.apply();
                hdrs.ipv4.src_addr = cmd.e_node_IP_addr;
                hdrs.ipv4.dst_addr = cmd.e_analyzer_IP_addr;

                if(cmd.report_type == 0x0){
                    // Trucate the packet to contain only Ethernet+IPv4+Report.
                    truncate(ETHERNET_HS + IPV4_HS + REPORT_HS);
                }else{
                    // Trucate the packet to contain only Ethernet+IPv4+Report.
                    truncate(ETHERNET_HS + IPV4_HS + LOOP_REPORT_HS);
                }
            }
            // }
        } else {
            mark_to_drop();
            // mark_to_drop(smd);
        }
    }
}

control computeChecksum(inout headers hdrs, inout custom_metadata_t cmd) {
    apply {
        update_checksum(
            hdrs.ipv4.isValid(),
            {
                hdrs.ipv4.version,
                hdrs.ipv4.ihl,
                hdrs.ipv4.dscp,
                hdrs.ipv4.ecn,
                hdrs.ipv4.total_length,
                hdrs.ipv4.identification,
                hdrs.ipv4.flags,
                hdrs.ipv4.fragment_offset,
                hdrs.ipv4.ttl,
                hdrs.ipv4.protocol,
                hdrs.ipv4.src_addr,
                hdrs.ipv4.dst_addr
            },
            hdrs.ipv4.header_checksum, 
            HashAlgorithm.csum16
        );
    }
}

control DeparserImpl(packet_out pkt, in headers hdrs) {
    apply {
        pkt.emit(hdrs.ethernet);
        pkt.emit(hdrs.arp);
        pkt.emit(hdrs.ipv4);
        pkt.emit(hdrs.telemetry);
        pkt.emit(hdrs.path_src);
        pkt.emit(hdrs.path_length);
        pkt.emit(hdrs.path_code);
        pkt.emit(hdrs.contention_points);
        pkt.emit(hdrs.suspicion_points);
        pkt.emit(hdrs.e2e_delay);
        pkt.emit(hdrs.ingress_pckts);
        pkt.emit(hdrs.ingress_bytes);
        pkt.emit(hdrs.bloom_filter);
        pkt.emit(hdrs.report);
        pkt.emit(hdrs.loop_report);
    }
}

V1Switch(
    ParserImpl(),
    verifyChecksum(),
    ingress(),
    egress(),
    computeChecksum(),
    DeparserImpl()
)main;