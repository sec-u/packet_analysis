# -*- coding: utf-8 -*-
import codecs
import logging
import nids
import os

import lib.mills as mills
from protocol_parse.ftpauth import FTPAuth
from protocol_parse.mysqlauth import MySQLAuth
from protocol_parse.smtpauth import SMTPAuth
from protocol_parse.sshauth import SSHAuth


class StreamHandler(object):
    """

    """
    __END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

    def __init__(self,
                 pcap_file=None,
                 device=None,
                 bpf_filter="tcp",
                 dst_port_filter=None,
                 dst_ip_filter=None,
                 data_level=1,
                 data_stream_direct=2,
                 std_output_enable=1,
                 file_tcpsession_path=None,
                 protocol_parse_conf=None):
        """

        :param pcap_file:
        :param device:
        :param bpf_filter:
        :param dst_port_filter:
        :param dst_ip_filter:
        :param data_level:
        :param data_stream_direct:
        :param is_human_print:
        :param file_output_file:
        """
        self.dst_port_filter = dst_port_filter
        self.dst_ip_filter = dst_ip_filter
        self.device = device
        self.pcap_file = pcap_file

        if pcap_file:
            nids.param("filename", pcap_file)
        elif device:
            nids.param("device", device)

        if bpf_filter:
            nids.param("pcap_filter", bpf_filter)  ## bpf restrict to TCP only, note

        self.data_level = data_level
        self.data_stream_direct = data_stream_direct
        self.std_output_enable = std_output_enable
        self.file_tcpsession_path = file_tcpsession_path
        self.protocol_parse_conf = protocol_parse_conf

        nids.param("scan_num_hosts", 0)  # disable portscan detection

        nids.chksum_ctl([('0.0.0.0/0', False)])  # disable checksumming

        nids.param("pcap_timeout", 64)
        nids.param("multiproc", 1)
        nids.param("tcp_workarounds", 1)

        self.file_hd_tcpsession = None
        self.file_hd_tcpsession_parse = None

        if self.file_tcpsession_path:
            self.file_hd_tcpsession = codecs.open(self.file_tcpsession_path,
                                                  mode='wb',
                                                  encoding='utf-8',
                                                  errors='ignore')
            if self.data_stream_direct == 2:
                file_tcpsession_path_parse = "%s_parse" % self.file_tcpsession_path

                self.file_hd_tcpsession_parse = codecs.open(file_tcpsession_path_parse,
                                                            mode='wb',
                                                            encoding='utf-8',
                                                            errors='ignore')

    def __del__(self):
        if self.file_hd_tcpsession:
            self.file_hd_tcpsession.close()
        if self.file_hd_tcpsession_parse:
            self.file_hd_tcpsession_parse.close()

    def run(self):
        """

        :return:
        """
        nids.init()

        nids.register_tcp(self.__handleTCPStream)

        # Loop forever (network device), or until EOF (pcap file)
        # Note that an exception in the callback will break the loop!
        try:
            nids.run()
        except nids.error as e:
            logging.error("[NIDS_RUN_Error]: %r" % e)
        except (KeyboardInterrupt, SystemExit) as e:
            logging.error("[System_Exit]: %r" % e)
        except Exception as e:
            logging.error("[NIDS RUN Exception]: %r" % e)

    def __handleTCPStream(self, tcp):
        """

        :param tcp:
        :return:
        """
        global ts_start, ts_end
        ((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
        if self.dst_port_filter and dst_port not in self.dst_port_filter:
            return
        if self.dst_ip_filter and dst_ip not in self.dst_ip_filter:
            return

        if tcp.nids_state == nids.NIDS_JUST_EST:
            if self.device:
                ts_start = mills.getCurrenttimestamp()
            else:
                ts_start = nids.get_pkt_ts()
            tcp.client.collect = 1
            tcp.server.collect = 1
        elif tcp.nids_state == nids.NIDS_DATA:
            if self.device:
                ts_end = mills.getCurrenttimestamp()
            else:
                ts_end = nids.get_pkt_ts()
            # keep all of the stream's new data
            tcp.discard(0)
            data_c2s = tcp.server.data[tcp.server.count - tcp.server.count_new:tcp.server.count]
            data_s2c = tcp.client.data[tcp.client.count - tcp.client.count_new:tcp.client.count]
            result = (ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, data_c2s, data_s2c)
            if self.data_stream_direct == 1:
                self.__outputTCP(result, direct=self.data_stream_direct, level=self.data_level)


        elif tcp.nids_state in StreamHandler.__END_STATES:
            if self.device:
                ts_end = mills.getCurrenttimestamp()
            else:
                ts_end = nids.get_pkt_ts()
            data_c2s_session = tcp.server.data[:tcp.server.count]
            data_s2c_session = tcp.client.data[:tcp.client.count]
            result = (ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, data_c2s_session, data_s2c_session)
            if self.data_stream_direct == 2:
                self.__outputTCP(result, direct=self.data_stream_direct, level=self.data_level)

    def __outputTCP(self, tcp_stream_data, direct=2, level=2):
        """

        :param tcp_stream_data:
        :param direct:
        :param level:
        :return:
        """
        if self.std_output_enable:
            self.__human_print(tcp_stream_data, direct=direct, level=level)
        if self.file_hd_tcpsession:
            self.__output_file(tcp_stream_data)

        if self.file_hd_tcpsession_parse:
            protocol = self.which_protocol_parse(tcp_stream_data)
            if protocol == "smtp":
                self.__parse_smtp_data(tcp_stream_data)
            elif protocol == "ftp":
                self.__parse_ftp_data(tcp_stream_data)
            elif protocol == "mysql":
                self.__parse_mysql_data(tcp_stream_data)
            elif protocol == "ssh":
                self.__parse_ssh_data(tcp_stream_data)

    def __parse_smtp_data(self, tcp_stream_data):
        """
        parse_smtp
        :param tcp_stream_data:
        :return:
        """
        sa = SMTPAuth(tcp_stream_data)
        data_yield = sa.parse_data()
        for d in data_yield:
            self.file_hd_tcpsession_parse.write("%r%s" % (d, os.linesep))

    def __parse_ftp_data(self, tcp_stream_data):
        """
        parse_ftp
        :param tcp_stream_data:
        :return:
        """
        fa = FTPAuth(tcp_stream_data)
        data_yield = fa.parse_data()
        for d in data_yield:
            self.file_hd_tcpsession_parse.write("%r%s" % (d, os.linesep))

    def __parse_mysql_data(self, tcp_stream_data):
        """
        parse_mysql
        :param tcp_stream_data:
        :return:
        """
        ms = MySQLAuth(tcp_stream_data)
        data_yield = ms.parse_data(sep="\x00")
        for d in data_yield:
            self.file_hd_tcpsession_parse.write("%r%s" % (d, os.linesep))

    def __parse_ssh_data(self, tcp_stream_data):
        """

        :param tcp_stream_data:
        :return:
        """
        ssha = SSHAuth(tcp_stream_data)
        data_yield = ssha.parse_data(sep="\x00")
        for d in data_yield:
            self.file_hd_tcpsession_parse.write("%r%s" % (d, os.linesep))

    def __output_file(self, tcp_stream_data):
        """

        :param tcp_stream_data:
        :return:
        """
        # if tcp_stream_data contains unprintable char, ugly output to file
        self.file_hd_tcpsession.write("%r%s" % (tcp_stream_data, os.linesep))

    def which_protocol_parse(self, tcp_stream_data):
        """

        :param tcp_stream_data:
        :return:
        """
        (_, _, _, _, _, dst_port, _, _) = tcp_stream_data
        if self.protocol_parse_conf:
            for protocol, ports in self.protocol_parse_conf.items():
                if dst_port in ports:
                    return protocol

    def __human_print(self, tcp_stream_data, direct=2, level=2):
        """

        :param tcp_stream_data:
        :param direct:
        :param level:
        :return:
        """
        (ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, data_c2s, data_s2c) = tcp_stream_data
        if direct == 2:
            print "\n ********************[DATA Bi-Direct]***************************************"
            print "[addr]: %s:%s %s:%s" % (src_ip, src_port, dst_ip, dst_port)
            print "[ts_start]: %s %s" % (ts_start, mills.timestamp2datetime(ts_start))
            print "[ts_end]: %s %s" % (ts_end, mills.timestamp2datetime(ts_end))
            print "[Data_Client_To_Server]: \n%s" % data_c2s
            if level > 1:
                print mills.str2hex2(data_c2s)
            print "[Data_Server_To_Client]: \n%s" % data_s2c
            if level > 1:
                print mills.str2hex2(data_s2c)
            print "***************************************************************************\n"
            return

        if direct == 1:
            print "\n *******************[DATA One-Direct]****************************************"
            if data_s2c:
                print "{dst_ip}:{dst_port} ---------------------------------> {src_ip}:{src_port} ".format(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
            else:
                print "{src_ip}:{src_port} ---------------------------------> {dst_ip}:{dst_port} ".format(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
            print "[ts_start]: %s %s" % (ts_start, mills.timestamp2datetime(ts_start))
            print "[ts_end]: %s %s" % (ts_end, mills.timestamp2datetime(ts_end))
            print "[Data_Client_To_Server]: \n%s" % data_c2s
            if level > 1:
                print mills.str2hex2(data_c2s)
            print "[Data_Server_To_Client]: \n%s" % data_s2c
            if level > 1:
                print mills.str2hex2(data_s2c)
            print "***************************************************************************\n"
            return
