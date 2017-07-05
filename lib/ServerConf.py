# -*- coding: utf-8 -*-
import codecs
import logging

from yaml import load

import mills


class ServerConf(object):
    """
    server 配置对象
    """

    def __init__(self, rulefname):
        """

        :param rulefname: 配置文件路径
        """
        self.__rulefd = None
        try:
            self.__rulefd = codecs.open(rulefname, mode='rb', encoding='utf8', errors='ignore')
        except Exception as e:
            logging.error("read %s file failed: %s" % (rulefname, repr(e)))

        dataMap = load(self.__rulefd)
        tcp_stream_handler = dataMap.get("tcp_stream_handler")
        self.bpf_filter = tcp_stream_handler.get("bpf_filter")
        self.dst_port_filter = tcp_stream_handler.get("dst_port_filter")
        self.dst_ip_filter = tcp_stream_handler.get("dst_ip_filter")
        self.pcap_file = tcp_stream_handler.get("pcap_file") if tcp_stream_handler.get("pcap_file_enable",
                                                                                       0) == 1 else None

        if self.pcap_file:
            self.pcap_file = mills.path(self.pcap_file)

        self.device = tcp_stream_handler.get("device") if tcp_stream_handler.get("device_enable",
                                                                                 0) == 1 else None

        self.data_level = tcp_stream_handler.get("data_level", 1)
        self.data_stream_direct = tcp_stream_handler.get("data_stream_direct", 2)
        self.std_output_enable = tcp_stream_handler.get("std_output_enable", 1)

        self.file_tcpsession_path = tcp_stream_handler.get("file_tcpsession_path") if tcp_stream_handler.get(
            "file_output_enable",
            0) == 1 else None

        if self.file_tcpsession_path:
            self.file_tcpsession_path = mills.path(self.file_tcpsession_path)

        self.protocol_parse_conf = tcp_stream_handler.get("protocol_parse_conf")

    def __del__(self):
        if self.__rulefd:
            self.__rulefd.close()
