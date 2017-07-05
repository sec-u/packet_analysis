import logging

from lib.ServerConf import ServerConf
from stream_handler.StreamHandler import StreamHandler


def main():
    """

    :return:
    """
    co = ServerConf(mills.path("etc/server.yaml"))

    sho = StreamHandler(pcap_file=co.pcap_file,
                        device=co.device,
                        bpf_filter=co.bpf_filter,
                        dst_port_filter=co.dst_port_filter,
                        dst_ip_filter=co.dst_ip_filter,
                        data_level=co.data_level,
                        data_stream_direct=co.data_stream_direct,
                        std_output_enable=co.std_output_enable,
                        file_tcpsession_path=co.file_tcpsession_path,
                        protocol_parse_conf=co.protocol_parse_conf)
    sho.run()


if __name__ == "__main__":
    """
    """
    import lib.mills as mills
    import lib.logger as logger

    logger.generate_special_logger(level=logging.INFO,
                                   logtype="tcpsession",
                                   curdir=mills.path("./log"))
    main()
