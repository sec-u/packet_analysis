# 功能

* 读取pcap包，打印详细的icmp/tcp/udp协议

* 读取pcap包或网络接口，打印详细的tcp会话数据，目前支持mysql/pgsql/smtp/ftp/ssh/redis/mongodb解析



# 安装依赖包

 `pip install -r requirements.txt`


* [pynids](https://github.com/MITRECND/pynids.git)

   * mac

   `brew install libnids`

   * linux

   `sudo apt-get install libnet1-dev libpcap-dev`

   `git clone https://github.com/MITRECND/pynids.git`

   `cd pynids`

   `sudo python setup.py build`

   `sudo python setup.py install`

* [dpkt](http://dpkt.readthedocs.io/en/latest/index.html)

   `pip install dpkt`

   或者

   `git clone https://github.com/kbandla/dpkt.git`


# 使用
* 读取pcap包，打印详细的icmp/tcp/udp协议

    `python print_pcap.py --help`

    `python print_pcap.py --pcapfile=data/pcap_pub/http_gzip.pcap  --assetport=80`




* 读取pcap包或网络接口，打印详细的tcp会话数据

   第一步:指定配置
   [server.yaml](etc/server.yaml)


   第二步:
   `python print_tcp_session.py`



# Bugs
## libnids
1. 不支持ipv6格式的数据包
2. 当server.yaml中配置为重组双向流量时
`data_stream_direct: 2` ，
只在tcp flag为RST或FIN时才会打印数据

   



