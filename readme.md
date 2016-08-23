*SRTP decoder decodes WebRTC media streams and writes decoded payload into the file*


## *This tool:*
 * decodes pcap (Packet Capture) format
 * extracts RTP packets
 * filters packets by SSRC
 * decodes secure
 * write payload to output file

RTP can be packed in different way.  
Supports stream: WebRTC, Regular SRTP, Turn Extensions.  

To store opus packets in a file, you need some kind of container format that stores the packet boundaries. I am using https://www.opus-codec.org simple container format.  
Option: container[true/false] - switches on/off this feature.  
  
  
### *Usage:*
 srtp_decoder[.exe] input output ssrc key sha container
 * input - input pcap file path (Not pcapng!!!, just pcap)
 * output - output pcm file path 
 * ssrc - RTP stream identifier https://tools.ietf.org/html/rfc3550#page-59 hex with 0x prefix
 * sha - crypto suite name https://tools.ietf.org/html/rfc4568#page-16
 * container - true/false see feature description above

### *Compiling:*

```bash
git clone https://github.com/ogolosovskiy/srtp_decoder.git
cd srtp_decoder
mkdir build
cd build
cmake ..
make
export PATH=`pwd`:"$PATH"
```

```bash
./win32/srtp_decoder.sln
```

### *Prerequrements linux/mac*
install libsrtp (https://github.com/dozeo/libsrtp I recomend)  
install libpcap  
  
### *Prerequrements windows*
  
setup include/lib path to   
libsrtp  https://github.com/cisco/libsrtp  
winpcap https://www.winpcap.org/devel.htm  
 

### *How to play pcm*  
http://www.audacityteam.org/  
File->Import->Raw data-> A-Law:Little-Endian:1 Channel(Mono):0:100:8000Hz  


### *How to play OPUS*  
https://www.opus-codec.org  
curl  http://downloads.xiph.org/releases/opus/opus-1.1.3.tar.gz -o opus.tar.gz  
tar -xvf ./opus.tar.gz  
cd opus-1.1.3/  
./configure  
make  
use opus_demo for converting OPUS payload to PCM  
 ./opus_demo -d 48000 1 payloadfile pcmfile  
play it by audacity  
File->Import->Raw data-> PCM 16 bit 48000Hz  
  
  
### *SDES/DTLS srtp*  

TO DO How to extract SEDS key/crypto from SDP  
TO DO How to extract DTLS key/crypto from browser logs









