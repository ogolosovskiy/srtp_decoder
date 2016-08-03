

How to compile linux/osx
install libsrtp (https://github.com/dozeo/libsrtp I recomend)
install libpcap
mkdir build
cd build
cmake ..
make
enjoy !


How to compile windows version:  
open srtp_decoder.sln   
setup include/lib path to   
libsrtp  https://github.com/cisco/libsrtp  
winpcap https://www.winpcap.org/devel.htm  


to play pcm  
http://www.audacityteam.org/  
File->Import->Raw data-> A-Law:Little-Endian:1 Channel(Mono):0:100:8000Hz  

Linux:  
  
sudo apt-get install  libsrtp-dev
