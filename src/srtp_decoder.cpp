// srtp_decoder.cpp : Defines the entry point for the console application.
//

#include "decoder.h"
#include "base64.h"
#include "pcap.h"
#include <string>
#include <iostream>
#include <cassert>

#include "pcap_reader.h"

#define LINE_LEN 16

bool ParseKeyParams(const std::string& key_params, uint8_t* key, int len) {
	// example key_params: "YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2"

	// Fail if base64 decode fails, or the key is the wrong size.
	std::string key_b64(key_params), key_str;
	if (!Base64::Decode(key_b64, Base64::DO_STRICT,
		&key_str, NULL) ||
		static_cast<int>(key_str.size()) != len) {
		std::cerr << "ERROR: Bad master key encoding, cant unbase64" << std::endl;
		throw std::runtime_error("SRTP fails");
		return false;
	}

	memcpy(key, key_str.c_str(), len);
	return true;
}

int SrtpCryptoSuiteFromName(const std::string& crypto_suite) {
	if (crypto_suite == CS_AES_CM_128_HMAC_SHA1_32)
		return SRTP_AES128_CM_SHA1_32;
	if (crypto_suite == CS_AES_CM_128_HMAC_SHA1_80)
		return SRTP_AES128_CM_SHA1_80;
	return SRTP_INVALID_CRYPTO_SUITE;
}

static void int_to_char(unsigned int i, unsigned char ch[4])
{
	ch[0] = i >> 24;
	ch[1] = (i >> 16) & 0xFF;
	ch[2] = (i >> 8) & 0xFF;
	ch[3] = i & 0xFF;
}

int main(int argc, char* argv[])
{
	std::cout << "SRTP decoder Version 1.00" << std::endl;

	if (argc < 7) {
		std::cerr << "ERROR: Bad arguments:" << std::endl;
		std::cout << "Usage: srtp_decoder[.exe] input_tcpdump_pcap_path output_decoded_payload_path ssrc_rtp_hex_format Base64_master_key sha_Crypto_Suite container[true/false]" << std::endl;
		std::cout << "Examples: "
			<< std::endl << "srtp_decoder ./tests/pcma.pcap ./tests/pcma.paylaod 0xdeadbeef aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz AES_CM_128_HMAC_SHA1_80 false" \
			<< std::endl << "srtp_decoder ./tests/webrtc_opus_p2p.pcap ./tests/output/webrtc_opus_p2p.payload 0x20C23467 FfLxRxclZ/lNM/g5MNSZgmvAUzR/pgSIVyOHUHji AES_CM_128_HMAC_SHA1_80 true" << std::endl;
		return 1;
	}

	global_params params;
	params.ssrc = 0;

	std::string input_path = argv[1];
	std::string output_path = argv[2];
	std::string ssrc_str = argv[3];
	std::string keyBase64 = argv[4];
	std::string sha = argv[5];
	params.ssrc = strtoul(ssrc_str.c_str(), 0, 16);
	bool container = std::string(argv[6]) == std::string("true");

	std::cout << "pcap file: " << input_path << std::endl;
	std::cout << "payload file: " << output_path << std::endl;
	std::cout << "32-bit SSRC identifier: 0x" << std::hex << params.ssrc << std::dec << std::endl;
	std::cout << "AES Base64 crypto key: " << keyBase64 << std::endl;
	std::cout << "crypto-suite: " << sha << std::endl;
	std::cout << "payload packaging: " << (container ? "true" : "false") << std::endl << std::endl;

	try {

		bool succ = read_pcap(input_path, params);
		if (!succ)
			return 1;
		std::cout << "Found " << params.srtp_stream.size() << " RTP packets (ssrc: 0x" << std::hex << params.ssrc << ")" << std::dec << std::endl;


		SrtpSession srtp_decoder;
		srtp_decoder.Init();
		bool ret;
		uint8_t recv_key[SRTP_MASTER_KEY_LEN];
		ret = ParseKeyParams(keyBase64, recv_key, sizeof(recv_key));
		if (ret) {
			ret = srtp_decoder.SetRecv(
				SrtpCryptoSuiteFromName(sha), recv_key,
				sizeof(recv_key));
		}


		std::ofstream payload_file(output_path.c_str(), std::ofstream::out | std::ofstream::binary);

//		std::cout << std::endl << "start decoding filtered SRTP" << std::endl;
		int count = 0;

		for (srtp_packets_t::iterator i = params.srtp_stream.begin(), lim = params.srtp_stream.end(); i != lim; i++)
		{

			int rtp_length = 0;
			unsigned char* srtp_buffer = i->data();
			int length = i->size();
			bool suc = srtp_decoder.UnprotectRtp(srtp_buffer, length, &rtp_length);
			if (!suc)
				std::cerr << "can't decrypt packet" << std::endl;
			common_rtp_hdr_t *hdr = (common_rtp_hdr_t *)srtp_buffer;
			int rtp_header_size = sizeof(common_rtp_hdr_t);
			unsigned char* payload = srtp_buffer + rtp_header_size;
			if (hdr->x) // has extension 
			{
				// If the X bit in the RTP header is one, a variable - length header
				// extension MUST be appended to the RTP header, following the CSRC list if present.
				common_rtp_hdr_ex_t* hdr_ex = (common_rtp_hdr_ex_t *)payload;
				payload += sizeof(common_rtp_hdr_ex_t);

				// calculate extensions RFC5285
				int number_of_extensions = htons(hdr_ex->extension_len);
				for (int n = 0; n < number_of_extensions; n++)
				{
					rtp_hdr_ex5285_t* h5285 = (rtp_hdr_ex5285_t*)payload;
					payload += sizeof(rtp_hdr_ex5285_t) + h5285->extension_len;
				}

				// There are as many
				// extension elements as fit into the length as indicated in the RTP
				// header extension length.Since this length is signaled in full 32 -
				// bit words, padding bytes are used to pad to a 32 - bit boundary.
				int extension_size = payload - srtp_buffer;;
				int padding = extension_size % 4;
				payload += padding;
			}

			rtp_header_size = payload - srtp_buffer;
			// std::cout << std::endl << "Chunk size: " << rtp_length - rtp_header_size << " payload: " << (int)hdr->pt;
			count++;
			size_t frame_size = rtp_length - rtp_header_size;


				if (container)
				{
					unsigned char sz[4];
					int_to_char(frame_size, sz);
					payload_file.write(reinterpret_cast<char*>(&sz[0]), 4);
					int_to_char(0, sz);
					payload_file.write(reinterpret_cast<char*>(&sz[0]), 4);
				}
				// The array may contain null characters, which are also copied without stopping the copying process.
				payload_file.write(reinterpret_cast<char*>(payload), frame_size);

//			std::cout << count << " frame size: " << frame_size << std::endl;
		}
		payload_file.close();
		std::cout << "Wrote " << count << " payload chunks " << std::endl;
		srtp_decoder.Terminate();

	}
	catch (std::exception const& err) {
		std::cerr << "Terminate: " << err.what() << std::endl;
		return 1;
	} 

	return 0;
}

