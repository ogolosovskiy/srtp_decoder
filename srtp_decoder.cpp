// srtp_decoder.cpp : Defines the entry point for the console application.
//

#include "decoder.h"
#include "base64.h"
#include "pcap.h"
#include <cassert>

#include "pcap_reader.h"

#define LINE_LEN 16

srtp_packets_t srtp_stream(new std::list<srtp_packet_t>());
long ssrc = 0;

bool ParseKeyParams(const std::string& key_params, uint8_t* key, int len) {
	// example key_params: "YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2"

	// Fail if base64 decode fails, or the key is the wrong size.
	std::string key_b64(key_params), key_str;
	if (!Base64::Decode(key_b64, Base64::DO_STRICT,
		&key_str, NULL) ||
		static_cast<int>(key_str.size()) != len) {
		std::cerr << "Bad master key encoding, cant unbase64" << std::endl;
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


int main(int argc, char* argv[])
{

	if (argc < 6) {
		std::cerr << "Usage: srtp_decoder[.exe] input_tcpdump_pcap_path output_decoded_payload_path ssrc_rtp_hex_format Base64_master_key sha_Crypto_Suite" << std::endl;
		std::cerr << "Example: srtp_decoder.exe D:\\temp\\pcaps\\marseillaise-srtp.pcap D:\\temp\\output.alw 0xdeadbeef aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz AES_CM_128_HMAC_SHA1_80" << std::endl;
		return 1;
	}

	std::string input_path = argv[1];
	std::string output_path = argv[2];
	std::string ssrc_str = argv[3];
	std::string keyBase64 = argv[4];
	std::string sha = argv[5];
	ssrc = (long) std::stoll(ssrc_str, 0, 16);

	std::cout << "tcpdump pcap path: " << input_path << std::endl;
	std::cout << "output RTP payload path: " << output_path << std::endl;
	std::cout << "32-bit SSRC identifier carried: 0x" << std::hex << ssrc << std::dec << std::endl;
	std::cout << "AES Base64 crypto key: " << keyBase64 << std::endl;
	std::cout << "Crypto-Suite: " << sha << std::endl;

	std::cout << std::endl << "Start read pcap" << std::endl;
	bool succ = read_pcap(input_path);
	if (!succ)
		return 1;
	std::cout << "Found RTP packets: " << srtp_stream->size() << std::endl;


	std::cout << std::endl << "Initialize CRYPTO" << std::endl;
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
	std::cout << std::endl << "CRYPTO ready" << std::endl;


	std::ofstream r_file(output_path, std::ofstream::binary);

	std::cout << std::endl << "Start DECODE" << std::endl;
	int count = 0;
	for (auto i = srtp_stream->begin(), lim = srtp_stream->end(); i != lim; i++)
	{

		int rtp_length = 0;
		char* srtp_buffer = i->data();
		int length = i->size();
		bool suc = srtp_decoder.UnprotectRtp(srtp_buffer, length, &rtp_length);
		if(!suc)
		  std::cerr << "can't decrypt packet" << std::endl;
		srtp_hdr_t *hdr = (srtp_hdr_t *)srtp_buffer;
		int rtp_header_size = sizeof(srtp_hdr_t);
		char* payload = srtp_buffer + rtp_header_size;
		if (hdr->x) // has extension 
		{
			// If the X bit in the RTP header is one, a variable - length header
			// extension MUST be appended to the RTP header, following the CSRC list if present.
			_rtp_hdr_ex_t* hdr_ex = (_rtp_hdr_ex_t *)payload;
			payload			+= sizeof(_rtp_hdr_ex_t);

			// calculate extensions RFC5285
			int number_of_extensions = htons(hdr_ex->extension_len);
			for (int n = 0; n < number_of_extensions; n++)
			{
				rtp_hdr_ex5285_t* h5285 = (rtp_hdr_ex5285_t*)payload;
				payload			+= sizeof(rtp_hdr_ex5285_t) + h5285->extension_len;
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
		r_file.write(payload, rtp_length - rtp_header_size);
	}
	r_file.close();
	std::cout << std::endl << "End DECODE, write " << count << " payload chunks " << std::endl;


	srtp_decoder.Terminate();
	return 0;
}

