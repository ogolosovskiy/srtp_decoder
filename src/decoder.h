
#include <list>
#include <string.h>
#include <algorithm>
#include <fstream> 
#ifdef WIN32
#include "srtp.h"
#else
#include "srtp/srtp.h"
#endif
#include "err.h"


// Constants for SRTP profiles.
const int SRTP_INVALID_CRYPTO_SUITE = 0;
const int SRTP_AES128_CM_SHA1_80 = 0x0001;
const int SRTP_AES128_CM_SHA1_32 = 0x0002;

const char CS_AES_CM_128_HMAC_SHA1_80[] = "AES_CM_128_HMAC_SHA1_80";
const char CS_AES_CM_128_HMAC_SHA1_32[] = "AES_CM_128_HMAC_SHA1_32";

class SrtpSession {
public:
	SrtpSession();
	~SrtpSession();

	// Configures the session for sending data using the specified
	// cipher-suite and key. Receiving must be done by a separate session.
	bool SetSend(int cs, const uint8_t* key, int len);
	// Configures the session for receiving data using the specified
	// cipher-suite and key. Sending must be done by a separate session.
	bool SetRecv(int cs, const uint8_t* key, int len);

	// Encrypts/signs an individual RTP/RTCP packet, in-place.
	// If an HMAC is used, this will increase the packet size.
	// Overloaded version, outputs packet index.
	bool ProtectRtp(void* data,
		int in_len,
		int max_len,
		int* out_len,
		int64_t* index);
	// Decrypts/verifies an invidiual RTP/RTCP packet.
	// If an HMAC is used, this will decrease the packet size.
	bool UnprotectRtp(void* data, int in_len, int* out_len);

	bool Init();
	void Terminate();

private:
	bool SetKey(int type, int cs, const uint8_t* key, int len);
	// Returns send stream current packet index from srtp db.
	bool GetSendStreamPacketIndex(void* data, int in_len, int64_t* index);

	void HandleEvent(const srtp_event_data_t* ev);

	srtp_ctx_t* session_;
	int rtp_auth_tag_len_;
	int rtcp_auth_tag_len_;
	bool inited_;
	int last_send_seq_num_;
};
