
#include "decoder.h"
#include <iostream>

#define SRTP_MASTER_KEY_LEN 30

const int SRTP_MASTER_KEY_BASE64_LEN = SRTP_MASTER_KEY_LEN * 4 / 3;
const int SRTP_MASTER_KEY_KEY_LEN = 16;
int SRTP_MASTER_KEY_SALT_LEN = 14;

	SrtpSession::SrtpSession()
		: session_(NULL)
		, inited_(false)
	{
	}

	SrtpSession::~SrtpSession() {
		if (session_) {
			srtp_dealloc(session_);
		}
	}

	bool SrtpSession::SetSend(int cs, const uint8_t* key, int len) {
		return SetKey(ssrc_any_outbound, cs, key, len);
	}

	bool SrtpSession::SetRecv(int cs, const uint8_t* key, int len) {
		return SetKey(ssrc_any_inbound, cs, key, len);
	}

	bool SrtpSession::UnprotectRtp(void* p, int in_len, int* out_len) {
		if (!session_) {
		  std::cerr << "Failed to unprotect SRTP packet: no SRTP Session";
			return false;
		}

		*out_len = in_len;
		int err = srtp_unprotect(session_, p, out_len);
		if (err != 0) {
		  std::cerr << "Failed to unprotect SRTP packet, err=" << err;
			return false;
		}
		return true;
	}

	bool SrtpSession::SetKey(int type, int cs, const uint8_t* key, int len) {
		if (session_) {
			std::cerr << "Failed to create SRTP session: " << "SRTP session already created";
			return false;
		}

		if (!Init()) {
			return false;
		}

		srtp_policy_t policy;
		memset(&policy, 0, sizeof(policy));

		if (cs == SRTP_AES128_CM_SHA1_80) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
		}
		else if (cs == SRTP_AES128_CM_SHA1_32) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy.rtp);   // rtp is 32,
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);  // rtcp still 80
		}
		else {
	//		LOG(LS_WARNING) << "Failed to create SRTP session: unsupported"	<< " cipher_suite " << cs;
			return false;
		}

		if (!key || len != SRTP_MASTER_KEY_LEN) {
//			LOG(LS_WARNING) << "Failed to create SRTP session: invalid key";
			return false;
		}

		policy.ssrc.type = static_cast<srtp_ssrc_type_t>(type);
		policy.ssrc.value = 0;
		policy.key = const_cast<uint8_t*>(key);
		// TODO(astor) parse window size from WSH session-param
		policy.window_size = 1024;
		policy.allow_repeat_tx = 1;
		// If external authentication option is enabled, supply custom auth module
		// id EXTERNAL_HMAC_SHA1 in the policy structure.
		// We want to set this option only for rtp packets.
		// By default policy structure is initialized to HMAC_SHA1.
		policy.next = NULL;

		int err = srtp_create(&session_, &policy);
		if (err != srtp_err_status_ok) {
			session_ = NULL;
//			LOG(LS_ERROR) << "Failed to create SRTP session, err=" << err;
			return false;
		}

		rtp_auth_tag_len_ = policy.rtp.auth_tag_len;
		rtcp_auth_tag_len_ = policy.rtcp.auth_tag_len;
		return true;
	}

	bool SrtpSession::Init() 
	{
		if (!inited_) {
			int err;
			err = srtp_init();
			if (err != srtp_err_status_ok) {
//				LOG(LS_ERROR) << "Failed to init SRTP, err=" << err;
				return false;
			}

/*			err = srtp_install_event_handler(&SrtpSession::HandleEventT);
			if (err != err_status_ok) {
				LOG(LS_ERROR) << "Failed to install SRTP event handler, err=" << err;
				return false;
			}
			*/
			inited_ = true;
		}

		return true;
	}

	void SrtpSession::Terminate() {
		if (inited_) {
			int err = srtp_shutdown();
			if (err) {
			  std::cerr << "srtp_shutdown failed. err=" << err;
				return;
			}
			inited_ = false;
		}
	}

	/*
	void SrtpSession::HandleEvent(const srtp_event_data_t* ev) {
		switch (ev->event) {
		case event_ssrc_collision:
			LOG(LS_INFO) << "SRTP event: SSRC collision";
			break;
		case event_key_soft_limit:
			LOG(LS_INFO) << "SRTP event: reached soft key usage limit";
			break;
		case event_key_hard_limit:
			LOG(LS_INFO) << "SRTP event: reached hard key usage limit";
			break;
		case event_packet_index_limit:
			LOG(LS_INFO) << "SRTP event: reached hard packet limit (2^48 packets)";
			break;
		default:
			LOG(LS_INFO) << "SRTP event: unknown " << ev->event;
			break;
		}
	}
	*/

