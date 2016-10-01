namespace tao {
using std::string;

/// A class that sends Tao requests and responses over a channel between Tao
/// hosts and Tao hosted programs.
class TaoRPC2 {
 public:
  /// Construct a TaoRPC2.
  /// @param channel The channel over which to send and receive messages.
  /// Ownership is taken.
  explicit TaoRPC2(MessageChannel *channel) : channel_(channel) {}

  virtual void Close() { channel_->Close(); }

  virtual bool SerializeToString(string *params) const;

  static TaoRPC2 *DeserializeFromString(const string &params);

  /// Tao implementation.
  /// @{
  virtual bool GetTaoName(string *name);
  virtual bool ExtendTaoName(const string &subprin);
  virtual bool GetRandomBytes(size_t size, string *bytes);
  virtual bool GetSharedSecret(size_t size, const string &policy,
                               string *bytes);
  virtual bool Attest(const string &message, string *attestation);
  virtual bool Seal(const string &data, const string &policy, string *sealed);
  virtual bool Unseal(const string &sealed, string *data, string *policy);

  virtual bool InitCounter(const string& label, int64_t& c);
  virtual bool GetCounter(const string &label, int64_t* c);
  virtual bool RollbackProtectedSeal(const string& label, const string &data, const string &policy, string *sealed);
  virtual bool RollbackProtectedUnseal(const string &sealed, string *data, string *policy);

  virtual string GetRecentErrorMessage() const { return failure_msg_; }
  virtual string ResetRecentErrorMessage() {
    string msg = failure_msg_;
    failure_msg_ = "";
    return msg;
  }
  /// @}

 protected:
  /// The channel over which to send and receive messages.
  unique_ptr<MessageChannel> channel_;

  /// Most recent RPC2 failure message, if any.
  string failure_msg_;

  /// Most recent RPC2 sequence number.
  unsigned int last_seq_;

 private:
  /// Do an RPC2 request/response interaction with the host Tao.
  /// @param op The operation.
  /// @param req The request to send.
  /// @param[out] data The returned data, if not nullptr.
  /// @param[out] policy The returned policy, if not nullptr.
  bool Request(const string &op, const TaoRPCRequest &req, string *data,
               string *policy, int64_t* counter);

  DISALLOW_COPY_AND_ASSIGN(TaoRPC2);
};
}  // namespace tao


namespace tao {

bool TaoRPC2::GetTaoName(string *name) {
  TaoRPCRequest rpc;
  return Request("Tao.GetTaoName", rpc, name, nullptr /* policy */, nullptr);
}

bool TaoRPC2::ExtendTaoName(const string &subprin) {
  TaoRPCRequest rpc;
  rpc.set_data(subprin);
  return Request("Tao.ExtendTaoName", rpc, nullptr /* data */,
                 nullptr /* policy */, nullptr);
}

bool TaoRPC2::GetRandomBytes(size_t size, string *bytes) {
  TaoRPCRequest rpc;
  rpc.set_size(size);
  return Request("Tao.GetRandomBytes", rpc, bytes, nullptr /* policy */, nullptr);
}

bool TaoRPC2::GetSharedSecret(size_t size, const string &policy, string *bytes) {
  TaoRPCRequest rpc;
  rpc.set_size(size);
  rpc.set_policy(policy);
  return Request("Tao.GetSharedSecret", rpc, bytes, nullptr /* policy */, nullptr);
}

bool TaoRPC2::Attest(const string &message, string *attestation) {
  TaoRPCRequest rpc;
  rpc.set_data(message);
  return Request("Tao.Attest", rpc, attestation, nullptr /* policy */, nullptr);
}

bool TaoRPC2::Seal(const string &data, const string &policy, string *sealed) {
  TaoRPCRequest rpc;
  rpc.set_data(data);
  rpc.set_policy(policy);
  return Request("Tao.Seal", rpc, sealed, nullptr /* policy */, nullptr);
}

bool TaoRPC2::Unseal(const string &sealed, string *data, string *policy) {
  TaoRPCRequest rpc;
  rpc.set_data(sealed);
  return Request("Tao.Unseal", rpc, data, policy, nullptr);
}

bool TaoRPC2::InitCounter(const string& label, int64_t& c) {
  printf("***InitCounter in tao_rpc\n");
return false;
  TaoRPCRequest rpc;
  rpc.set_label(label);
  rpc.set_counter(c);
  return Request("Tao.InitCounter", rpc, nullptr, nullptr, nullptr);
}

bool TaoRPC2::GetCounter(const string& label, int64_t* c) {
  printf("***GetCounter in tao_rpc\n");
  TaoRPCRequest rpc;
  rpc.set_label(label);
  return Request("Tao.GetCounter", rpc, nullptr, nullptr, c);
}

bool TaoRPC2::RollbackProtectedSeal(const string& label, const string &data, const string &policy, string *sealed) {
  printf("***RollbackProtectedSeal in tao_rpc\n");
  TaoRPCRequest rpc;
  rpc.set_policy(policy);
  rpc.set_data(data);
  return Request("Tao.RollbackProtectedSeal", rpc, sealed, nullptr, nullptr);
}

bool TaoRPC2::RollbackProtectedUnseal(const string &sealed, string *data, string *policy) {
  printf("***RollbackProtectedUnseal in tao_rpc\n");
  TaoRPCRequest rpc;
  rpc.set_data(sealed);
  return Request("Tao.RollbackProtectedUnseal", rpc, data, policy, nullptr);
}

bool TaoRPC2::Request(const string &op, const TaoRPCRequest &req, string *data,
                     string *policy, int64_t* counter) {
  ProtoRPCRequestHeader reqHdr;
  ProtoRPCResponseHeader respHdr;
  reqHdr.set_op(op);
  reqHdr.set_seq(++last_seq_);
  TaoRPCResponse resp;
  bool eof;
  if (!channel_->SendMessage(reqHdr)) {
    failure_msg_ = "Channel send header failed";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (!channel_->SendMessage(req)) {
    failure_msg_ = "Channel send failed";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (!channel_->ReceiveMessage(&respHdr, &eof)) {
    failure_msg_ = "Channel receive header failed";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (eof) {
    failure_msg_ = "Channel is closed";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (respHdr.has_error()) {
    failure_msg_ = respHdr.error();
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    string discard;
    channel_->ReceiveString(&discard, &eof);
    return false;
  }
  if (!channel_->ReceiveMessage(&resp, &eof)) {
    failure_msg_ = "Channel receive failed";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (eof) {
    failure_msg_ = "Channel is closed";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (respHdr.op() != op) {
    failure_msg_ = "Unexpected operation in response";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (respHdr.seq() != reqHdr.seq()) {
    failure_msg_ = "Unexpected sequence number in response";
    LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
    return false;
  }
  if (data != nullptr) {
    if (!resp.has_data()) {
      failure_msg_ = "Malformed response (missing data)";
      LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
      return false;
    }
    data->assign(resp.data());
  }
  if (policy != nullptr) {
    if (!resp.has_policy()) {
      failure_msg_ = "Malformed response (missing policy)";
      LOG(ERROR) << "RPC2 to Tao host failed: " << failure_msg_;
      return false;
    }
    policy->assign(resp.policy());
  }
  return true;
}

bool TaoRPC2::SerializeToString(string *params) const {
  string channel_params;
  if (!channel_->SerializeToString(&channel_params)) {
    LOG(ERROR) << "Could not serialize TaoRPC2";
    return false;
  }
  params->assign("tao::TaoRPC2+" + channel_params);
  return true;
}

TaoRPC2 *TaoRPC2::DeserializeFromString(const string &params) {
  stringstream in(params);
  skip(in, "tao::TaoRPC2+");
  if (!in) return nullptr;  // not for us
  string channel_params;
  getline(in, channel_params, '\0');
  // Try each known channel type.
  MessageChannel *channel;
  channel = FDMessageChannel::DeserializeFromString(channel_params);
  if (channel != nullptr) return new TaoRPC2(channel);
  LOG(ERROR) << "Unknown channel serialized for TaoRPC2";
  return nullptr;
}

}  // namespace tao
