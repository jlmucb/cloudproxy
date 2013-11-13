#include "legacy_tao_channel.h"

#include <keyczar/stl_util-inl.h>
#include <glog/logging.h>

// safe integer operations
#include <safe_iop.h>

// minimal amount of code needed from the old CloudProxy implementation to
// bootstrap into a new one
#include <jlmcrypto.h>
#include <cert.h>
#include <keys.h>
#include <logging.h>
#include <policyCert.inc>
#include <validateEvidence.h>

using keyczar::base::ScopedSafeString;

using tao::Attestation;
using tao::SignedStatement;
using tao::Statement;

namespace tao {
LegacyTaoChannel::LegacyTaoChannel(const string &directory,
                                   const string &keys_directory,
                                   const string &domain_name)
    : directory_(directory),
      keys_directory_(keys_directory),
      domain_name_(domain_name),
      tao_host_(new taoHostServices()),
      tao_env_(new taoEnvironment()),
      legacy_policy_cert_(nullptr) {
  // Initialization is performed in the Init method.
}

bool LegacyTaoChannel::Init() {
  CHECK(initAllCrypto()) << "Could not initialize jlmcrypto";

  const char *directory = directory_.c_str();
  const char **parameters = &directory;
  int parameterCount = 1;

  try {
    // init host
    CHECK(tao_host_->HostInit(PLATFORMTYPELINUX, parameterCount, parameters))
        << "Can't init the host";

    // init environment
    CHECK(tao_env_->EnvInit(PLATFORMTYPELINUXAPP, keys_directory_.c_str(),
                            domain_name_.c_str(), directory, tao_host_.get(), 0,
                            NULL)) << "Can't init the environment";

    // set up the legacy policy key
    legacy_policy_cert_.reset(new PrincipalCert());
    CHECK(legacy_policy_cert_->init(const_cast<const char *>(
        reinterpret_cast<char *>(tao_env_->m_policyKey))))
        << "Could not initialize the legacy policy public key";
    CHECK(legacy_policy_cert_->parsePrincipalCertElements())
        << "Could not finish legacy policy public key initialization";
  }
  catch (const char * err) {
    LOG(ERROR) << "Error in initializing the legacy tao: " << err;
    tao_env_->EnvClose();
    tao_host_->HostClose();
    return false;
  }

  // Make sure that our measurement is valid. Otherwise, fail.
  CHECK(tao_env_->m_myMeasurementValid)
      << "The Tao initialized correctly, but this program had an invalid "
         "measurement, so no operations can be performed";

  return true;
}

bool LegacyTaoChannel::GetRandomBytes(size_t size, string *bytes) const {
  if (!bytes) {
    LOG(ERROR) << "bytes was null";
    return false;
  }

  int val = 0;
  if (!sop_safe_cast(1, int, val, 0, size_t, size)) {
    LOG(ERROR)
        << "The requested byte count does not fit into a signed 32-bit integer";
    return false;
  }

  return tao_env_->GetEntropy(static_cast<int>(size), bytes.data());
}

bool LegacyTaoChannel::Seal(const string &data, string *sealed) const {
  if (!sealed) {
    LOG(ERROR) << "sealed was null";
    return false;
  }

  if (!tao_env_->m_myMeasurementValid) {
    LOG(ERROR) << "Can't seal data, since our measurement is invalid";
    return false;
  }

  // the sealed size is 2 * sizeof(int) + hostedMeasurementSize +
  // dataSize
  int sealed_size =
      2 * sizeof(int) + tao_env_->m_myMeasurementSize + data.size();

  // This is safe, since the 4th argument of Seal is read-only,
  // despite not having a const annotation.
  byte *data_bytes =
      reinterpret_cast<unsigned char *>(const_cast<char *>(data.data()));

  // create a temporary buffer to hold the sealed data
  scoped_array<unsigned char> temp_sealed(sealed_size);

  int data_size = 0;
  size_t orig_data_size = data.size();
  if (!sop_safe_cast(1, int, data_size, 0, size_t, orig_data_size)) {
    LOG(ERROR)
        << "The size of the data does not fit into a signed 32-bit integer";
    return false;
  }
  data_size = static_cast<int>(orig_data_size);

  byte *sealed_bytes = reinterpret_cast<unsigned char *>(sealed->data());
  if (!tao_env_->Seal(tao_env_->m_myMeasurementSize, tao_env_->m_myMeasurement,
                      data_size, data_bytes, &sealed_size, temp_sealed.get())) {
    LOG(ERROR) << "Could not seal the data using the legacy Tao";
    return false;
  }

  sealed->assign(reinterpret_cast<char *>(temp_sealed.get()), sealed_size);
  return true;
}

bool LegacyTaoChannel::Unseal(const string &sealed, string *data) const {
  if (!data) {
    LOG(ERROR) << "data was null";
    return false;
  }

  int data_size = 0;
  size_t orig_data_size = data.size();
  if (!sop_safe_cast(1, int, data_size, 0, size_t, orig_data_size)) {
    LOG(ERROR)
        << "The size of the data does not fit into a signed 32-bit integer";
    return false;
  }

  int sealed_size = static_cast<int>(sealed.size());
  int unsealed_size = 0;
  if (!sop_sub3(&unsealed_size, sealed_size, 2 * sizeof(int),
                tao_env_->m_myMeasurementSize)) {
    LOG(ERROR) << "Could not compute the unsealed size due to integer overflow";
    return false;
  }

  // TODO(tmroeder): Make this a scoped safe array that deletes its
  // data in its destructor.
  scoped_array<unsigned char> temp_secret(unsealed_size);

  // As in Seal, these casts are safe because the 4th argument to
  // Unseal is treated as read-only.
  byte *sealed_bytes =
      reinterpret_cast<unsigned char *>(const_cast<char *>(sealed.data()));
  if (!tao_env_->Unseal(tao_env_->m_myMeasurementSize,
                        tao_env_->m_myMeasurement, sealed_size, sealed_bytes,
                        &unsealed_size, temp_secret.get())) {
    LOG(ERROR) << "Could not unseal the data using the legacy Tao";
    return 1;
  }

  data->assign(reinterpret_cast<char *>(temp_secret.get()), unsealed_size);
  memset(temp_secret.get(), 0, unsealed_size);
}

bool LegacyTaoChannel::Attest(const string &data, string *attestation) const {
  if (!attestation) {
    LOG(ERROR) << "attestation was null";
    return false;
  }

  Statement s;
  time_t cur_time;
  time(&cur_time);

  s.set_time(cur_time);
  s.set_data(data);

  // TODO(tmroeder): this hash value needs to be set properly, though
  // I think this is correct for the legacy Tao.
  s.set_hash_alg("SHA256");

  // The hash in this case is the hash that will be assigned by the
  // legacy Tao environment, which is the hash of this very program.
  string my_hash(tao_env_->m_myMeasurement, tao_env_->m_myMeasurementSize);
  s.set_hash(my_hash);

  string serialized_statement;
  if (!s.SerializeToString(&serialized_statement)) {
    LOG(ERROR) << "Could not serialize the statement";
    return false;
  }

  // The signature in this case should be the attestation by the
  // legacy Tao, and the public key is the attest certificate
  byte *attestCertificate = tao_env_->m_ancestorEvidence;
  int size = tao_env_->m_ancestorEvidenceSize;

  string attestCert(attestCertificate, size);
  int attestSize = MaxAttestation;
  scoped_array<byte> attest(new byte[attestSize]);

  int serialized_size = 0;
  size_t orig_serialized_size = serialized_statement.size();
  if (!sop_safe_cast(1, int, serialized_size, 0, size_t,
                     orig_serialized_size)) {
    LOG(ERROR) << "The size of the statement could not be cast to an integer";
    return false;
  }

  serialized_size = static_cast<int>(orig_serialized_size);
  byte *serialized_statement_data = reinterpret_cast<byte *>(
      reinterpret_cast<char *>(serialized_statement.data()));
  // IAH: since Attest only contains the hash, we have to send the
  // data separately in this case.
  if (!tao_env_->Attest(tao_env_->m_myMeasurement,
                        tao_env_->m_myMeasurementSize, serialized_size,
                        serialized_statement_data, &attestSize, attest.get())) {
    LOG(ERROR) << "Could not attest to the data using the legacy Tao";
    return false;
  }

  Attestation a;
  a.set_type(LEGACY);
  a.set_serialized_statement(serialized_statement);
  a.mutable_sig()->assign(attest.get(), attestSize);
  a.set_cert(attestCert);

  if (!a.SerializeToString(attestation)) {
    LOG(ERROR) << "Could not serialize the attestation to a string";
    return false;
  }

  return true;
}

bool LegacyTaoChannel::VerifyAttestation(const string &attestation) const {
  // deserialize the attestation and check it
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse the attestation";
    return false;
  }

  if (a.type() != LEGACY) {
    LOG(ERROR) << "Wrong type of attestation supplied to "
                  "LegacyTao::Attestation. Expected " << LEGACY
               << " but received " << a.type();
    return false;
  }

  taoAttest ta;
  KeyInfo *policy_key = legacy_policy_cert_->getSubjectKeyInfo();
  if (!ta.init(CPXMLATTESTATION, a.signature(), a.cert(), policy_key)) {
    LOG(ERROR) << "Could not initialize the taoAttest object";
    return false;
  }

  if (!ta.verifyAttestation()) {
    LOG(ERROR) << "The legacy Tao attesation does not pass verification";
    return false;
  }

  // Check the time in the Statement to make sure it's not too late.
  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the serialized statement";
    return false;
  }

  time_t cur_time;
  time(&cur_time);

  time_t past_time = a.time();
  if (cur_time - past_time > AttestationTimeout) {
    LOG(ERROR) << "The attestation was too old";
    return false;
  }

  return true;
}

bool LegacyTaoChannel::ExtractData(const string &attestation, string *data) const {
  // deserialize the attestation and check it
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse the attestation";
    return false;
  }

  if (a.type() != LEGACY) {
    LOG(ERROR) << "Wrong type of attestation supplied to "
                  "LegacyTao::Attestation. Expected " << LEGACY
               << " but received " << a.type();
    return false;
  }

  taoAttest ta;
  KeyInfo *policy_key = legacy_policy_cert_->getSubjectKeyInfo();
  if (!ta.init(CPXMLATTESTATION, a.signature(), a.cert(), policy_key)) {
    LOG(ERROR) << "Could not initialize the taoAttest object";
    return false;
  }

  // TODO(tmroeder): is this right?
  char *value = ta.quoteValue();
  data->assign(value, strlen(value) + 1);
  free(value);
  return true;
}
}  // namespace tao
