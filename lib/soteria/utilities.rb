module Soteria

class Utilities


  # Generate a request ID for a SOAP call.
  #
  # @param [String] prefix The prefix for the request ID. This should tell the user what the call is.
  # @return [String] A string that is the request ID for a call. The request ID is just used for debugging purposes.
  def self.get_request_id(prefix)
    SecureRandom.uuid.delete('-')
  end


  # Create a Savon client object to make calls.
  #
  # @see Savon::Client
  # @param [String] wsdl The absolute path to, or the URL of the WSDL file for this client.
  # @param [Boolean] should_log
  # @param [String] cert_file The absolute path to the certificate file.
  # @param [String] cert_key The absolute path to the certificate key file.
  # @param [String] cert_key_password The password fo the certificate key file.
  def self.create_client(wsdl, should_log, cert_file, cert_key, cert_key_password)
    Savon.client(wsdl: wsdl,
                 env_namespace: :soapenv,
                 namespace: 'https://schemas.symantec.com/vip/2011/04/vipuserservices',
                 log: should_log,
                 ssl_version: :TLSv1,
                 ssl_cert_file: cert_file,
                 ssl_cert_key_file: cert_key,
                 ssl_cert_key_password: cert_key_password,
                 namespace_identifier: :vip)
  end


  CREDENTIAL_TYPES = {
      standard: 'STANDARD_OTP',
      certificate: 'CERTIFICATE',
      sms: 'SMS_OTP',
      voice: 'VOICE_OTP',
      service: 'SERVICE_OTP'
  }
end
end