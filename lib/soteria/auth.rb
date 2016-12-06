require 'savon'
module Soteria

  class Auth

    def initialize(cert, key, pw, log)

      @client = Savon.client(wsdl: 'lib/wsdl/vip_auth.wsdl',
                             env_namespace: :soapenv,
                             endpoint: 'https://services-auth.vip.symantec.com/mgmt/soap',
                             log: log,
                             ssl_version: :TLSv1,
                             ssl_cert_file: cert,
                             ssl_cert_key_file: key,
                             ssl_cert_key_password: pw,
                             namespace_identifier: :vip)

      @prov_client = Savon.client(wsdl: 'lib/wsdl/vip_auth.wsdl',
                                  env_namespace: :soapenv,
                                  endpoint: 'https://services-auth.vip.symantec.com/prov/soap',
                                  log: log,
                                  ssl_version: :TLSv1,
                                  ssl_cert_file: cert,
                                  ssl_cert_key_file: key,
                                  ssl_cert_key_password: pw,
                                  namespace_identifier: :vip)

      @val_client = Savon.client(wsdl: 'lib/wsdl/vip_auth.wsdl',
                                 env_namespace: :soapenv,
                                 endpoint: 'https://services-auth.vip.symantec.com/val/soap',
                                 log: log,
                                 ssl_version: :TLSv1,
                                 ssl_cert_file: cert,
                                 ssl_cert_key_file: key,
                                 ssl_cert_key_password: pw,
                                 namespace_identifier: :vip)
    end


    # Send a temporary password to the token.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @param [Int] pass
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def set_temp_pass(token_id, pass)
      res = @client.call(:set_temporary_password,
                         message: {
                             'vip:TokenId': token_id,
                             'vip:TemporaryPassword': pass
                         },
                         attributes: {
                             'Version': '3.1',
                             'Id': '123'
                         }
      ).body

      get_return_hash(res[:set_temporary_password_response])
    end


    # Use the EnableToken for SMS OTP API to enable a previously disabled SMS OTP credential.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def enable_sms_credentail(token_id)
      res = @client.call(:enable_token,
                         message: {
                             'vip:TokenId': token_id,
                             'vip:TemporaryPassword': pass
                         },
                         attributes: {
                             'Version': '3.1',
                             'Id': '123'
                         }
      ).body

      get_return_hash(res[:enable_token_response])
    end


    # Use the DisableToken for SMS OTP API to disable an SMS OTP credential.
    #
    # @param [String] reason The reason for disabling the token.
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def disable_sms_credentail(reason, token_id)
      res = @client.call(:disable_token,
                         message: {
                             'vip:TokenId': token_id,
                             'vip:TemporaryPassword': pass
                         },
                         attributes: {
                             'Version': '3.1',
                             'Id': '123'
                         }
      ).body

      get_return_hash(res[:enable_token_response])
    end


    # Call when a newly registered SMS OTP credential requires activation
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def activate_token(token_id)
      res = @client.call(:activate_token,
                         message: {
                             'vip:TokenId': token_id
                         },
                         attributes: {
                             'Version': '3.1',
                             'Id': '123'
                         }
      ).body

      get_return_hash(res[:activate_token_response])
    end


    # Use the DeactivateToken for SMS OTP API to deactivate an SMS OTP credential. If the deactivation is successful, the credential is deactivated.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def deactivate_token(token_id)
      res = @client.call(:deactivate_token,
                         message: {
                             'vip:TokenId': token_id
                         },
                         attributes: {
                             'Version': '3.1',
                             'Id': '123'
                         }
      ).body

      get_return_hash(res[:deactivate_token_response])
    end


    # Register a new SMS OTP credential.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def register(token_id)
      res = @prov_client.call(:register,
                              message: {
                                  'vip:TokenId': token_id,
                                  attributes!: {
                                      'vip:TokenId':
                                          {
                                              type: 'SMS'
                                          }
                                  }
                              },
                              attributes: {
                                  'Version': '3.1',
                                  'Id': '123'
                              }
      ).body

      get_return_hash(res[:enable_token_response])
    end


    # Helper function to create the hash to return. All user calls have the same return values.
    #
    # @param [Hash] res
    # @return [Hash] A hash with the appropriate values. Included are: :success - a boolean if the operation was successful,
    def get_return_hash(res)
      response_hash = res[:status]

      {
          success: response_hash[:reason_code] == '0000',
          message: response_hash[:status_message],
          id: res[:@request_id]
      }
    end

  end

end

