module Soteria

  class Credential


    def get_return_hash(response_hash)
      success = response_hash[:status] == '0000'

      {
          success: success,
          message: response_hash[:status_message],
          id: response_hash[:request_id],
          auth_id: response_hash[:authn_id],
          detail: response_hash[:detail_message]
      }
    end


    # Authenticate a user with a credential. A credential includes a physical token, the desktop VIP credential app or
    # the mobile VIP credential app. Users must link their credential id to their user id for this authentication to work.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP authentication WSDL.
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec db.
    # @param [String] credential_code The code from the users credential that was entered into the website.
    # @return [Hash] A hash with information on if the authentication was successful.
    def authenticate_user_credential(client, user_id, credential_code)
      result = client.call(:authenticate_user,
                           message: {
                               'vip:requestId': Utilities.get_request_id('authenticate_user_credential'),
                               'vip:userId': user_id,
                               'vip:otpAuthData':
                                   {
                                       'vip:otp': credential_code
                                   }
                           })

      get_return_hash(result.body[:authenticate_user_response])

    end


    # Create the body for the authenticate credentials request.
    #
    # @param [Integer] otp The One Time Password to check if valid.
    # @param [Array] credentials An array of hashes, with between 1 and 5 credentials. Each hash should contain 2 values :id - the id of the credential and :type - the type of the credential.
    # @return [Hash] A hash representing the request body for the authenticate credentials request.
    def get_auth_body(otp, credentials)

      credential_array = []

      credentials.each do |credential|
        credential_array.push({'vip:credentialId': credential[:id], 'vip:credentialType': credential[:type]})
      end

      {
          'vip:requestId': Utilities.get_request_id('authenticate_credentials'),
          'vip:credentials': credential_array,
          'vip:otpAuthData': {
              'vip:otp': otp
          }
      }

    end


    # Check if a otp is valid for a given credential.
    #
    # @param [Integer] otp The One Time Password to check if valid.
    # @param [Array] credentials An array of hashes, with between 1 and 5 credentials. Each hash should contain 2 values :id - the id of the credential and :type - the type of the credential.
    # @see CredentialTypes
    # @return [Hash] A hash with all information about if the otp was successful
    def authenticate_credentials(client, otp, credentials)
      result = client.call(:authenticate_credentials, message: get_auth_body(otp, credentials))
      get_return_hash(result.body[:authenticate_credentials_response])
    end


    # Register a SMS credential to the VIP Account. This must be done before you can add a SMS credential to a user.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [Object] phone_number The phone number to register.
    def register_sms(client, phone_number)
      result = client.call(:register, message: {
          'vip:requestId': Utilities.get_request_id('register_credential'),
          'vip:smsDeliveryInfo': {
              'vip:phoneNumber': phone_number
          }
      } )

      get_return_hash(result.body[:register_response])
    end


    # Use getCredentialInfo to get the credential that was last bound to the user, When the credential was last authenticated and
    # the friendly name for the credential.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP query WSDL.
    # @param [String] credential_id The unique ID for the credential.
    # @param [String] credential_type The type of the credential.
    # @param [Boolean] include_push If this flag is present and set to be true, the response contains all the push attributes in the field pushAttributes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes. Also contains :credential which is a hash with info about the credential.
    def get_credential_info(client, credential_id, credential_type, include_push)
      message = {
          'vip:requestId': Utilities.get_request_id('get_credential_info'),
          'vip:credentialId': credential_id,
          'vip:credentialType': credential_type
      }

      unless include_push == nil
        message[:'vip:includePushAttributes'] = include_push
      end

      response = client.call(:get_credential_info, message: message)
      response_hash = response.body[:get_credential_info_response]

      ret = get_return_hash(response_hash)

      # get the credential info
      credential = {
          id: response_hash[:credential_id],
          type: response_hash[:credential_type],
          enabled: response_hash[:credential_status] == 'ENABLED'
      }

      # add the bindings if they exist
      unless response_hash[:num_bindings] == '0'
        credential[:user_binding] = response_hash[:user_binding_detail]
      end

      ret[:credential] = credential

      ret
    end


    # Use getServerTime to obtain the current server time.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP query WSDL.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes. Also contains :time which is current server time.
    def get_server_time(client)
      response = client.call(:get_server_time, message: {'vip:requestId': Utilities.get_request_id('get_server_time')})
      response_body = response.body[:get_server_time_response]
      ret = get_return_hash(response_body)

      unless response_body[:timestamp] == nil
        ret[:time] = response_body[:timestamp]
      end

      ret
    end

  end

end