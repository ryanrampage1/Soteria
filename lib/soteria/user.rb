module Soteria

  class User


    # Add a new user to the list of users in Symantec VIP database.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id Id of the user to create.
    # @param [String] pin an optional value that is a pin for the user. The PIN may be 4 to 128 international characters in length, depending on restrictions of the PIN policy.
    # @return [Hash] A hash that contains: :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def create(client, user_id, pin)
      message = {
          'vip:requestId': Utilities.get_request_id('create_user'),
          'vip:userId': user_id
      }

      unless pin.nil?
        message['vip:pin'] = pin
      end

      response = client.call(:create_user, message: message)

      get_return_hash(response.body[:create_user_response])
    end


    # Delete a user from the database of Symantec VIP users.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id Id of the user to delete.
    # @return [Hash] A hash that contains: :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def delete(client, user_id)
      response = client.call(:delete_user,
                             message: {
                                 'vip:requestId': Utilities.get_request_id('delete_user'),
                                 'vip:userId': user_id
                             })

      get_return_hash(response.body[:delete_user_response])
    end


    # Creates the body for a add credential request.
    #
    # @param [String] user_id Id of the user to add a credential to.
    # @param [String] credential_id
    # @param [String] credential_type must be one of the keys to the credential types from the Utilities class.
    # @see Utilities::CREDENTIAL_TYPES
    # @param [Hash] options A hash that can contain the following. :name adds a friendly name to the credential added to vip, :otp sends a otp from the credential with the request to verify that the user actually has possession of the credential
    # @return [Hash] A hash representing the body of the soap request to add a credential.
    def get_add_credential_message(user_id, credential_id, credential_type, options)
      message = {
          'vip:requestId': Utilities.get_request_id('add_credential'),
          'vip:userId': user_id
      }

      credential_detail = {
          'vip:credentialId': credential_id,
          'vip:credentialType': credential_type
      }

      unless options == nil
        if options.key?(:name)
          credential_detail[:'vip:friendlyName'] = options[:name]
        end

        if options.key?(:otp)
          message[:'vip:otpAuthData'] = {
              'vip:otp': options[:otp]
          }
        end
      end

      message[:'vip:credentialDetail'] = credential_detail

      message
    end


    # Add a credential to an existing user in the Symantec VIP database.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id Id of the user to add a credential to.
    # @param [String] credential_id Unique identifier of the credential.
    # @param [String] credential_type must be one of the keys to the credential types from the Utilities class.
    # @see Utilities::CREDENTIAL_TYPES
    # @param [Hash] options A hash that can contain the following. :name adds a friendly name to the credential added to vip, :otp sends a otp from the credential with the request to verify that the user actually has possession of the credential
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def add_credential(client, user_id, credential_id, credential_type, options)
      response = client.call(:add_credential, message: get_add_credential_message(user_id, credential_id, credential_type, options))
      get_return_hash(response.body[:add_credential_response])
    end


    # Remove a credential from a given user. If the Device deletion policy for Remembered Devices is set to Admin Only,
    # credentials can only be removed through VIP Manager. The removeCredential API will return the error 6010: This
    # account is not authorized to perform the requested operation
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id Id of the user to remove a credential from.
    # @param [String] credential_id Unique identifier of the credential.
    # @param [String] credential_type must be one of the keys to the credential types from the Utilities class.
    # @see Utilities::CREDENTIAL_TYPES
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def remove_credential(client, user_id, credential_id, credential_type)
      response = client.call(:remove_credential, message: {
          'vip:requestId': Utilities.get_request_id('remove_credential'),
          'vip:userId': user_id,
          'vip:credentialId': credential_id,
          'vip:credentialType': credential_type
      })

      get_return_hash(response.body[:remove_credential_response])
    end


    # Updates the friendly name of a users credential.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id Id of the user to remove a credential from.
    # @param [String] credential_id Unique identifier of the credential.
    # @param [String] credential_type must be one of the keys to the credential types from the Utilities class.
    # @see Utilities::CREDENTIAL_TYPES
    # @param [Object] name A user-defined name to identify the credential.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def update_credential(client, user_id, credential_id, credential_type, name)
      response = client.call(:update_credential, message: {
          'vip:requestId': Utilities.get_request_id('update_credential'),
          'vip:userId': user_id,
          'vip:credentialId': credential_id,
          'vip:credentialType': credential_type,
          'vip:friendlyName': name
      })

      get_return_hash(response.body[:update_credential_response])
    end


    # Get all the credentials that have been last bound to a user or the last authentication, as well as the friendly
    # name for the user's credential.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP query WSDL.
    # @param [String] user_id Id of the user to get information about.
    # @param [Boolean] include_push If the users push details should be returned.
    # @return [Hash] A hash that contains; :credentials a array of credentials available, :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def get_user_info(client, user_id, include_push)
      response = client.call(:get_user_info, message: {
          'vip:requestId': Utilities.get_request_id('get_user_info'),
          'vip:userId': user_id,
          'vip:includePushAttributes': include_push
      })

      response_hash = response.body[:get_user_info_response]

      credentials = []

      if response_hash[:num_bindings] == nil || response_hash[:num_bindings] ==  '0'
        credentials = nil

      else
        response_hash[:credential_binding_detail].each do |credential|

          bind_detail = credential[:binding_detail]

          if credential[:credential_type] == 'STANDARD_OTP'
            push_attrs = credential[:push_attributes]
            credentials.push({
                                 type: 'STANDARD_OTP',
                                 enabled: response_hash[:credential_status] == 'ENABLED' && bind_detail[:bind_status] == 'ENABLED',
                                 friendly_name: bind_detail[:friendly_name],
                                 push: push_check(push_attrs),
                                 credential_id: credential[:credential_id]
                             })

          elsif credential[:credential_type] == 'SMS_OTP'
            credentials.push({
                                 type: 'SMS_OTP',
                                 enabled: response_hash[:credential_status] == 'ENABLED' && bind_detail[:bind_status] == 'ENABLED',
                                 friendly_name: bind_detail[:friendly_name],
                                 push: false,
                                 credential_id: credential[:credential_id]
                             })
          elsif credential[:credential_type] == 'VOICE_OTP'
            credentials.push({
                                 type: 'VOICE_OTP',
                                 enabled: response_hash[:credential_status] == 'ENABLED' && bind_detail[:bind_status] == 'ENABLED',
                                 friendly_name: bind_detail[:friendly_name],
                                 push: false,
                                 credential_id: credential[:credential_id]
                             })
          end

        end

      end

      ret = get_return_hash(response_hash)
      ret[:credentials] = credentials
      ret
    end


    # Use updateUser to update information about a user in VIP User Services.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id The unique ID for the user.
    # @param [Object] options
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def update_user(client, user_id, options)
      message = {
          'vip:requestId': Utilities.get_request_id('update_user'),
          'vip:userId': user_id
      }

      unless options == nil
        if options.key?(:newId)
          message[:'vip:newUserId'] = options[:newId]
        end

        if options.key?(:status)
          message[:'vip:newUserStatus'] = options[:status]
        end

        if options.key?(:oldPin)
          message[:'vip:oldPin'] = options[:oldPin]
        end

        if options.key?(:newPin)
          message[:'vip:newPin'] = options[:newPin]
        end

        if options.key?(:pinReset)
          message[:'vip:forcePinReset'] = options[:pinReset]
        end

      end

      response = client.call(:update_user, message: message)
      get_return_hash(response.body[:update_user_response])
    end


    # Use clearUserPin to remove an assigned PIN from a user.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id The unique ID for the user.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def clear_user_pin(client, user_id)
      response = client.call(:clear_user_pin, message: {
          'vip:requestId': Utilities.get_request_id('clear_pin'),
          'vip:userId': user_id
      })

      get_return_hash(response.body[:clear_user_pin_response])
    end


    # Use setTemporaryPasswordAttributes to change the expiration date for a temporary security code you previously set.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id The unique ID for the user.
    # @param [Object] options
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def set_temp_pass_attr(client, user_id, options)
      message = {
          'vip:requestId': Utilities.get_request_id('set_temp_pass_attr'),
          'vip:userId': user_id
      }

      unless options == nil
        inner = {}
        if options.key?(:oneTime)
          inner[:'vip:oneTimeUseOnly'] = options[:oneTime]
        end

        if options.key?(:expireTime)
          inner[:'vip:expirationTime'] = options[:expireTime]
        end

        message[:'vip:temporaryPasswordAttributes'] = inner
      end

      response = client.call(:set_temporary_password_attributes, message: message)
      get_return_hash(response.body[:set_temporary_password_attributes_response])
    end


    # Use getTemporaryPasswordAttributes to poll VIP User Services every three to five seconds to check the status of a
    # push notification. The push notification is validated against the notification’s unique transaction ID.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP query WSDL.
    # @param [String] user_id The unique ID for the user.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def get_temp_pass_attr(client, user_id)
      response = client.call(:get_temporary_password_attributes, message: {
          'vip:requestId': Utilities.get_request_id('get_temp_pass_attr'),
          'vip:userId': user_id
      })
      response_hash = response.body[:get_temporary_password_attributes_response]

      ret = get_return_hash(response_hash)

      unless response_hash[:temp_pwd_attributes] == nil
        ret[:oneTime] = response_hash[:temp_pwd_attributes][:one_time_use_only]
        ret[:expiration] = response_hash[:temp_pwd_attributes][:expiration_time]
      end

      ret
    end


    # Use setTemporaryPassword to set a temporary security code for a user. You can optionally set an
    # expiration date for the security code, or set it for one-time use only. The request requires the user ID and
    # optionally, the temporary security code string. If you do not provide a security code, VIP User Services generates
    # one for you.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id The unique ID for the user.
    # @param [Int] phone The phone or mobile device number to which the VIP User Service should deliver the security code.
    # @param [Hash] options
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def set_temp_password(client, user_id, phone, options)
      message = {
          'vip:requestId': Utilities.get_request_id('set_temp_pass'),
          'vip:userId': user_id
      }

      phone_options = {'vip:phoneNumber': phone}

      unless options == nil
        if options.key?(:otp)
          message[:'vip:temporaryPassword'] = options[:otp]
        end

        if options.key?(:expireTime)
          message[:'vip:expirationTime'] = options[:expireTime]
        end

        if options.key?(:oneTime)
          message[:'vip:temporaryPasswordAttributes'] = { 'vip:oneTimeUseOnly': options[:oneTime] }
        end

        if options.key?(:from)
          phone_options[:'vip:expirationTime'] = options[:from]
        end
      end

      message[:'vip:smsDeliveryInfo'] = phone_options

      response = client.call(:set_temporary_password, message: message)

      ret = get_return_hash(response.body[:set_temporary_password_response])
      ret[:password] = response.body[:set_temporary_password_response][:temporary_password]

      ret
    end


    # Use clearTemporaryPassword to add users to VIP User Services.to remove a temporary security code from a user. If the
    # user attempts to use a temporary security that has been cleared, VIP User Services returns an error stating the
    # security code is not set. If the user validates a security code using a valid credential, any temporary security
    # code that is set for that user is automatically cleared.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [String] user_id The unique ID for the user.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def clear_temp_pass(client, user_id)
      message = {
          'vip:requestId': Utilities.get_request_id('clear_temp_pass'),
          'vip:userId': user_id
      }

      response = client.call(:clear_temporary_password, message: message)
      get_return_hash(response.body[:clear_temporary_password_response])
    end


    # Helper function to loop through an array of hashes with key value pairs and return if push is enabled.
    #
    # @param [Array] attrs A array of hash attributes
    # @return [Boolean] If push is enabled for the give attributes
    def push_check(attrs)
      attrs.each do |a|
        if a[:key] == 'PUSH_ENABLED'
          return a[:value]
        end
      end
      false
    end


    # Helper function to create the hash to return. All user calls have the same return values.
    #
    # @param [Hash] response_hash
    # @return [Hash] A hash with the appropriate values. Included are: :success - a boolean if the operation was successful,
    def get_return_hash(response_hash)
      success = response_hash[:status] == '0000'

      {
          success: success,
          message: response_hash[:status_message],
          id: response_hash[:request_id]
      }
    end

  end

end