require 'savon'
require 'soteria/utilities'
require 'soteria/sms'
require 'soteria/credential'
require 'soteria/user'
require 'soteria/push'
require 'soteria/auth'

module Soteria

  class Client

    # To use Soteria, SSL certificates for Symantec VIP Services are required. To obtain a certificate go to
    # https://manager.vip.symantec.com/ and log in. From the dashboard go to Account -> Manage VIP Certificates -> Request
    # a Certificate. From there follow the directions to create a new certificate. On the download screen select the PKCS#12
    # format and enter the password you would like to use to secure the certificate. Once the certificate is downoaded run
    # these two commands to split the PKCS#12 certificate into a public and private key.
    #
    # @param [String] cert_file The relative path to the SSL cert on the server.
    # @param [String] cert_key_file The relative path to the SSL cert key on the server.
    # @param [String] password The password for the cert key file.
    # @param [Boolean] should_log if the client should log everything. This is good for development.
    def initialize(cert_file, cert_key_file, password, should_log)
      # @cert_file = cert_file
      # @cert_key_file = cert_key_file
      # @cert_key_password = password

      #[:get_server_time, :get_user_info, :get_credential_info, :get_temporary_password_attributes, :poll_push_status]
      @query_client = Utilities.create_client('vipuserservices-query-1.7.wsdl', should_log, cert_file, cert_key_file, password)

      #[:authenticate_user, :authenticate_user_with_push, :authenticate_credentials, :evaluate_risk, :confirm_risk, :deny_risk, :check_otp]
      @auth_client = Utilities.create_client('vipuserservices-auth-1.7.wsdl', should_log, cert_file, cert_key_file, password)

      #[:create_user, :update_user, :delete_user, :clear_user_pin, :add_credential, :update_credential, :remove_credential, :set_temporary_password, :clear_temporary_password, :set_temporary_password_attributes, :send_otp, :register]
      @management_client = Utilities.create_client('vipuserservices-mgmt-1.7.wsdl', should_log, cert_file, cert_key_file, password)

      @auth = Auth.new(cert_file, cert_key_file, password, should_log)

      @push = Push.new
      @sms = SMS.new
      @credential = Credential.new
      @user = User.new
    end


    # Getter for the query client
    #
    # @return [Soteria.Client] The Query client
    def get_query_client
      @query_client
    end


    # Getter for the auth client
    #
    # @return [Soteria.Client] The Auth client
    def get_auth_client
      @auth_client
    end


    # Getter for the management client
    #
    # @return [Soteria.Client] The Management client
    def get_management_client
      @management_client
    end


    # Send a push notification to the specified user for authentication.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec database.
    # @param [Hash] options
    # @return [Hash]
    def send_push(user_id, options)
      @push.send_push(@auth_client, user_id, options)
    end


    # Polls for the status of the push notification. This is necessary because VIP does not have push support.
    # This will poll until the response is no longer push in progress, then it will return a hash with the results.
    #
    # @param [String] transaction_id The id of the push transaction. id is in the hash returned from the send_push call
    # @param [Int] interval An integer value in seconds that is the interval between polling VIP Services for a push response.
    # @param [Int] time_out An integer value in seconds that is the timeout for polling. This should match the timeout that was set for the push message.
    # @return [Hash] A hash with information on if the authentication was successful.
    def poll_for_response(transaction_id, interval, time_out)
      @push.poll_for_response(@query_client, transaction_id, interval, time_out)
    end


    # authenticate_with_push handles the process of sending the push to a user as well as polling for the response.
    # It calls send_push, then takes the transaction id from that call and starts polling for the result. It has the
    # same result as making the calls independently but requires only one call instead of two as well as handles any errors.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec database.
    # @param [Int] interval An integer value in seconds that is the interval between polling VIP Services for a push response.
    # @param [Int] time_out An integer value in seconds that is the timeout for polling. This should match the timeout that was set for the push message.
    # @param [Hash] options
    # @return [Hash] A hash with information on if the authentication was successful.
    def authenticate_with_push(user_id, interval, time_out, options)
      push_response = @push.send_push(@auth_client, user_id, options)

      unless push_response[:success]
        return push_response
      end

      transaction_id = push_response[:transaction_id]

      @push.poll_for_response(@query_client, transaction_id, interval, time_out)
    end


    # Authenticate a user with a credential. A credential includes a physical token, the desktop VIP credential app or
    # the mobile VIP credential app. Users must link their credential id to their user id for this authentication to work.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec database.
    # @param [String] credential_code The code from the users credential that was entered into the website.
    # @return [Hash] A hash with information on if the authentication was successful.
    def authenticate_user_credential(user_id, credential_code)
      @credential.authenticate_user_credential(@auth_client, user_id, credential_code)
    end


    # Check if a otp is valid for a given credential.
    #
    # @param [Integer] otp The One Time Password to check if valid.
    # @param [Array] credentials An array of hashes, with between 1 and 5 credentials. Each hash should contain 2 values :id - the id of the credential and :type - the type of the credential.
    # @see CredentialTypes
    # @return [Hash] A hash with all information about if the otp was successful
    def authenticate_credentials(otp, credentials)
      @credential.authenticate_credentials(@auth_client, otp, credentials)
    end


    # Send a sms One Time Password to a user.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec database.
    # @param [Int] phone_number The phone number that the sms code should be sent to.
    # @return [Hash] A hash with all the appropriate information about the status of the SMS.
    def send_sms(user_id, phone_number)
      @sms.send_sms(@management_client, user_id, phone_number)
    end


    # Check if the otp that a user entered is valid or not.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec database.
    # @param [Object] otp The otp that was sent to the user via sms or voice
    # @return [Hash] A hash with all information about if the otp was successful
    def check_otp(user_id, otp)
      @sms.check_otp(@auth_client, user_id, otp)
    end


    # Add a new user to the list of users in Symantec VIP database.
    #
    # @param [String] user_id Id of the user to create.
    # @param [String] pin an optional value that is a pin for the user. The PIN may be 4 to 128 international characters in length, depending on restrictions of the PIN policy.
    # @return [Hash] A hash that contains: :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def create_user(user_id, pin)
      @user.create(@management_client, user_id, pin)
    end


    # Delete a user from the database of Symantec VIP users.
    #
    # @param [String] user_id Id of the user to delete.
    # @return [Hash] A hash that contains: :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def delete_user(user_id)
      @user.delete(@management_client, user_id)
    end


    # Use updateUser to update information about a user in VIP User Services.
    #
    # @param [String] user_id The unique ID for the user.
    # @param [Object] options
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def update_user(user_id, options)
      @user.update_user(@management_client, user_id, options)
    end


    # Use clearUserPin to remove an assigned PIN from a user.
    #
    # @param [String] user_id The unique ID for the user.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def clear_user_pin(user_id)
      @user.clear_user_pin(@management_client, user_id)
    end


    # Use setTemporaryPasswordAttributes to change the expiration date for a temporary security code you previously set.
    #
    # @param [String] user_id The unique ID for the user.
    # @param [Object] options
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def set_temp_pass_attr(user_id, options)
      @user.set_temp_pass_attr(@management_client, user_id, options)
    end


    # Use getTemporaryPasswordAttributes to poll VIP User Services every three to five seconds to check the status of a
    # push notification. The push notification is validated against the notification’s unique transaction ID.
    #
    # @param [String] user_id The unique ID for the user.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def get_temp_pass_attr(user_id)
      @user.get_temp_pass_attr(@query_client, user_id)
    end


    # Use setTemporaryPassword to set a temporary security code for a user. You can optionally set an
    # expiration date for the security code, or set it for one-time use only. The request requires the user ID and
    # optionally, the temporary security code string. If you do not provide a security code, VIP User Services generates
    # one for you.
    #
    # @param [String] user_id The unique ID for the user.
    # @param [Int] phone The phone or mobile device number to which the VIP User Service should deliver the security code.
    # @param [Hash] options
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def set_temp_password(user_id, phone, options)
      @user.set_temp_password(@management_client, user_id, phone, options)
    end


    # Use clearTemporaryPassword to add users to VIP User Services.to remove a temporary security code from a user. If the
    # user attempts to use a temporary security that has been cleared, VIP User Services returns an error stating the
    # security code is not set. If the user validates a security code using a valid credential, any temporary security
    # code that is set for that user is automatically cleared.
    #
    # @param [String] user_id The unique ID for the user.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def clear_temp_pass(user_id)
      @user.clear_temp_pass(@management_client, user_id)
    end


    # Use getCredentialInfo to get the credential that was last bound to the user, When the credential was last authenticated and
    # the friendly name for the credential.
    #
    # @param [String] credential_id The unique ID for the credential.
    # @param [String] credential_type The type of the credential.
    # @param [Boolean] include_push If this flag is present and set to be true, the response contains all the push attributes in the field pushAttributes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes. Also contains :credential which is a hash with info about the credential.
    def get_credential_info(credential_id, credential_type, include_push)
      @credential.get_credential_info(@query_client, credential_id, credential_type, include_push)
    end


    # Use getServerTime to obtain the current server time.
    #
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes. Also contains :time which is current server time.
    def get_server_time()
      @credential.get_server_time(@query_client)
    end


    # Add a credential to an existing user in the Symantec VIP database.
    #
    # @param [String] user_id Id of the user to add a credential to.
    # @param [String] credential_id
    # @param [String] credential_type must be one of the keys to the credential types from the Utilities class.
    # @see Utilities::CREDENTIAL_TYPES
    # @param [Hash] options A hash that can contain the following. :name adds a friendly name to the credential added to vip, :otp sends a otp from the credential with the request to verify that the user actually has possession of the credential
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def add_credential(user_id, credential_id, credential_type, options)
      @user.add_credential(@management_client, user_id, credential_id, credential_type, options)
    end


    # Get all the credentials that have been last bound to a user or the last authentication, as well as the friendly
    # name for the user's credential.
    #
    # Returns an array with a hash for every credential that can be used as a second factor authentication option a user has. Each hash contains:
    # * :type - The type of the credential.
    # * :enabled - If the credential is enabled.
    # * :friendly_name - The name the user gave the credential.
    # * :push - A boolean if push is enabled for the credential.
    # * :credential_id - The id of the credential. This is useful for SMS auth.
    #
    # @param [String] user_id Id of the user to get information about.
    # @param [Boolean] include_push If the users push details should be returned.
    def get_user_info(user_id, include_push)
      @user.get_user_info(@query_client, user_id, include_push)
    end


    # Call to register a SMS credential to the VIP account. Before a user can add a SMS credential to their account
    # it must first exist in the organizations list of credentials.
    #
    # @param [Integer] phone_number The phone number credential to register.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def register_sms(phone_number)
      @credential.register_sms(@management_client, phone_number)
    end


    # Remove a credential from a given user. If the Device deletion policy for Remembered Devices is set to Admin Only,
    # credentials can only be removed through VIP Manager. The removeCredential API will return the error 6010: This
    # account is not authorized to perform the requested operation
    #
    # @param [String] user_id Id of the user to remove a credential from.
    # @param [String] credential_id Unique identifier of the credential.
    # @param [String] credential_type must be one of the keys to the credential types from the Utilities class.
    # @see Utilities::CREDENTIAL_TYPES
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def remove_credential(user_id, credential_id, credential_type)
      puts @user.remove_credential(@management_client, user_id, credential_id, credential_type)
    end


    # Updates the friendly name of a users credential.
    #
    # @param [String] user_id Id of the user to remove a credential from.
    # @param [String] credential_id Unique identifier of the credential.
    # @param [String] credential_type must be one of the keys to the credential types from the Utilities class.
    # @see Utilities::CREDENTIAL_TYPES
    # @param [Object] name A user-defined name to identify the credential.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def update_credential(user_id, credential_id, credential_type, name)
      puts @user.update_credential(@management_client, user_id, credential_id, credential_type, name)
    end


    # Send a temporary password to the token.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @param [Int] pass
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def set_temp_pass(token_id, pass)
      @auth.set_temp_pass(token_id, pass)
    end


    # Use the EnableToken for SMS OTP API to enable a previously disabled SMS OTP credential.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def enable_sms_credentail(token_id)
      @auth.enable_sms_credentail(token_id)
    end


    # Use the DisableToken for SMS OTP API to disable an SMS OTP credential.
    #
    # @param [String] reason The reason for disabling the token.
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def disable_sms_credentail(reason, token_id)
      @auth.disable_sms_credentail(reason, token_id)
    end


    # Call when a newly registered SMS OTP credential requires activation
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def activate_token(token_id)
      @auth.activate_token(token_id)
    end


    # Use the DeactivateToken for SMS OTP API to deactivate an SMS OTP credential. If the deactivation is successful, the credential is deactivated.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def deactivate_token(token_id)
      @auth.deactivate_token(token_id)
    end


    # Register a new SMS OTP credential.
    #
    # @param [Int] token_id Specifies the phone number that identifies the credential to the VIP Web Services. Do not use spaces or dashes.
    # @return [Hash] A hash that contains; :success a boolean if the call succeeded, :message a string with any error message, :id the id of the call for debugging purposes
    def register(token_id)
      @auth.register(token_id)
    end

  end

end
