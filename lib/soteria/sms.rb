module Soteria

  class SMS


    # Creates the body for a send SMS otp request.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec database.
    # @param [Int] phone_number The phone number that the sms code should be sent to.
    # @return [Hash] A hash with all information about if the otp was successful.
    def create_send_sms_body(user_id, phone_number)
      {
          'vip:requestId': Utilities.get_request_id('send_sms_otp'),
          'vip:userId': user_id,
          'vip:smsDeliveryInfo':
              {
                  'vip:phoneNumber': phone_number
              }
      }
    end


    # Send a sms One Time Password to a user.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec database.
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP management WSDL.
    # @param [Int] phone_number The phone number that the sms code should be sent to.
    # @return [Hash] A hash with all the appropriate information about the status of the SMS.
    def send_sms(client, user_id, phone_number)
      sms_res = client.call(:send_otp, message: create_send_sms_body(user_id, phone_number))
      result_hash = sms_res.body[:send_otp_response]
      success = result_hash[:status] == '0000'

      {
          success: success,
          id: result_hash[:request_id],
          message: result_hash[:status_message]
      }
    end


    # Creates the body for a check otp request.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec db.
    # @param [Object] otp The otp that was sent to the user via sms or voice
    # @return [Hash] A hash representing the body of the soap request to check if an otp is valid.
    def create_check_otp_body(user_id, otp)
      {
          'vip:requestId': Utilities.get_request_id('check_sms_otp'),
          'vip:userId': user_id,
          'vip:otpAuthData':
              {
                  'vip:otp': otp
              }
      }
    end


    # Check if the otp that a user entered is valid or not.
    #
    # @param [String] user_id Id of the user to authenticate. This is the user id that is stored in the Symantec db.
    # @param [Object] otp The otp that was sent to the user via sms or voice
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP authentication WSDL.
    # @return [Hash] A hash with all information about if the otp was successful
    def check_otp(client, user_id, otp)
      check_otp_response = client.call(:check_otp, message: create_check_otp_body(user_id, otp))
      result_hash = check_otp_response.body[:check_otp_response]

      success = result_hash[:status] == '0000'

      {
          success: success,
          id: result_hash[:request_id],
          message: result_hash[:status_message]
      }
    end


  end

end