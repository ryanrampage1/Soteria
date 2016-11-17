require_relative 'utilities'
module Soteria

  class Push


    # Creates the body for a send push request.
    #
    # @param [String] user_id The id of the user to send the push to
    # @param [Hash] options
    # @return [Hash] A hash representing the body of the soap request to send a push notification.
    def get_push_request_body(user_id, options)

      # add in required values
      message = {
          'vip:requestId': Utilities.get_request_id('send_push_request'),
          'vip:userId': user_id,
      }

      # no extra options so set the push auth data to nothing
      # and return the body
      if options == nil
        message[:'vip:pushAuthData'] = ''
        return message
      end

      #check if the user passed a pin, if so add it
      if options.key?(:pin)
        message[:'vip:pin'] = options[:pin]
      end

      # check for all push auth data options and add them
      if options.key?(:title) || options.key?(:message) || options.key?(:profile) || options.key?(:time_out)
        inner = []
        if options.key?(:title)
          inner.push({'vip:Key': 'display.message.title', 'vip:Value': options[:title]})
        end
        if options.key?(:message)
          inner.push({'vip:Key': 'display.message.text', 'vip:Value': options[:message]})
        end
        if options.key?(:profile)
          inner.push({'vip:Key': 'display.message.profile', 'vip:Value': options[:profile]})
        end

        # Add the options to the push auth data
        if options.key?(:time_out)
          message[:'vip:pushAuthData'] = {
              'vip:displayParameters': inner,
              'vip:requestParameters':
                  {
                      'vip:Key': 'request.timeout',
                      'vip:Value': options[:time_out]
                  }
          }

        else
          message[:'vip:pushAuthData'] = {'vip:displayParameters': inner}
        end

      else
        # dont add any push auth data
        message[:'vip:pushAuthData'] = ''
      end

      # if options.key?(:level)
      #   message['authContext'] = {'params': {'Key': 'authLevel.level', 'Value': options[:level]}}
      # end

      message
    end


    # Send a push notification to the specified user for authentication.
    #
    # @param [Savon::Client] client A Savon client object to make the call with.
    # @see Savon::Client
    # @param [String] user_id The id of the user to send the push to
    # @param [Hash] options
    def send_push(client, user_id, options)

      # get the body of the request
      request_body = get_push_request_body(user_id, options)
      push_res = client.call(:authenticate_user_with_push, message: request_body)
      result_hash = push_res.body[:authenticate_user_with_push_response]

      # 6040 is the status code for a push being sent, any other code the push was not sent
      success = result_hash[:status] == '6040'

      {
          success: success,
          id: result_hash[:request_id],
          transaction_id: result_hash[:transaction_id],
          message: result_hash[:status_message]
      }

    end


    # Polls for the status of the push notification. This is necessary because VIP does not have push support.
    # This will poll until the response is no longer push in progress, then it will return a hash with the results.
    #
    # @param [Savon::Client] client A Savon client object to make the call with. This needs to be created with the VIP query WSDL.
    # @param [String] transaction_id The id of the push transaction. id is in the hash returned from the send_push call
    # @param [Int] interval An integer value in seconds that is the interval between polling VIP Services for a push response.
    # @param [Int] time_out An integer value in seconds that is the timeout for polling. This should match the timeout that was set for the push message.
    # @return [Hash] A hash with information on if the authentication was successful.
    def poll_for_response(client, transaction_id, interval, time_out)

      1.upto(time_out/interval) do

        response = client.call(:poll_push_status,
                               message: {
                                   'vip:requestId': Utilities.get_request_id("poll_push_status"),
                                   'vip:transactionId': transaction_id
                               })

        # The status of the push is called transaciton status
        transaction_status = response.body[:poll_push_status_response][:transaction_status]
        call_status = response.body[:poll_push_status_response]

        # 7001 is in progress so we are waiting for that to change
        if transaction_status[:status] != '7001'

          success = transaction_status[:status] == '7000'
          return {
              success: success,
              message: transaction_status[:status_message],
              id: call_status[:request_id]
          }

        end

        sleep interval

      end

    end

  end

end