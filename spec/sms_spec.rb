require 'spec_helper'
require 'savon/mock/spec_helper'

describe Soteria::SMS do

  include Savon::SpecHelper

  before :all do
    savon.mock!

    @sms = Soteria::SMS.new

    auth_client_wsdl = File.read('spec/fixtures/wsdl/vipuserservices-auth-1.7.wsdl')
    @auth_client = Savon.client(wsdl: auth_client_wsdl)

    mgmt_client_wsdl = File.read('spec/fixtures/wsdl/vipuserservices-mgmt-1.7.wsdl')
    @mgmt_client = Savon.client(wsdl: mgmt_client_wsdl)
  end

  after :all do
    savon.unmock!
  end

  it 'creates the request body to send an sms' do
    result_hash = @sms.create_send_sms_body('test1', 123456789)
    result_hash[:'vip:requestId'] = nil

    expected_hash = {
        'vip:requestId': nil,
        'vip:userId': 'test1',
        'vip:smsDeliveryInfo':
            {
                'vip:phoneNumber': 123456789
            }
    }

    expect(result_hash). to match expected_hash
  end

  it 'creates the request body to check an otp' do
    result_hash = @sms.create_check_otp_body('test1', 'otp123')
    result_hash[:'vip:requestId'] = nil

    expected_hash = {
        'vip:requestId': nil,
        'vip:userId': 'test1',
        'vip:otpAuthData':
            {
                'vip:otp': 'otp123'
            }
    }

    expect(result_hash). to match expected_hash
  end

  it 'sends a sms otp' do
    body = File.read('spec/fixtures/sms/send_sms_success_response.xml')
    savon.expects(:send_otp).with(message: :any).returns(body)
    result_hash = @sms.send_sms(@mgmt_client, '', '')

    expected_hash = {
        success: true,
        id: 'test123',
        message: 'Success'
    }

    expect(result_hash). to match expected_hash
  end

  it 'checks if a otp is valid' do
    body = File.read('spec/fixtures/sms/check_otp_success_response.xml')
    savon.expects(:check_otp).with(message: :any).returns(body)
    result_hash = @sms.check_otp(@auth_client, '', '')

    expected_hash = {
        success: true,
        id: 'test123',
        message: 'Success'
    }

    expect(result_hash). to match expected_hash
  end
end

