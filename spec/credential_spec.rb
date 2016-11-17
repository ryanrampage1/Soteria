require 'spec_helper'
require 'savon/mock/spec_helper'
require 'date'

describe Soteria::Credential do

  include Savon::SpecHelper

  before :all do
    savon.mock!

    @credential = Soteria::Credential.new
    @auth_client = Savon.client(wsdl: File.read('spec/fixtures/wsdl/vipuserservices-auth-1.7.wsdl'))
    @mgmt_client = Savon.client(wsdl: File.read('spec/fixtures/wsdl/vipuserservices-mgmt-1.7.wsdl'))
    @query_client = Savon.client(wsdl: File.read('spec/fixtures/wsdl/vipuserservices-query-1.7.wsdl'))
  end

  after :all do
    savon.unmock!
  end

  it 'returns correct values from a call that successfully authenticates a user' do
    body = File.read('spec/fixtures/credential/credential_success.xml')
    savon.expects(:authenticate_user).with(message: :any).returns(body)
    res = @credential.authenticate_user_credential(@auth_client, '', '')

    expect(res[:success]).to eq true
    expect(res[:message]).to eq 'Success'
    expect(res[:id]).to eq 'testsuccess1234'
    expect(res[:auth_id]).to eq 'testsuccess123456'
    expect(res[:detail]).to eq nil

  end

  it 'returns correct values from a call that fails to authenticate a user' do

    body = File.read('spec/fixtures/credential/credential_fail.xml')
    savon.expects(:authenticate_user).with(message: :any).returns(body)
    res = @credential.authenticate_user_credential(@auth_client, '', '')

    expect(res[:success]).to eq false
    expect(res[:message]).to eq 'Authentication failed.'
    expect(res[:detail]).to eq 'Failed with an invalid OTP'
    expect(res[:id]).to eq 'testfail1234'
    expect(res[:auth_id]).to eq nil

  end

  it 'gets the body for the authenticate credentials call' do
    otp = 123342

    result_hash = @credential.get_auth_body(otp, [{id: 1, type: 'a'}, {id: 2, type: 'b'}])
    result_hash[:'vip:requestId'] = nil

    expected_hash = {
        'vip:requestId': nil,
        'vip:credentials': [{'vip:credentialId': 1, 'vip:credentialType': 'a'}, {'vip:credentialId': 2, 'vip:credentialType': 'b'}],
        'vip:otpAuthData': {
            'vip:otp': otp
        }
    }

    expect(result_hash).to match expected_hash

  end

  it 'authenticates credentials' do
    body = File.read('spec/fixtures/credential/authenticate_credentials_response.xml')
    savon.expects(:authenticate_credentials).with(message: :any).returns(body)

   result_hash =  @credential.authenticate_credentials(@auth_client, '', [{id: 1, type: 'a'}, {id: 2, type: 'b'}])

    expected_hash = {
        success: true,
        message: 'Success.',
        id: 'AUTHCRED_87263487236',
        auth_id: nil,
        detail: nil
    }

    expect(result_hash).to match expected_hash

  end

  it 'registers a sms credential' do

    body = File.read('spec/fixtures/credential/register_sms_response.xml')
    savon.expects(:register).with(message: :any).returns(body)

    result_hash = @credential.register_sms(@mgmt_client, '')

    expected_hash = {
        success: false,
        message: 'Credential is already registered for this account.',
        id: 'test23456',
        auth_id: nil,
        detail: 'Token has already been activated.'
    }

    expect(result_hash).to match expected_hash
  end

  it 'gets the server time' do
    body = File.read('spec/fixtures/credential/get_server_time_response.xml')
    savon.expects(:get_server_time).with(message: :any).returns(body)

    result_hash = @credential.get_server_time(@query_client)

    expected_hash = {
        success: true,
        message: 'Success',
        id: 'abcd1234',
        auth_id: nil,
        detail: nil,
        time: Date.parse('2010-07-26T00:54:47.390-07:00')
    }

    expect(result_hash).to match expected_hash
  end

end